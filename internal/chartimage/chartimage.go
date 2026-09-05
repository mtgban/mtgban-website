// Package chartimage draws a price history as a PNG.
//
// The site's own chart is a canvas the reader's browser fills in from JSON,
// which is the right answer everywhere a browser is running and no answer at
// all where one is not: a link unfurl is a fetch by a robot that renders no
// scripts and accepts no SVG, so a graph reaches it as pixels or not at all.
package chartimage

import (
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"io"
	"math"
	"strings"

	"golang.org/x/image/font"
	"golang.org/x/image/font/inconsolata"
	"golang.org/x/image/math/fixed"
	"golang.org/x/image/vector"
)

// Series is one line: a name for the legend, the colour the site draws it in,
// and one value per label. A NaN is a gap in the record rather than a zero,
// and is drawn as a break in the line.
type Series struct {
	Name  string
	Color string
	Data  []float64
}

// Spec is everything a chart needs to be drawn.
type Spec struct {
	// Title sits above the plot, usually the card the prices belong to
	Title string

	// Subtitle sits under it, usually the window the prices cover
	Subtitle string

	// Labels are the dates the values line up with, oldest first
	Labels []string

	Series []Series

	// Width and Height in pixels; zero takes the defaults
	Width, Height int
}

// The defaults are a shape link unfurls show without cropping, and large
// enough that a year of daily prices still has a pixel each.
const (
	DefaultWidth  = 800
	DefaultHeight = 418
)

// The page these stand in for is dark, and an unfurl sits in a dark client
// more often than not.
var (
	background = color.RGBA{0x14, 0x17, 0x1c, 0xff}
	panel      = color.RGBA{0x1b, 0x1f, 0x26, 0xff}
	gridline   = color.RGBA{0x2c, 0x32, 0x3c, 0xff}
	textBright = color.RGBA{0xe6, 0xe9, 0xef, 0xff}
	textDim    = color.RGBA{0x8b, 0x93, 0xa1, 0xff}
	fallback   = color.RGBA{0x5b, 0x8d, 0xef, 0xff}
)

const (
	padLeft   = 62
	padRight  = 16
	padTop    = 46
	padBottom = 46

	lineWidth = 1.8
)

// Render draws the spec and writes it out as a PNG.
func Render(w io.Writer, spec Spec) error {
	width, height := spec.Width, spec.Height
	if width <= 0 {
		width = DefaultWidth
	}
	if height <= 0 {
		height = DefaultHeight
	}

	img := image.NewRGBA(image.Rect(0, 0, width, height))
	draw.Draw(img, img.Bounds(), &image.Uniform{background}, image.Point{}, draw.Src)

	plot := image.Rect(padLeft, padTop, width-padRight, height-padBottom)
	draw.Draw(img, plot, &image.Uniform{panel}, image.Point{}, draw.Src)

	low, high, ok := bounds(spec.Series)
	if !ok {
		// Nothing charted: say so rather than drawing an empty grid that reads
		// as a price of zero.
		drawText(img, inconsolata.Bold8x16, textBright, padLeft, padTop-18, spec.Title)
		drawText(img, inconsolata.Regular8x16, textDim,
			plot.Min.X+12, plot.Min.Y+plot.Dy()/2, "No price history for this window")
		return png.Encode(w, img)
	}

	// A flat line would divide by zero, and has to sit somewhere in the plot
	// rather than on its floor.
	if high-low < 0.01 {
		low, high = low-0.5, high+0.5
	}
	low, high = padRange(low, high)

	drawGrid(img, plot, low, high)
	drawDateAxis(img, plot, spec.Labels)

	for _, series := range spec.Series {
		drawSeries(img, plot, series, low, high)
	}

	drawText(img, inconsolata.Bold8x16, textBright, padLeft, padTop-24, spec.Title)
	if spec.Subtitle != "" {
		drawText(img, inconsolata.Regular8x16, textDim, padLeft, padTop-8, spec.Subtitle)
	}
	drawLegend(img, plot, spec.Series, height)

	return png.Encode(w, img)
}

// bounds is the range of every value that is not a gap.
func bounds(all []Series) (low, high float64, ok bool) {
	low, high = math.Inf(1), math.Inf(-1)
	for _, series := range all {
		for _, value := range series.Data {
			if math.IsNaN(value) || math.IsInf(value, 0) {
				continue
			}
			ok = true
			low = math.Min(low, value)
			high = math.Max(high, value)
		}
	}
	return low, high, ok
}

// padRange opens the range out to round numbers, so the gridlines land on
// prices someone would say out loud.
func padRange(low, high float64) (float64, float64) {
	span := high - low
	step := niceStep(span / 4)

	low = math.Floor(low/step) * step
	high = math.Ceil(high/step) * step
	if low < 0 {
		low = 0
	}
	return low, high
}

// niceStep rounds a gridline interval to 1, 2, 5 or 10 times a power of ten.
func niceStep(raw float64) float64 {
	if raw <= 0 {
		return 1
	}
	magnitude := math.Pow(10, math.Floor(math.Log10(raw)))
	switch normalized := raw / magnitude; {
	case normalized <= 1:
		return magnitude
	case normalized <= 2:
		return 2 * magnitude
	case normalized <= 5:
		return 5 * magnitude
	default:
		return 10 * magnitude
	}
}

func drawGrid(img *image.RGBA, plot image.Rectangle, low, high float64) {
	const lines = 4
	for i := 0; i <= lines; i++ {
		value := low + (high-low)*float64(i)/lines
		y := plot.Max.Y - int(float64(plot.Dy())*float64(i)/lines)
		if y >= plot.Max.Y {
			y = plot.Max.Y - 1
		}

		draw.Draw(img, image.Rect(plot.Min.X, y, plot.Max.X, y+1),
			&image.Uniform{gridline}, image.Point{}, draw.Src)

		label := fmt.Sprintf("$%.2f", value)
		if value >= 100 {
			label = fmt.Sprintf("$%.0f", value)
		}
		drawText(img, inconsolata.Regular8x16, textDim,
			plot.Min.X-8-textWidth(inconsolata.Regular8x16, label), y+5, label)
	}
}

// drawDateAxis writes the ends of the window and its middle, which is as much
// as fits without the labels running into each other.
func drawDateAxis(img *image.RGBA, plot image.Rectangle, labels []string) {
	if len(labels) == 0 {
		return
	}

	y := plot.Max.Y + 18
	at := func(index, x int, align int) {
		label := labels[index]
		width := textWidth(inconsolata.Regular8x16, label)
		drawText(img, inconsolata.Regular8x16, textDim, x-width*align/2, y, label)
	}

	at(0, plot.Min.X, 0)
	if len(labels) > 2 {
		at(len(labels)/2, plot.Min.X+plot.Dx()/2, 1)
	}
	if len(labels) > 1 {
		at(len(labels)-1, plot.Max.X-textWidth(inconsolata.Regular8x16, labels[len(labels)-1]), 0)
	}
}

// drawSeries draws one line, breaking it wherever the record has a gap.
func drawSeries(img *image.RGBA, plot image.Rectangle, series Series, low, high float64) {
	if len(series.Data) == 0 {
		return
	}

	stroke := parseColor(series.Color)
	span := high - low
	pointAt := func(i int) (float64, float64) {
		x := float64(plot.Min.X)
		if len(series.Data) > 1 {
			x += float64(plot.Dx()) * float64(i) / float64(len(series.Data)-1)
		}
		y := float64(plot.Max.Y) - float64(plot.Dy())*(series.Data[i]-low)/span
		return x, y
	}

	var run [][2]float64
	flush := func() {
		if len(run) > 1 {
			strokePath(img, plot, run, stroke)
		} else if len(run) == 1 {
			// A day on its own still happened; a dot says so where a line
			// cannot.
			dot(img, plot, run[0][0], run[0][1], stroke)
		}
		run = run[:0]
	}

	for i, value := range series.Data {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			flush()
			continue
		}
		x, y := pointAt(i)
		run = append(run, [2]float64{x, y})
	}
	flush()
}

// strokePath fills the polyline as one ribbon: out along one side of the run
// and back along the other, closed into a single polygon.
//
// One polygon rather than a quad per segment because the rasterizer sums the
// area a path covers and takes the size of the sum: two shapes wound opposite
// ways cancel where they overlap, which drew the line as a dotted one, a hole
// at every joint.
func strokePath(img *image.RGBA, clip image.Rectangle, points [][2]float64, stroke color.RGBA) {
	half := lineWidth / 2

	// The outward direction at each point, from the run either side of it, so
	// the ribbon turns corners without pinching.
	normals := make([][2]float64, len(points))
	for i := range points {
		previous, next := i-1, i+1
		if previous < 0 {
			previous = i
		}
		if next >= len(points) {
			next = i
		}
		dx := points[next][0] - points[previous][0]
		dy := points[next][1] - points[previous][1]
		length := math.Hypot(dx, dy)
		if length == 0 {
			normals[i] = [2]float64{0, half}
			continue
		}
		normals[i] = [2]float64{-dy / length * half, dx / length * half}
	}

	rasterizer := vector.NewRasterizer(clip.Dx(), clip.Dy())
	at := func(i int, sign float64) (float32, float32) {
		x := points[i][0] + normals[i][0]*sign - float64(clip.Min.X)
		y := points[i][1] + normals[i][1]*sign - float64(clip.Min.Y)
		return float32(x), float32(y)
	}

	x, y := at(0, 1)
	rasterizer.MoveTo(x, y)
	for i := 1; i < len(points); i++ {
		rasterizer.LineTo(at(i, 1))
	}
	for i := len(points) - 1; i >= 0; i-- {
		rasterizer.LineTo(at(i, -1))
	}
	rasterizer.ClosePath()

	rasterizer.Draw(img, clip, &image.Uniform{stroke}, image.Point{})
}

func dot(img *image.RGBA, clip image.Rectangle, x, y float64, stroke color.RGBA) {
	rasterizer := vector.NewRasterizer(clip.Dx(), clip.Dy())
	cx, cy := float32(x-float64(clip.Min.X)), float32(y-float64(clip.Min.Y))
	const r = lineWidth

	rasterizer.MoveTo(cx-r, cy-r)
	rasterizer.LineTo(cx+r, cy-r)
	rasterizer.LineTo(cx+r, cy+r)
	rasterizer.LineTo(cx-r, cy+r)
	rasterizer.ClosePath()
	rasterizer.Draw(img, clip, &image.Uniform{stroke}, image.Point{})
}

// drawLegend names the lines under the plot, in the colours they were drawn.
func drawLegend(img *image.RGBA, plot image.Rectangle, all []Series, height int) {
	x := plot.Min.X
	y := height - 12
	for _, series := range all {
		if series.Name == "" {
			continue
		}
		swatch := image.Rect(x, y-9, x+9, y)
		draw.Draw(img, swatch, &image.Uniform{parseColor(series.Color)}, image.Point{}, draw.Src)

		drawText(img, inconsolata.Regular8x16, textDim, x+14, y, series.Name)
		x += 14 + textWidth(inconsolata.Regular8x16, series.Name) + 18

		// Whatever is left does not fit on the line, and a legend running off
		// the edge is worse than a short one.
		if x > plot.Max.X-40 {
			drawText(img, inconsolata.Regular8x16, textDim, x, y, "…")
			return
		}
	}
}

// parseColor reads the "#rrggbb" the datasets carry, falling back to the
// site's accent for anything it cannot.
func parseColor(value string) color.RGBA {
	value = strings.TrimPrefix(strings.TrimSpace(value), "#")
	if len(value) != 6 {
		return fallback
	}
	var rgb [3]uint8
	for i := 0; i < 3; i++ {
		var component int
		if _, err := fmt.Sscanf(value[i*2:i*2+2], "%02x", &component); err != nil {
			return fallback
		}
		rgb[i] = uint8(component)
	}
	return color.RGBA{rgb[0], rgb[1], rgb[2], 0xff}
}

func drawText(img *image.RGBA, face font.Face, col color.RGBA, x, y int, text string) {
	drawer := &font.Drawer{
		Dst:  img,
		Src:  &image.Uniform{col},
		Face: face,
		Dot:  fixed.P(x, y),
	}
	drawer.DrawString(text)
}

func textWidth(face font.Face, text string) int {
	return font.MeasureString(face, text).Round()
}
