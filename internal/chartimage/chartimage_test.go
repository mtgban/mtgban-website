package chartimage

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
	"testing"
)

func render(t *testing.T, spec Spec) image.Image {
	t.Helper()
	var buffer bytes.Buffer
	if err := Render(&buffer, spec); err != nil {
		t.Fatalf("rendering: %v", err)
	}
	img, err := png.Decode(&buffer)
	if err != nil {
		t.Fatalf("what came out is not a PNG: %v", err)
	}
	return img
}

func ramp(n int) []float64 {
	data := make([]float64, n)
	for i := range data {
		data[i] = 10 + float64(i)/4
	}
	return data
}

// The point of the package: a picture, at the size that was asked for.
func TestRenderProducesAPNG(t *testing.T) {
	img := render(t, Spec{
		Title:  "A Card",
		Labels: []string{"2026-01-01", "2026-01-02", "2026-01-03"},
		Series: []Series{{Name: "TCG Low", Color: "#5b8def", Data: []float64{1, 2, 3}}},
		Width:  400,
		Height: 220,
	})

	if got := img.Bounds().Dx(); got != 400 {
		t.Errorf("width %d, want 400", got)
	}
	if got := img.Bounds().Dy(); got != 220 {
		t.Errorf("height %d, want 220", got)
	}
}

// A card nobody has priced in the window still has to come back as an image,
// rather than as an error or as a grid whose floor reads as a price of zero.
func TestRenderSaysWhenThereIsNothingToDraw(t *testing.T) {
	for _, spec := range []Spec{
		{Title: "Nothing"},
		{Title: "All gaps", Labels: []string{"2026-01-01"}, Series: []Series{
			{Name: "TCG Low", Color: "#5b8def", Data: []float64{math.NaN()}},
		}},
	} {
		var buffer bytes.Buffer
		if err := Render(&buffer, spec); err != nil {
			t.Fatalf("%q: %v", spec.Title, err)
		}
		if _, err := png.Decode(bytes.NewReader(buffer.Bytes())); err != nil {
			t.Errorf("%q did not come back as a PNG: %v", spec.Title, err)
		}
	}
}

// A price that never moved has no range to scale against, and dividing by it
// would put the line nowhere.
func TestRenderHandlesAFlatLine(t *testing.T) {
	flat := make([]float64, 40)
	for i := range flat {
		flat[i] = 7.5
	}
	img := render(t, Spec{
		Title:  "Flat",
		Labels: make([]string, 40),
		Series: []Series{{Name: "TCG Low", Color: "#ff0000", Data: flat}},
	})
	if !hasColor(img, color.RGBA{0xff, 0, 0, 0xff}) {
		t.Error("a flat line was not drawn at all")
	}
}

// A day with no price is a hole in the record, and the line has to break over
// it rather than run straight through as though the price had been observed.
func TestAGapBreaksTheLine(t *testing.T) {
	const n = 120
	data := ramp(n)
	for i := 40; i < 80; i++ {
		data[i] = math.NaN()
	}

	img := render(t, Spec{
		Title:  "Gapped",
		Labels: make([]string, n),
		Series: []Series{{Name: "TCG Low", Color: "#ff0000", Data: data}},
		Width:  DefaultWidth,
		Height: DefaultHeight,
	})

	plot := image.Rect(padLeft, padTop, DefaultWidth-padRight, DefaultHeight-padBottom)
	columnAt := func(index int) int {
		return plot.Min.X + plot.Dx()*index/(n-1)
	}

	// The middle of the gap carries none of the line.
	if columnHasColor(img, columnAt(60), plot, color.RGBA{0xff, 0, 0, 0xff}) {
		t.Error("the line runs through a stretch with no prices in it")
	}
	// The stretches either side of it do.
	for _, index := range []int{10, 110} {
		if !columnHasColor(img, columnAt(index), plot, color.RGBA{0xff, 0, 0, 0xff}) {
			t.Errorf("the line is missing at point %d, where there is a price", index)
		}
	}
}

// Gridlines are read as prices, so they land on numbers someone would say.
func TestNiceStepRoundsToReadableIntervals(t *testing.T) {
	for _, tt := range []struct {
		raw  float64
		want float64
	}{
		{0.4, 0.5}, {1, 1}, {1.5, 2}, {3, 5}, {7, 10}, {24, 50}, {0, 1},
	} {
		if got := niceStep(tt.raw); got != tt.want {
			t.Errorf("niceStep(%v) = %v, want %v", tt.raw, got, tt.want)
		}
	}
}

// The colours come from the datasets as the site writes them, and anything
// unreadable still has to draw as something.
func TestParseColor(t *testing.T) {
	if got := parseColor("#22c55e"); got != (color.RGBA{0x22, 0xc5, 0x5e, 0xff}) {
		t.Errorf("parsed #22c55e as %v", got)
	}
	if got := parseColor("22c55e"); got != (color.RGBA{0x22, 0xc5, 0x5e, 0xff}) {
		t.Errorf("a colour without its hash came out as %v", got)
	}
	for _, bad := range []string{"", "blue", "#12345", "#zzzzzz"} {
		if got := parseColor(bad); got != fallback {
			t.Errorf("parseColor(%q) = %v, want the fallback", bad, got)
		}
	}
}

func hasColor(img image.Image, want color.RGBA) bool {
	bounds := img.Bounds()
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			if closeTo(img.At(x, y), want) {
				return true
			}
		}
	}
	return false
}

func columnHasColor(img image.Image, x int, within image.Rectangle, want color.RGBA) bool {
	for y := within.Min.Y; y < within.Max.Y; y++ {
		if closeTo(img.At(x, y), want) {
			return true
		}
	}
	return false
}

// The line is drawn with soft edges, so its pixels are the colour blended into
// the panel behind it rather than the colour itself.
func closeTo(got color.Color, want color.RGBA) bool {
	r, g, b, _ := got.RGBA()
	return abs(int(r>>8)-int(want.R)) < 48 &&
		abs(int(g>>8)-int(want.G)) < 48 &&
		abs(int(b>>8)-int(want.B)) < 48
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
