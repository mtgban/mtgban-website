package metricsreport

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/mtgban/mtgban-website/observability"
)

// Snapshot is what the reports said as of one day.
type Snapshot struct {
	Candidates []Candidate
	Signals    []Signal
	Errors     []string // one label a script error row first seen in the snapshot's seven days
	Problems   []string // from Problems
	// CounterDays is how many days of the seven its Signals cover had metrics.flush rows.
	CounterDays int
}

// DigestSection is one titled list of short lines.
type DigestSection struct {
	Title string
	Lines []string
}

// Digest is what changed in a week, as plain data; sections with no lines are left out.
type Digest struct{ Sections []DigestSection }

// NothingChanged is what an empty digest says.
const NothingChanged = "Nothing changed in the last seven days."

// weekNotCounted is the digest's one line when either week was not fully counted.
func weekNotCounted(now, prev int) string {
	return fmt.Sprintf("The last %d days have %d counted days and the %d before have %d; each needs %d, so no row is compared.",
		digestWeekDays, now, digestWeekDays, prev, minWeekDays)
}

// The digest's limits.
const (
	maxNewErrors    = 5   // lines the New errors section prints
	maxMoved        = 3   // lines the Moved most section prints
	maxSectionLines = 12  // lines any section prints, the last saying how many more
	maxLineRunes    = 200 // a line is cut to this many runes
)

// The digest's section titles, in order.
const (
	titleRemove = "New to consider removing"
	titleMoved  = "Moved most"
	titleNotCmp = "Not compared"
	titleErrors = "New errors: a script and error type no build had shown before this week"
	titleHealth = "Health"
)

// Empty reports whether the digest has nothing to say.
func (d Digest) Empty() bool {
	for _, s := range d.Sections {
		if len(s.Lines) > 0 {
			return false
		}
	}
	return true
}

// Text is the digest as plain text: NothingChanged when empty, else each section's
// title and its lines prefixed "- ", sections a blank line apart, no trailing newline.
func (d Digest) Text() string {
	if d.Empty() {
		return NothingChanged
	}
	var parts []string
	for _, s := range d.Sections {
		if len(s.Lines) == 0 {
			continue
		}
		var b strings.Builder
		b.WriteString(cleanLine(s.Title))
		for _, l := range s.Lines {
			b.WriteString("\n- ")
			b.WriteString(cleanLine(l))
		}
		parts = append(parts, b.String())
	}
	return strings.Join(parts, "\n\n")
}

// Changes says what changed in the last 7 finished days against the 7 before. It is pure;
// the caller loads DigestQueries and builds now and prev with DigestSnapshots, whatever the
// page's picker says. A candidate settles only at 30 measured days; with either week's
// CounterDays under 7, Not compared says so in place of Moved most; Problems are now's only.
func Changes(now, prev Snapshot) Digest {
	var d Digest
	add := func(title string, lines []string) {
		if len(lines) == 0 {
			return
		}
		if len(lines) > maxSectionLines {
			more := len(lines) - (maxSectionLines - 1)
			lines = append(slices.Clone(lines[:maxSectionLines-1]), fmt.Sprintf("and %d more", more))
		}
		clean := make([]string, len(lines))
		for i, l := range lines {
			clean[i] = cleanLine(l)
		}
		d.Sections = append(d.Sections, DigestSection{Title: title, Lines: clean})
	}
	add(titleRemove, newRemovals(now.Candidates, prev.Candidates))
	if now.CounterDays < minWeekDays || prev.CounterDays < minWeekDays {
		// a row missing from an uncounted week is not a zero, so nothing is compared
		add(titleNotCmp, []string{weekNotCounted(now.CounterDays, prev.CounterDays)})
	} else {
		add(titleMoved, movedMost(now.Signals, prev.Signals))
	}
	add(titleErrors, newErrors(now.Errors, prev.Errors))
	add(titleHealth, now.Problems)
	return d
}

// ShiftPeriods returns the totals with periods 0 to by-1 dropped and every other Period
// lowered by by, so the window before reads as the window; the input is not modified.
func ShiftPeriods(totals []observability.DayTotal, by int) []observability.DayTotal {
	var out []observability.DayTotal
	for _, t := range totals {
		if t.Period >= by {
			t.Period -= by
			out = append(out, t)
		}
	}
	return out
}

// isSettled reports whether a candidate is unused or rare over a full 30 measured days.
func isSettled(c Candidate) bool {
	return (c.Class == ClassUnused || c.Class == ClassRare) && c.DaysMeasured >= newAfterDays
}

// newRemovals counts by area the candidates settled in now and not in prev, most first.
func newRemovals(now, prev []Candidate) []string {
	before := map[Unit]bool{}
	for _, c := range prev {
		if isSettled(c) {
			before[Unit{c.Name, c.Scope, c.Value}] = true
		}
	}
	seen := map[Unit]bool{}
	byArea := map[string]int{}
	for _, c := range now {
		u := Unit{c.Name, c.Scope, c.Value}
		if !isSettled(c) || before[u] || seen[u] {
			continue
		}
		seen[u] = true
		area := c.Area
		if area == "" {
			area = "no area"
		}
		byArea[area]++
	}
	areas := make([]string, 0, len(byArea))
	for a := range byArea {
		areas = append(areas, a)
	}
	slices.SortFunc(areas, func(a, b string) int { return cmp.Or(cmp.Compare(byArea[b], byArea[a]), cmp.Compare(a, b)) })
	lines := make([]string, len(areas))
	for i, a := range areas {
		lines[i] = fmt.Sprintf("%s: %d", a, byArea[a])
	}
	return lines
}

// signalKey matches a signal across snapshots.
type signalKey struct{ section, name, scope, value string }

// movedSections are the Invest sections whose rows can move.
var movedSections = []string{SectionWalls, SectionFailures, SectionMobile}

// movedMost is the measured walls, failures and mobile rows that moved most, at most three.
// A row new since prev moved from 0; a row whose name was not measured in prev is skipped,
// and a failure rate row is compared by its rate, only when it has one in both snapshots.
// A move needs minMoveCount in count and minMovePercent in count, or in rate for a rate row.
func movedMost(now, prev []Signal) []string {
	before := map[signalKey]Signal{}
	unmeasured := map[signalKey]bool{}
	for _, s := range prev {
		if s.NotMeasured {
			unmeasured[signalKey{s.Section, s.Name, "", ""}] = true
			continue
		}
		k := signalKey{s.Section, s.Name, s.Scope, s.Value}
		if _, ok := before[k]; !ok {
			before[k] = s
		}
	}
	type move struct {
		s, old    Signal
		was       int64
		magnitude float64
	}
	var moves []move
	seen := map[signalKey]bool{}
	for _, s := range now {
		k := signalKey{s.Section, s.Name, s.Scope, s.Value}
		if s.NotMeasured || !slices.Contains(movedSections, s.Section) || seen[k] || unmeasured[signalKey{s.Section, s.Name, "", ""}] {
			continue
		}
		seen[k] = true
		old, had := before[k]
		if isRateRow(s) && (!s.HasRate() || !had || !old.HasRate()) {
			continue
		}
		was := old.Count
		delta := s.Count - was
		if max(was, s.Count) < growthFloor || max(delta, -delta) < minMoveCount {
			continue
		}
		// the move and its base as integers, so the percent line is exact
		size, base := max(delta, -delta), max(was, 1)
		if isRateRow(s) {
			size, base = s.Count*old.Denom-old.Count*s.Denom, old.Count*s.Denom
			size = max(size, -size)
		}
		if base <= 0 || size*100 < minMovePercent*base {
			continue
		}
		magnitude := float64(size) / float64(base)
		moves = append(moves, move{s, old, was, magnitude})
	}
	slices.SortFunc(moves, func(a, b move) int {
		return cmp.Or(cmp.Compare(b.magnitude, a.magnitude), compareKey(a.s, b.s), cmp.Compare(a.s.Section, b.s.Section))
	})
	var lines []string
	for _, m := range moves[:min(len(moves), maxMoved)] {
		if isRateRow(m.s) {
			lines = append(lines, fmt.Sprintf("%s: %.1f%% to %.1f%%", m.s.Label, m.old.Rate*100, m.s.Rate*100))
			continue
		}
		lines = append(lines, fmt.Sprintf("%s: %d to %d", m.s.Label, m.was, m.s.Count))
	}
	return lines
}

// isRateRow reports whether a row is a failure rate, not a count.
func isRateRow(s Signal) bool {
	return s.Section == SectionFailures && s.Denom > 0
}

// newErrors is now's error labels not in prev, in now's order, at most maxNewErrors.
func newErrors(now, prev []string) []string {
	var lines []string
	for _, e := range now {
		if len(lines) == maxNewErrors {
			break
		}
		if !slices.Contains(prev, e) && !slices.Contains(lines, e) {
			lines = append(lines, e)
		}
	}
	return lines
}

// cleanLine makes a line one plain line: control characters become spaces, and it is cut to maxLineRunes.
func cleanLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > maxLineRunes {
		s = string(r[:maxLineRunes])
	}
	return s
}
