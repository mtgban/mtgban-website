package metricsreport

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/observability"
)

func TestErrorLabel(t *testing.T) {
	if got := ErrorLabel("navbar.js", 42, "TypeError"); got != "navbar.js:42 TypeError" {
		t.Errorf("got %q", got)
	}
	if got := ErrorLabel("other", 0, "ScriptError"); got != "other ScriptError" {
		t.Errorf("a row with no line reads %q", got)
	}
}

// errorTopRows are two rows of one build, the second with no line.
func errorTopRows() []observability.ErrorTop {
	day := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	return []observability.ErrorTop{
		{Script: "navbar.js", Line: 42, Class: "TypeError", N: 31, Desktop: 27, Mobile: 4, FirstDay: day, LastDay: day},
		{Script: "other", Line: 0, Class: "ScriptError", N: 9, Desktop: 9, FirstDay: day, LastDay: day},
	}
}

func TestErrorSignals(t *testing.T) {
	build := strings.Repeat("0f", 20)
	got := ErrorSignals(errorTopRows(), build)
	if len(got) != 2 {
		t.Fatalf("got %d signals", len(got))
	}
	if got[0].Section != "failures" || got[0].Label != "navbar.js:42 TypeError" || got[0].Count != 31 ||
		got[0].Evidence != "build 0f0f0f0, desktop 27, mobile 4, since 2026-11-03" {
		t.Errorf("first signal = %+v", got[0])
	}
	if got[0].Name != "ui.js.error" || got[0].Scope != "navbar.js" || got[0].Value != "TypeError" {
		t.Errorf("the row's registry key = %q %q %q", got[0].Name, got[0].Scope, got[0].Value)
	}
	if got[0].Help != "A script error or an unhandled promise rejection, by script, line and type." || got[1].Help != got[0].Help {
		t.Errorf("help %q, want one naming both errors and rejections", got[0].Help)
	}
	if got[0].Denom != 0 || got[0].Previous != 0 || got[0].Rate != 0 || got[0].HasRate() {
		t.Errorf("an error row is a count with no rate: %+v", got[0])
	}
	if got[1].Label != "other ScriptError" {
		t.Errorf("a row with no line reads %q", got[1].Label)
	}
	if ErrorSignals(nil, build) != nil {
		t.Error("no rows, no signals")
	}
}

// The rows go where WithErrors puts them, and the digest diffs their labels.
func TestErrorSignalsThroughTheReports(t *testing.T) {
	build := strings.Repeat("0f", 20)
	got := WithErrors([]Signal{{Section: SectionFailures, Label: "a"}, {Section: SectionMobile, Label: "b"}}, ErrorSignals(errorTopRows(), build), true)
	var labels []string
	for _, s := range got {
		labels = append(labels, s.Label)
		if s.NotMeasured {
			t.Errorf("a measured build has a not-measured row: %+v", s)
		}
	}
	if !slices.Equal(labels, []string{"a", "navbar.js:42 TypeError", "other ScriptError", "b"}) {
		t.Errorf("labels = %v", labels)
	}
	d := Changes(counted(Snapshot{Errors: []string{ErrorLabel("navbar.js", 42, "TypeError"), ErrorLabel("utils.js", 7, "RangeError")}}),
		counted(Snapshot{Errors: []string{ErrorLabel("navbar.js", 42, "TypeError")}}))
	if len(d.Sections) != 1 || d.Sections[0].Title != titleErrors || !slices.Equal(d.Sections[0].Lines, []string{"utils.js:7 RangeError"}) {
		t.Errorf("digest = %+v", d.Sections)
	}
}
