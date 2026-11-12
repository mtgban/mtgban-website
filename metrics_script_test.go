package main

import (
	"os"
	"regexp"
	"slices"
	"testing"

	"github.com/mtgban/mtgban-website/observability"
)

// The class, bucket and script lists in js/metrics.js are the registry's.
func TestMetricsScriptMatchesTheRegistry(t *testing.T) {
	src, err := os.ReadFile("js/metrics.js")
	if err != nil {
		t.Fatal(err)
	}
	list := func(name string) []string {
		m := regexp.MustCompile(`(?s)var ` + name + ` = \[(.*?)\];`).FindSubmatch(src)
		if m == nil {
			t.Fatalf("js/metrics.js has no %s array", name)
		}
		var out []string
		for _, q := range regexp.MustCompile(`'([^']*)'`).FindAllSubmatch(m[1], -1) {
			out = append(out, string(q[1]))
		}
		return out
	}
	for _, c := range []struct{ js, name string }{
		{"ERROR_CLASSES", "ui.js.error"},
		{"ERROR_CLASSES", "ui.js.rejection"},
		{"TTFB_BUCKETS", "ui.perf.ttfb"},
		{"LCP_BUCKETS", "ui.perf.lcp"},
		{"DOM_READY_BUCKETS", "ui.perf.dom_ready"},
	} {
		n, _ := observability.Lookup(c.name)
		if got := list(c.js); !slices.Equal(got, n.Enum) {
			t.Errorf("%s = %v, but %s allows %v", c.js, got, c.name, n.Enum)
		}
	}
	if got, want := list("SCRIPTS"), observability.Scripts(); !slices.Equal(got, want) {
		t.Errorf("SCRIPTS = %v, but observability.Scripts() is %v", got, want)
	}
}
