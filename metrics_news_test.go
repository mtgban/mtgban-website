package main

import (
	"slices"
	"testing"

	"github.com/mtgban/mtgban-website/observability"
)

// Every report and every sortable column the newspaper has is a value the
// client counters accept, so a new report cannot ship uncounted.
func TestNewspaperPagesAreCountedValues(t *testing.T) {
	report, _ := observability.Lookup("ui.news.report")
	sort, _ := observability.Lookup("ui.news.sort")
	for _, p := range newspaperPagesInitial {
		if p.Option == "options" || p.Option == "syp" {
			continue
		}
		if !slices.Contains(report.Enum, p.Option) {
			t.Errorf("report %s is not a ui.news.report value", p.Option)
		}
		for _, h := range p.Head {
			if (h.CanSort || h.ConditionalSort) && !slices.Contains(sort.Enum, h.Field) {
				t.Errorf("%s: column %s is not a ui.news.sort value", p.Option, h.Field)
			}
		}
	}
}
