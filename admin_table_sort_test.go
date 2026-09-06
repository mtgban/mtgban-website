package main

import (
	"strings"
	"testing"
)

// The scraper tables sort on a header click, the way the arbit tables do,
// and say so in the markup the script hangs off: which tables, and which
// column reads as a number rather than a name.
func TestAdminScraperTablesSort(t *testing.T) {
	pv := PageVars{
		BetaNav: &NavElem{Short: "b"},
		Tables: [][][]string{
			{{"Card Kingdom", "CK", "CK", "2026-09-06T10:00:00Z", "12345", "👍", "ok"}},
			{{"Card Kingdom", "CK", "CK", "2026-09-06T10:00:00Z", "6789", "👍", "ok"}},
		},
	}
	out := renderPage(t, "admin.html", false, pv)

	if got := strings.Count(out, `class="table-data admin-table" data-sortable`); got != 2 {
		t.Errorf("%d tables sort, want the two scraper tables", got)
	}
	if got := strings.Count(out, `<th data-sort="number">Entries</th>`); got != 2 {
		t.Errorf("%d Entries headers read as a number, want 2", got)
	}
	if !strings.Contains(out, `table.admin-table[data-sortable]`) {
		t.Error("the page carries no sorter for the tables it marked")
	}
}
