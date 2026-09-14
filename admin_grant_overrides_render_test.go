package main

import (
	"strings"
	"testing"
)

// The People panel's grants table gains an Overrides column and the
// quick-add form gains a field for it; render the exact row shape Admin()
// builds (index 3 of Tables, six columns) to confirm the template's
// {{index $row 5}} doesn't run past the row and the new markup shows up.
func TestAdminGrantOverridesColumnRenders(t *testing.T) {
	pv := PageVars{
		BetaNav: &NavElem{Short: "b"},
		Tables: [][][]string{
			{}, // dashboard tables 0-2, unused by this test
			{},
			{},
			{ // grants table (Tables index 3)
				{"1", "cat", "person@example.com", "Person", "Pioneer", `{"Search":{"SearchOfflineMode":"true"}}`},
				{"2", "", "plain@example.com", "Plain", "Modern", ""},
			},
		},
	}

	out := renderPage(t, "admin.html", false, pv)

	if !strings.Contains(out, `name="grantOverrides"`) {
		t.Error("quick-add form is missing the grantOverrides field")
	}
	if !strings.Contains(out, "<th>Overrides</th>") {
		t.Error("grants table is missing the Overrides header")
	}
	if !strings.Contains(out, `SearchOfflineMode`) {
		t.Error("a grant's Overrides JSON did not render into its row")
	}
}
