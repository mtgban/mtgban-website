package main

import (
	"strings"
	"testing"
)

// The People panel's grants table edits in place: render the exact row shape
// Admin() builds (index 3 of Tables, six columns) to confirm each cell is a
// field of its row's save form, the row's tier is the one selected, and the
// quick-add form still carries the overrides field.
func TestAdminGrantRowsEditInPlace(t *testing.T) {
	pv := PageVars{
		UserNav: &NavElem{Short: "b"},
		Tiers:   []string{"Modern", "Pioneer"},
		AdminVars: AdminVars{
			Tables: [][][]string{
				{}, // dashboard tables 0-2, unused by this test
				{},
				{},
				{ // grants table (Tables index 3)
					{"1", "cat", "person@example.com", "Person", "Pioneer", `{"Search":{"SearchOfflineMode":"true"}}`},
					{"2", "", "plain@example.com", "Plain", "Modern", ""},
					{"3", "", "gone@example.com", "Gone", "Pauper", ""},
				},
			},
		},
	}

	out := renderPage(t, "admin.html", false, pv)

	for _, want := range []string{
		`name="grantOverrides" placeholder=`,
		"<th>Overrides</th>",
		`<form method="POST" action="admin?page=people" id="admin-grant-1">`,
		`<input type="hidden" name="updateEmail" value="person@example.com">`,
		`<input form="admin-grant-1" type="email" name="grantEmail" value="person@example.com"`,
		`<input form="admin-grant-1" type="text" name="grantOverrides" value="{&#34;Search&#34;:{&#34;SearchOfflineMode&#34;:&#34;true&#34;}}"`,
		`<input form="admin-grant-2" type="text" name="grantName" value="Plain"`,
		`<input type="hidden" name="revokeEmail" value="plain@example.com">`,
		`src="/js/admin-people.js?hash=`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the page is missing %s", want)
		}
	}
	// The quick-add form's fields run in the table's column order.
	form := out[strings.Index(out, `class="admin-grant-form"`):strings.Index(out, `class="table-data admin-table admin-grants"`)]
	last := -1
	for _, field := range []string{"grantCategory", "grantEmail", "grantName", "grantTier", "grantOverrides"} {
		at := strings.Index(form, `name="`+field+`"`)
		if at < last {
			t.Errorf("%s is out of the table's column order in the quick-add form", field)
		}
		last = at
	}
	// Row 1 is a Pioneer, row 2 a Modern: each select opens on its own tier.
	if got := strings.Count(out, `<option value="Pioneer" selected>`); got != 1 {
		t.Errorf("%d Pioneer options selected, want row 1's alone", got)
	}
	if got := strings.Count(out, `<option value="Modern" selected>`); got != 1 {
		t.Errorf("%d Modern options selected, want row 2's alone", got)
	}
	// Row 3's tier is not in the ACL: its select opens on that tier all the
	// same, not on the first one listed.
	if !strings.Contains(out, `<option value="Pauper" selected>Pauper (not in ACL)</option>`) {
		t.Error("row 3's select does not open on its own tier")
	}
	if got := strings.Count(out, ` selected>`); got != 3 {
		t.Errorf("%d options selected, want one per row", got)
	}
}
