package main

import (
	"io"
	"log"
	"net/url"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/internal/access"
)

// A People row saves in place: a POST naming the row by updateEmail rewrites
// that grant with the row's fields where it stands in the list, refuses an
// email another row holds, says so when nothing changed, and leaves the
// quick-add path as it was.
func TestAdminGrantSaveEditsTheRow(t *testing.T) {
	freshPokes(t)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	savedLog := LogPages["Admin"]
	t.Cleanup(func() { LogPages["Admin"] = savedLog })
	LogPages["Admin"] = log.New(io.Discard, "", 0)
	loadAccessFiles(t, `{"Legacy":{"Search":{}},"Vintage":{"Search":{}}}`,
		`[`+grantFor("a@example.com", "Legacy")+`,`+grantFor("b@example.com", "Legacy")+`,`+grantFor("d@example.com", "Pauper")+`]`)

	row := url.Values{
		"updateEmail":    {"a@example.com"},
		"grantEmail":     {"A@Example.com"},
		"grantName":      {"Alice"},
		"grantCategory":  {"tester"},
		"grantTier":      {"Vintage"},
		"grantOverrides": {`{"Search":{"SearchOfflineMode":"true"}}`},
	}
	var pv PageVars
	adminGrantSave(postForm("/admin", row), &pv)
	grants := PatreonGrants()
	if pv.WarningMessage != "" || !strings.HasPrefix(pv.InfoMessage, "Updated the grant for a@example.com") {
		t.Fatalf("warning %q, info %q; want the update reported", pv.WarningMessage, pv.InfoMessage)
	}
	if len(grants) != 3 || grants[0].Email != "a@example.com" || grants[0].Name != "Alice" ||
		grants[0].Category != "tester" || grants[0].Tier != "Vintage" ||
		grants[0].Overrides["Search"]["SearchOfflineMode"] != "true" || grants[1].Email != "b@example.com" {
		t.Fatalf("grants %+v; want a's row rewritten in place and b's kept", grants)
	}

	pv = PageVars{}
	adminGrantSave(postForm("/admin", row), &pv)
	if pv.WarningMessage != "" || !strings.HasPrefix(pv.InfoMessage, "No changes") {
		t.Errorf("saving the row again: warning %q, info %q; want no changes reported", pv.WarningMessage, pv.InfoMessage)
	}

	taken := url.Values{"updateEmail": {"a@example.com"}, "grantEmail": {"b@example.com"}, "grantTier": {"Vintage"}}
	pv = PageVars{}
	adminGrantSave(postForm("/admin", taken), &pv)
	if !strings.Contains(pv.WarningMessage, "already has a grant") || PatreonGrants()[0].Email != "a@example.com" {
		t.Errorf("moving a onto b's email: warning %q, grants %+v; want it refused", pv.WarningMessage, PatreonGrants())
	}

	gone := url.Values{"updateEmail": {"c@example.com"}, "grantEmail": {"c@example.com"}, "grantTier": {"Vintage"}}
	pv = PageVars{}
	adminGrantSave(postForm("/admin", gone), &pv)
	if !strings.Contains(pv.WarningMessage, "no grant found") || len(PatreonGrants()) != 3 {
		t.Errorf("editing a row that is gone: warning %q, %d grants; want it refused", pv.WarningMessage, len(PatreonGrants()))
	}

	// d's tier is not in the ACL. The row posts it as its own, so an
	// untouched save is refused and d keeps the tier rather than moving to
	// the first one the select lists.
	orphan := url.Values{"updateEmail": {"d@example.com"}, "grantEmail": {"d@example.com"}, "grantName": {"Name"}, "grantCategory": {"friend"}, "grantTier": {"Pauper"}}
	pv = PageVars{}
	adminGrantSave(postForm("/admin", orphan), &pv)
	if !strings.Contains(pv.WarningMessage, "unknown tier: Pauper") || PatreonGrants()[2].Tier != "Pauper" {
		t.Errorf("saving a row whose tier is gone: warning %q, tier %q; want it refused and kept", pv.WarningMessage, PatreonGrants()[2].Tier)
	}

	added := url.Values{"grantEmail": {"c@example.com"}, "grantTier": {"Legacy"}}
	pv = PageVars{}
	adminGrantSave(postForm("/admin", added), &pv)
	grants = PatreonGrants()
	if pv.WarningMessage != "" || len(grants) != 4 || grants[3].Email != "c@example.com" {
		t.Errorf("quick-add: warning %q, grants %+v; want c appended", pv.WarningMessage, grants)
	}
}

// A People form posts the stamp of the list its table was drawn from: a
// stamp of a list that has since changed is refused and saves nothing, the
// current one saves, and a form with no stamp still saves.
func TestAdminGrantRevokeRefusesAMovedTable(t *testing.T) {
	freshPokes(t)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	savedLog := LogPages["Admin"]
	t.Cleanup(func() { LogPages["Admin"] = savedLog })
	LogPages["Admin"] = log.New(io.Discard, "", 0)
	loadAccessFiles(t, `{"Legacy":{"Search":{}}}`,
		`[`+grantFor("a@example.com", "Legacy")+`,`+grantFor("b@example.com", "Legacy")+`]`)

	old := grantsStamp(PatreonGrants())
	var pv PageVars
	adminGrantSave(postForm("/admin", url.Values{"grantEmail": {"c@example.com"}, "grantTier": {"Legacy"}, "grantsStamp": {old}}), &pv)
	if pv.WarningMessage != "" || len(PatreonGrants()) != 3 {
		t.Fatalf("quick-add with the current stamp: warning %q, %d grants; want c added", pv.WarningMessage, len(PatreonGrants()))
	}

	pv = PageVars{}
	adminGrantRevoke(postForm("/admin", url.Values{"revokeEmail": {"a@example.com"}, "grantsStamp": {old}}), &pv)
	if !strings.Contains(pv.WarningMessage, access.ErrGrantsChanged.Error()) || len(PatreonGrants()) != 3 {
		t.Errorf("revoke from a moved table: warning %q, %d grants; want it refused", pv.WarningMessage, len(PatreonGrants()))
	}

	pv = PageVars{}
	adminGrantRevoke(postForm("/admin", url.Values{"revokeEmail": {"a@example.com"}, "grantsStamp": {grantsStamp(PatreonGrants())}}), &pv)
	if pv.WarningMessage != "" || len(PatreonGrants()) != 2 {
		t.Errorf("revoke with the current stamp: warning %q, %d grants; want a removed", pv.WarningMessage, len(PatreonGrants()))
	}

	pv = PageVars{}
	adminGrantRevoke(postForm("/admin", url.Values{"revokeEmail": {"b@example.com"}}), &pv)
	if pv.WarningMessage != "" || len(PatreonGrants()) != 1 {
		t.Errorf("revoke with no stamp: warning %q, %d grants; want b removed", pv.WarningMessage, len(PatreonGrants()))
	}
}
