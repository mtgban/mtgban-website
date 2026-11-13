package observability

import (
	"slices"
	"strings"
	"testing"
)

func TestAPIFamily(t *testing.T) {
	for _, c := range []struct{ path, want string }{
		{"/api/mtgban/search/retail/lightning bolt s:lea", "api.v1.search"},
		{"/api/mtgban/search/", "api.v1.search"},
		{"/api/mtgban/all.json", "api.v1"},
		{"/api/mtgban/retail/CK.json", "api.v1"},
		{"/api/v2/search/buylist/t:goblin cmc<=2", "api.v2.search"},
		{"/api/v2/search/retail/../../etc/passwd", "api.v2.search"},
		{"/api/v2/history/5f8287b1-5bb6-5f4c-ad17-316a40d5bb0c", "api.v2.history"},
		{"/api/v2/history/set/LEA.csv", "api.v2.history"},
		{"/api/v2/newspaper/reports.json", "api.v2.newspaper"},
		{"/api/v2/newspaper/syp.csv", "api.v2.newspaper"},
		{"/api/v2/retail/all.json", "api.v2"},
		{"/api/v2/", "api.v2"},
		{"/api/load/CK", "api.load"},
		{"/api/load/datastore", "api.load"},
		{"/api/v2", "other"}, // no trailing slash: the mux redirects it
		{"/api/v20/retail/all.json", "other"},
		{"/api/v3/retail/all.json", "other"},
		{"/api/suggest", "other"}, // the site's own endpoints are not price API
		{"/api/userstate/favorites", "other"},
		{"/API/V2/retail/all.json", "other"},
		{"/search", "other"},
		{"api/v2/retail/all.json", "other"},
		{"", "other"},
	} {
		if got := APIFamily(c.path); got != c.want {
			t.Errorf("APIFamily(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

// The label set is closed: whatever the path, the answer is a family or other.
func TestAPIFamilyIsBounded(t *testing.T) {
	families := APIFamilies()
	if len(families) != 7 || slices.Contains(families, "other") {
		t.Fatalf("APIFamilies = %v, want the seven labels without other", families)
	}
	for _, f := range families {
		if len(f) > 40 {
			t.Errorf("family %q is over 40 characters", f)
		}
	}
	for _, path := range []string{
		"/api/v2/search/retail/" + strings.Repeat("x", 500),
		"/api/mtgban/search/retail/<script>alert(1)</script>",
		"/api/v2/history/00000000-0000-0000-0000-000000000000,11111111-1111-1111-1111-111111111111",
		"/wp-login.php",
	} {
		if got := APIFamily(path); got != "other" && !slices.Contains(families, got) {
			t.Errorf("APIFamily(%q) = %q, outside the label set", path, got)
		}
	}
	families[0] = "changed"
	if APIFamilies()[0] == "changed" {
		t.Error("APIFamilies returns a fresh slice")
	}
}
