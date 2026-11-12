package observability

import (
	"slices"
	"strings"
	"testing"
)

func TestStockNamesAreTheStockFamily(t *testing.T) {
	for _, n := range All() {
		if strings.HasPrefix(n.Name, "stock.") != (n.Family == FamilyStock) {
			t.Errorf("%s: the stock. prefix and the Stock family go together", n.Name)
		}
		if n.Family == FamilyStock && n.Report != ReportContext {
			t.Errorf("%s: stored state is context, not a candidate", n.Name)
		}
	}
	if _, ok := Lookup("stock.favorites_sealed"); ok {
		t.Error("a synced favorite does not say it is sealed; nothing can count it")
	}
}

// The stock rows keep a key only when Check returns it unchanged, so every stock name must refuse what it does not list.
func TestStockNamesTakeOnlyBoundedKinds(t *testing.T) {
	for _, n := range All() {
		if n.Family != FamilyStock {
			continue
		}
		if !slices.Contains([]ValueKind{ValueNone, ValueEnum, ValueBucket}, n.Values) {
			t.Errorf("%s: value kind %d passes stored text through; want none, enum or bucket", n.Name, n.Values)
		}
		if !slices.Contains([]ScopeKind{ScopeNone, ScopeEnum}, n.Scope) {
			t.Errorf("%s: scope kind %d passes stored text through; want none or enum", n.Name, n.Scope)
		}
	}
}

// The lists handed out are copies: writing to one widens nothing the registry accepts.
func TestStockListsAreCopies(t *testing.T) {
	games, keys := StockGames(), StockPrefKeys()
	games[0], keys[0] = "test-game", "test_key"
	alerts, _ := Lookup("stock.alerts")
	if _, _, ok := alerts.Check("test-game", "retail", Validators{}); ok {
		t.Error("a write to StockGames reached the registry")
	}
	pref, _ := Lookup("stock.pref")
	if _, _, ok := pref.Check("", "test_key", Validators{}); ok {
		t.Error("a write to StockPrefKeys reached the registry")
	}
	if StockGames()[0] == "test-game" || StockPrefKeys()[0] == "test_key" {
		t.Error("a write to a copy changed the next copy")
	}
}

// No stock name, scope or value is over the registry's 40 characters.
func TestStockStringsFitTheLimit(t *testing.T) {
	for _, n := range All() {
		if n.Family != FamilyStock {
			continue
		}
		for _, s := range slices.Concat([]string{n.Name}, n.Scopes, n.Enum) {
			if len(s) > 40 {
				t.Errorf("%s: %q is over 40 characters", n.Name, s)
			}
		}
	}
}

func TestBucketFor(t *testing.T) {
	for _, c := range []struct {
		name string
		n    int64
		want string
	}{
		{"stock.favorites", 0, "0"}, {"stock.favorites", 9, "1-9"}, {"stock.favorites", 50, "50+"},
		{"stock.recents", 15, "15+"}, {"stock.backpack", 100, "100+"},
		{"stock.backpack_tabs", 1, "1"}, {"stock.backpack_tabs", 2, "2"}, {"stock.backpack_tabs", 4, "3-4"},
		{"stock.upload_presets", 1, "1"}, {"stock.arbit_presets", 12, "10+"},
		{"stock.alerts_stores", 0, "0"}, {"stock.alerts_stores", 1, "1"}, {"stock.alerts_stores", 3, "2-4"},
	} {
		got, ok := BucketFor(c.name, c.n)
		if !ok || got != c.want {
			t.Errorf("BucketFor(%s, %d) = %q, %v, want %q", c.name, c.n, got, ok, c.want)
		}
	}
	if _, ok := BucketFor("stock.rows", 3); ok {
		t.Error("stock.rows has no buckets")
	}
}

// Every label a bucketed name can produce is in its enum, and Check takes it.
func TestStockBucketsMatchTheirEnums(t *testing.T) {
	for name := range stockEdges {
		entry, ok := Lookup(name)
		if !ok || entry.Values != ValueBucket {
			t.Fatalf("%s has edges and no bucket entry", name)
		}
		for n := range int64(200) {
			label, _ := BucketFor(name, n)
			if !slices.Contains(entry.Enum, label) {
				t.Errorf("%s: %d buckets to %q, which its enum lacks", name, n, label)
			}
		}
	}
}

func TestStockScopesAndValuesCheck(t *testing.T) {
	alerts, _ := Lookup("stock.alerts")
	if _, _, ok := alerts.Check("magic", "retail", Validators{}); !ok {
		t.Error("magic retail alerts are refused")
	}
	if _, _, ok := alerts.Check("test-game", "retail", Validators{}); ok {
		t.Error("an unknown game is stored")
	}
	if _, _, ok := alerts.Check("", "retail", Validators{}); ok {
		t.Error("a scoped name is stored with no scope")
	}
	pref, _ := Lookup("stock.pref")
	if _, _, ok := pref.Check("", "theme", Validators{}); !ok {
		t.Error("the theme key is refused")
	}
	if _, _, ok := pref.Check("", "anything_else", Validators{}); ok {
		t.Error("a key outside the list is stored")
	}
}
