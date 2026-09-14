package sessionstore

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"

	"github.com/mtgban/mtgban-website/internal/docparse"
)

// fakeHost is a minimal, in-memory stand-in for whatever a real deployment
// uses to serve its scrapers - Sellers/Vendors backed by a plain slice
// instead of an atomic snapshot, Install/Drop mutating it directly. It lets
// Registry be tested without a host's scraper-loading machinery at all.
type fakeHost struct {
	mu            sync.Mutex
	sellers       []mtgban.Seller
	vendors       []mtgban.Vendor
	configured    []string
	notifications []string
}

func (f *fakeHost) hooks() Hooks {
	return Hooks{
		Sellers: func() []mtgban.Seller {
			f.mu.Lock()
			defer f.mu.Unlock()
			return slices.Clone(f.sellers)
		},
		Vendors: func() []mtgban.Vendor {
			f.mu.Lock()
			defer f.mu.Unlock()
			return slices.Clone(f.vendors)
		},
		IsConfigured: func(shorthand string) bool {
			f.mu.Lock()
			defer f.mu.Unlock()
			return slices.ContainsFunc(f.configured, func(c string) bool {
				return strings.EqualFold(c, shorthand)
			})
		},
		Install: func(kind string, scraper mtgban.Scraper) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			if kind == Retail {
				f.sellers = append(f.sellers, scraper.(mtgban.Seller))
			} else {
				f.vendors = append(f.vendors, scraper.(mtgban.Vendor))
			}
			return nil
		},
		Drop: func(kind, shorthand string) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if kind == Retail {
				f.sellers = slices.DeleteFunc(f.sellers, func(s mtgban.Seller) bool {
					return s.Info().Shorthand == shorthand
				})
			} else {
				f.vendors = slices.DeleteFunc(f.vendors, func(v mtgban.Vendor) bool {
					return v.Info().Shorthand == shorthand
				})
			}
		},
		Notify: func(kind, message string) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.notifications = append(f.notifications, kind+": "+message)
		},
	}
}

func newRegistry() (*Registry, *fakeHost) {
	host := &fakeHost{}
	return New(host.hooks()), host
}

func priced(cardID string, price float64) docparse.Entry {
	return docparse.Entry{CardID: cardID, OriginalPrice: price}
}

// A store lists what a store can list: a priced, matched row. The rest is
// left out and counted, so the caller is told what did not make it. None of
// these ids are real cards, so they never resolve as sealed - which is
// exactly what lets this test run without a datastore loaded.
func TestFromEntriesKeepsWhatAStoreCanList(t *testing.T) {
	entries := []docparse.Entry{
		{CardID: "uuid-a", OriginalPrice: 2.5, OriginalCondition: "SP", Quantity: 3, HasQuantity: true},
		{CardID: "uuid-a", OriginalPrice: 2.5, OriginalCondition: "SP", Quantity: 1, HasQuantity: true},
		{CardID: "uuid-b", OriginalPrice: 10},
		{CardID: "uuid-c", OriginalPrice: 0, Quantity: 4, HasQuantity: true},
		{CardID: "uuid-d", OriginalPrice: 1, MismatchError: errors.New("no match")},
		{CardID: "", OriginalPrice: 1},
		{CardID: "uuid-e", OriginalPrice: 99, Unpacked: true},
		{CardID: "uuid-f", OriginalPrice: 3, OriginalCondition: "MINT"},
	}

	scraper, report, err := FromEntries(Retail, mtgban.ScraperInfo{Shorthand: "ZZS"}, entries)
	if err != nil {
		t.Fatalf("building the store: %s", err)
	}
	if report.Entries != 3 || report.Unpriced != 1 || report.OtherSide != 0 || report.UnknownGrade != 1 {
		t.Errorf("report = %+v, want 3 listed, 1 unpriced and 1 of unknown grade", report)
	}
	if !strings.Contains(report.String(), "1 with an unknown condition left out") {
		t.Errorf("the report reads %q", report)
	}

	inv := scraper.(mtgban.Seller).Inventory()
	if len(inv) != 2 {
		t.Fatalf("the inventory holds %d cards, want uuid-a and uuid-b", len(inv))
	}
	if len(inv["uuid-a"]) != 1 || inv["uuid-a"][0].Quantity != 4 || inv["uuid-a"][0].Conditions != "SP" {
		t.Errorf("uuid-a = %+v, want one SP line holding both rows", inv["uuid-a"])
	}
	if len(inv["uuid-b"]) != 1 || inv["uuid-b"][0].Quantity != 1 || inv["uuid-b"][0].Conditions != "NM" {
		t.Errorf("uuid-b = %+v, want one NM line of one copy", inv["uuid-b"])
	}
	if scraper.Info().InventoryTimestamp == nil {
		t.Error("the inventory carries no timestamp")
	}

	scraper, report, err = FromEntries(Buylist, mtgban.ScraperInfo{Shorthand: "ZZV"}, entries)
	if err != nil {
		t.Fatalf("building the buylist: %s", err)
	}
	bl := scraper.(mtgban.Vendor).Buylist()
	if len(bl) != 2 || bl["uuid-b"][0].BuyPrice != 10 {
		t.Errorf("the buylist holds %+v, want the same two cards bought", bl)
	}
	if scraper.Info().BuylistTimestamp == nil {
		t.Error("the buylist carries no timestamp")
	}
}

func TestFromEntriesRejectsUnknownKind(t *testing.T) {
	_, _, err := FromEntries("sealed", mtgban.ScraperInfo{Shorthand: "ZZS"}, nil)
	if err == nil {
		t.Error("an unknown kind was accepted")
	}
}

// A published store installs through the host's own hooks and the registry
// remembers it.
func TestRegistryPublishInstallsAndTracks(t *testing.T) {
	reg, host := newRegistry()

	report, err := reg.Publish(Retail, mtgban.ScraperInfo{Name: "Session Store", Shorthand: "ZZS"},
		[]docparse.Entry{priced("uuid-a", 1), priced("uuid-b", 2)})
	if err != nil {
		t.Fatalf("publishing: %s", err)
	}
	if report.Entries != 2 {
		t.Errorf("report = %+v, want 2 listed", report)
	}
	if len(host.sellers) != 1 || host.sellers[0].Info().Shorthand != "ZZS" {
		t.Fatalf("the host serves %+v, want one seller named ZZS", host.sellers)
	}
	if !reg.Is(Retail, "ZZS") {
		t.Error("ZZS is not registered as a session store")
	}
	if reg.Is(Buylist, "ZZS") {
		t.Error("the buylist side reads as registered too")
	}
}

// The form the caller hands over is checked before anything reaches the
// host: an empty name or shorthand, an unsafe shorthand, and a list with
// nothing to show are all refused without installing anything.
func TestRegistryPublishValidates(t *testing.T) {
	rows := []docparse.Entry{priced("uuid-a", 1)}

	for _, tt := range []struct {
		desc    string
		info    mtgban.ScraperInfo
		entries []docparse.Entry
	}{
		{"no name", mtgban.ScraperInfo{Shorthand: "ZZS"}, rows},
		{"no shorthand", mtgban.ScraperInfo{Name: "Session"}, rows},
		{"a shorthand a cookie would split", mtgban.ScraperInfo{Name: "Session", Shorthand: "A|B"}, rows},
		{"a shorthand with a space", mtgban.ScraperInfo{Name: "Session", Shorthand: "A B"}, rows},
		{"nothing to list", mtgban.ScraperInfo{Name: "Session", Shorthand: "ZZS"}, []docparse.Entry{{CardID: "uuid-a"}}},
	} {
		reg, host := newRegistry()
		_, err := reg.Publish(Retail, tt.info, tt.entries)
		if err == nil {
			t.Errorf("%s: published", tt.desc)
		}
		if len(host.sellers) != 0 {
			t.Errorf("%s: the host serves %+v after a refusal", tt.desc, host.sellers)
		}
	}
}

// A session store never shadows a real one: neither a shorthand the host's
// config claims, loaded or not, nor one already serving under a spelling
// that only differs by case.
func TestRegistryPublishRefusesARealStore(t *testing.T) {
	reg, host := newRegistry()
	host.configured = []string{"CK"}
	host.sellers = append(host.sellers, mtgban.NewSellerFromInventory(
		mtgban.InventoryRecord{"uuid-x": {{Price: 1}}}, mtgban.ScraperInfo{Shorthand: "ZZREAL"}))
	rows := []docparse.Entry{priced("uuid-a", 1)}

	for _, shorthand := range []string{"CK", "ck", "ZZREAL", "zzreal"} {
		_, err := reg.Publish(Retail, mtgban.ScraperInfo{Name: "Session", Shorthand: shorthand}, rows)
		if err == nil {
			t.Errorf("%s published over a real store", shorthand)
		}
		if reg.Is(Retail, shorthand) {
			t.Errorf("%s registered as a session store", shorthand)
		}
	}
	if len(host.sellers) != 1 || len(host.sellers[0].Inventory()) != 1 {
		t.Errorf("the real seller's inventory changed: %+v", host.sellers)
	}
}

// Publishing again under the same shorthand, in any case, replaces what is
// there rather than sitting beside it - and the two sides of a shorthand are
// independent stores.
func TestRegistryPublishReplacesItsOwnStore(t *testing.T) {
	reg, host := newRegistry()
	rows3 := []docparse.Entry{priced("uuid-a", 1), priced("uuid-b", 1), priced("uuid-c", 1)}
	rows1 := []docparse.Entry{priced("uuid-a", 1)}

	if _, err := reg.Publish(Retail, mtgban.ScraperInfo{Name: "Session", Shorthand: "ZZS"}, rows3); err != nil {
		t.Fatalf("publishing: %s", err)
	}
	if _, err := reg.Publish(Retail, mtgban.ScraperInfo{Name: "Session", Shorthand: "zzs"}, rows1); err != nil {
		t.Fatalf("publishing under another case: %s", err)
	}
	if len(host.sellers) != 1 || host.sellers[0].Info().Shorthand != "zzs" {
		t.Errorf("the host serves %+v, want only one seller spelled zzs", host.sellers)
	}
	// Is is case-insensitive, so both spellings agree - the fact worth
	// asserting is that there is exactly one seller, not two
	if !reg.Is(Retail, "ZZS") || !reg.Is(Retail, "zzs") {
		t.Error("the registry does not recognize the store under either spelling")
	}

	if _, err := reg.Publish(Buylist, mtgban.ScraperInfo{Name: "Session", Shorthand: "zzs"}, rows1); err != nil {
		t.Fatalf("publishing the buylist side: %s", err)
	}
	if len(host.sellers) != 1 || len(host.vendors) != 1 {
		t.Errorf("the sides are not independent: sellers=%+v vendors=%+v", host.sellers, host.vendors)
	}
}

// Remove takes a session store off the host and notifies; a store the host's
// config has since claimed, or one already removed, is refused.
func TestRegistryRemove(t *testing.T) {
	reg, host := newRegistry()
	if _, err := reg.Publish(Retail, mtgban.ScraperInfo{Name: "Session", Shorthand: "ZZS"},
		[]docparse.Entry{priced("uuid-a", 1)}); err != nil {
		t.Fatalf("publishing: %s", err)
	}

	if err := reg.Remove(Retail, "ZZS"); err != nil {
		t.Fatalf("removing: %s", err)
	}
	if len(host.sellers) != 0 {
		t.Errorf("the host still serves %+v after removal", host.sellers)
	}
	if reg.Is(Retail, "ZZS") {
		t.Error("ZZS is still registered after being removed")
	}
	if len(host.notifications) != 1 {
		t.Errorf("got %d notifications, want one", len(host.notifications))
	}

	if err := reg.Remove(Retail, "ZZS"); err == nil {
		t.Error("removing ZZS twice said ok")
	}
}

// Is and Remove are case-insensitive against the registry's own bookkeeping,
// the same as the shadow check Publish runs: a caller who does not know or
// does not spell a store's shorthand exactly as it was last published still
// finds it, and can still take it down.
func TestRegistryIsAndRemoveIgnoreCase(t *testing.T) {
	reg, host := newRegistry()
	if _, err := reg.Publish(Retail, mtgban.ScraperInfo{Name: "Session", Shorthand: "ZZS"},
		[]docparse.Entry{priced("uuid-a", 1)}); err != nil {
		t.Fatalf("publishing: %s", err)
	}

	for _, spelling := range []string{"ZZS", "zzs", "Zzs"} {
		if !reg.Is(Retail, spelling) {
			t.Errorf("Is(%q) = false, want true", spelling)
		}
	}

	if err := reg.Remove(Retail, "zzs"); err != nil {
		t.Fatalf("removing under a different case: %s", err)
	}
	if len(host.sellers) != 0 {
		t.Errorf("the host still serves %+v after a differently-cased removal", host.sellers)
	}
	if reg.Is(Retail, "ZZS") {
		t.Error("ZZS is still registered after being removed under another case")
	}
}

// A shorthand the host's config claims after the store was published is a
// real store from then on: the registry may still remember it, but Remove
// may not touch what now serves under it.
func TestRegistryRemoveYieldsToTheConfig(t *testing.T) {
	reg, host := newRegistry()
	if _, err := reg.Publish(Retail, mtgban.ScraperInfo{Name: "Session", Shorthand: "ZZS"},
		[]docparse.Entry{priced("uuid-a", 1)}); err != nil {
		t.Fatalf("publishing: %s", err)
	}

	host.configured = []string{"ZZS"}

	if err := reg.Remove(Retail, "ZZS"); err == nil {
		t.Error("removed a store the config now claims")
	}
	if len(host.sellers) != 1 {
		t.Error("the claimed store stopped serving")
	}
}
