package csiidparser

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// shelves stands in for the site's sellers snapshot: a pointer that can be
// pointed at a new list, which is what a scrapers refresh does.
type shelves struct {
	ptr atomic.Pointer[[]mtgban.Seller]
}

func newParser() (*Parser, *shelves) {
	var s shelves
	return &Parser{Sellers: s.ptr.Load}, &s
}

// publish installs a new snapshot and answers with the pointer naming it.
func (s *shelves) publish(sellers ...mtgban.Seller) *[]mtgban.Seller {
	list := sellers
	s.ptr.Store(&list)
	return &list
}

// shelf is one Cool Stuff Inc shelf, keyed by uuid with the entries the
// scrapers publish under it.
func shelf(shorthand string, byUUID map[string][]*mtgban.InventoryEntry) mtgban.Seller {
	inv := mtgban.InventoryRecord{}
	for uuid, entries := range byUUID {
		for _, entry := range entries {
			entry.Price = 1
			inv.Add(uuid, entry)
		}
	}
	return mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{
		Name: shorthand, Shorthand: shorthand, MetadataOnly: true,
	})
}

// priced is the shape the singles scrapers publish: the product id in the
// field meant for it, and the link beside it.
func priced(pid string) *mtgban.InventoryEntry {
	return &mtgban.InventoryEntry{
		OriginalID: pid,
		URL:        "https://www.coolstuffinc.com/p/" + pid,
	}
}

// linkedOnly is the shape the sealed shelf publishes for Magic: the listing
// page it was read from names the product, and nothing fills OriginalID.
func linkedOnly(link string) *mtgban.InventoryEntry {
	return &mtgban.InventoryEntry{URL: link}
}

func TestResolve(t *testing.T) {
	p, live := newParser()
	live.publish(
		shelf("CSI", map[string][]*mtgban.InventoryEntry{
			"uuid-aaa": {priced("1435")},
			"uuid-bbb": {priced("300001")},
			// A page carries an offer row per condition, all of them the
			// one product: an agreement, not a collision.
			"uuid-ccc": {priced("300002"), priced("300002")},
			"uuid-ddd": {priced("400001")},
			"uuid-eee": {priced("400002")},
		}),
		shelf("CSIUnique", map[string][]*mtgban.InventoryEntry{
			// The market's other half, which is why both shorthands are
			// read rather than the "CSI" the scraper itself reports.
			"uuid-fff": {priced("600001")},
			// Two printings the storefront shelves under one product: the
			// id names neither.
			"uuid-ggg": {priced("300001")},
			// The same printing's other finish. The scraper reads the
			// finish off the offer row and the id off the page, so both
			// answer to the one id - and they are the one card.
			"uuid-ddd_f": {priced("400001")},
			// Etched is filed under its own suffix and is the same card
			// for the same reason.
			"uuid-eee_e": {priced("400002")},
		}),
		shelf("CSISealed", map[string][]*mtgban.InventoryEntry{
			// The Magic sealed path stamps the link and nothing else, so
			// the id has to be read back out of it or this resolves to
			// nothing - and Magic is the only game the bot reads links for.
			"uuid-box": {linkedOnly("https://coolstuffinc.com/p/500001")},
			// The same page with an affiliate tag appended, which is what
			// the scraper writes when it is configured with one.
			"uuid-bundle": {linkedOnly("https://coolstuffinc.com/p/500002?utm_referrer=mtgban")},
			// The other games' sealed path fills both fields.
			"uuid-trove": {priced("500003")},
		}),
	)

	for _, tc := range []struct {
		name  string
		csiID string
		want  string
	}{
		{"a product one printing answers to", "1435", "uuid-aaa"},
		{"a product two printings answer to", "300001", ""},
		{"one page's several offer rows", "300002", "uuid-ccc"},
		{"a product's two finishes", "400001", "uuid-ddd"},
		{"a product's etched twin", "400002", "uuid-eee"},
		{"the market's other half", "600001", "uuid-fff"},
		{"a sealed product named by its link alone", "500001", "uuid-box"},
		{"a sealed link carrying an affiliate tag", "500002", "uuid-bundle"},
		{"a sealed product named by both", "500003", "uuid-trove"},
		{"unknown product", "999999", ""},
		{"empty id", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.Resolve(tc.csiID); got != tc.want {
				t.Errorf("Resolve(%q) = %q, want %q", tc.csiID, got, tc.want)
			}
		})
	}
}

// The id is read out of the link only where the field meant for it is empty,
// and the link is written in more than one shape.
func TestProductIDFromURL(t *testing.T) {
	for _, tc := range []struct {
		name, link, want string
	}{
		{"the singles spelling", "https://www.coolstuffinc.com/p/1435", "1435"},
		{"the sealed spelling", "https://coolstuffinc.com/p/500001", "500001"},
		{"an affiliate tag", "https://www.coolstuffinc.com/p/1435?utm_referrer=mtgban", "1435"},
		{"a trailing segment", "https://coolstuffinc.com/p/1435/goblin-king", "1435"},
		{"a non-numeric id", "https://coolstuffinc.com/p/abc123", "abc123"},
		{"some other page", "https://www.coolstuffinc.com/mtg/goblin-king", ""},
		{"nothing at all", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := productIDFromURL(tc.link); got != tc.want {
				t.Errorf("productIDFromURL(%q) = %q, want %q", tc.link, got, tc.want)
			}
		})
	}
}

func TestResolveWithNothingPublished(t *testing.T) {
	// A deployment of a game this storefront does not sell has no such
	// seller, and a Parser nobody wired has no source at all. Both answer
	// nothing rather than failing.
	p, _ := newParser()
	if got := p.Resolve("1435"); got != "" {
		t.Errorf("with no sellers = %q, want empty string", got)
	}
	if got := (&Parser{}).Resolve("1435"); got != "" {
		t.Errorf("with no source = %q, want empty string", got)
	}
}

func TestIndexFollowsTheShelves(t *testing.T) {
	// The inventories are replaced without the datastore moving, so an index
	// keyed on a datastore stamp would go on answering from the previous
	// shelves - and would do it silently.
	p, live := newParser()

	live.publish(shelf("CSI", map[string][]*mtgban.InventoryEntry{
		"uuid-before": {priced("700001")},
	}))
	if got := p.Resolve("700001"); got != "uuid-before" {
		t.Fatalf("before the refresh = %q, want uuid-before", got)
	}

	live.publish(shelf("CSI", map[string][]*mtgban.InventoryEntry{
		"uuid-after": {priced("700001")},
	}))
	if got := p.Resolve("700001"); got != "uuid-after" {
		t.Errorf("after the refresh = %q, want uuid-after", got)
	}
}

// A seller that is not one of these shelves is republished constantly, and
// rebuilding the index for one of those is a walk spent arriving at the same
// map.
func TestIndexIsKeptAcrossAnUnrelatedRefresh(t *testing.T) {
	p, live := newParser()

	csi := shelf("CSI", map[string][]*mtgban.InventoryEntry{
		"uuid-aaa": {priced("800001")},
	})
	other := shelf("TCGLow", map[string][]*mtgban.InventoryEntry{
		"uuid-zzz": {priced("999999")},
	})

	live.publish(csi, other)
	if got := p.Resolve("800001"); got != "uuid-aaa" {
		t.Fatalf("before the refresh = %q, want uuid-aaa", got)
	}
	was := p.cached.Load()

	// The unrelated seller refreshes: a new snapshot, the same shelves
	// inside it.
	live.publish(csi, shelf("TCGLow", map[string][]*mtgban.InventoryEntry{
		"uuid-zzz": {priced("999998")},
	}))
	if got := p.Resolve("800001"); got != "uuid-aaa" {
		t.Errorf("after the refresh = %q, want uuid-aaa", got)
	}

	now := p.cached.Load()
	if was == now {
		t.Error("the index was not re-keyed to the snapshot in hand")
	}
	// Re-keyed, not rebuilt: the same map carried across.
	if !mapsAreTheSame(was.ids, now.ids) {
		t.Error("the index was rebuilt for a seller it does not read")
	}
}

// mapsAreTheSame reports whether two references name the one map, which is
// what says a walk was skipped rather than repeated to the same answer.
func mapsAreTheSame(was, now map[string]string) bool {
	const probe = "\x00probe"
	was[probe] = "yes"
	defer delete(was, probe)
	return now[probe] == "yes"
}

// The index is read by handlers that run concurrently, and a refresh can land
// in the middle of one. Run with -race.
func TestConcurrentReadsAcrossARefresh(t *testing.T) {
	p, live := newParser()
	live.publish(shelf("CSI", map[string][]*mtgban.InventoryEntry{
		"uuid-aaa": {priced("900001")},
	}))

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 50 {
				p.Resolve("900001")
			}
		})
	}
	for range 4 {
		wg.Go(func() {
			live.publish(shelf("CSI", map[string][]*mtgban.InventoryEntry{
				"uuid-aaa": {priced("900001")},
			}))
		})
	}
	wg.Wait()
}
