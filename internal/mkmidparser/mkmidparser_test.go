package mkmidparser

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"weak"

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

// shelf is one Cardmarket shelf, keyed by uuid with the product each entry
// priced carried alongside it - the shape the scrapers publish.
func shelf(shorthand string, byUUID map[string]string) mtgban.Seller {
	inv := mtgban.InventoryRecord{}
	for uuid, mkmID := range byUUID {
		inv.Add(uuid, &mtgban.InventoryEntry{OriginalID: mkmID, Price: 1})
	}
	return mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{
		Name: shorthand, Shorthand: shorthand, MetadataOnly: true,
	})
}

func TestResolve(t *testing.T) {
	p, live := newParser()
	live.publish(
		shelf("MKMTrend", map[string]string{
			"uuid-aaa": "265854",
			"uuid-bbb": "300001",
			"uuid-ddd": "400001",
			"uuid-eee": "400002",
		}),
		shelf("MKMLow", map[string]string{
			// The same card priced by the other index: an agreement, not
			// a collision.
			"uuid-aaa": "265854",
			// Two printings Cardmarket shelves under one product: the id
			// names neither.
			"uuid-ccc": "300001",
			// The same printing's other finish. Cardmarket sells a
			// printing's finishes as one product, which is half the Magic
			// shelves, and the upload's foil column says which is meant.
			"uuid-ddd_f": "400001",
			// Etched is filed under its own suffix too, and is the same
			// card for the same reason.
			"uuid-eee_e": "400002",
		}),
		shelf("MKMSealed", map[string]string{
			// Published by the sealed scraper rather than either singles
			// index, which is why all three are read.
			"uuid-box": "500001",
		}),
	)

	for _, tc := range []struct {
		name  string
		mkmID string
		want  string
	}{
		{"a product one printing answers to", "265854", "uuid-aaa"},
		{"a product two printings answer to", "300001", ""},
		{"a product's two finishes", "400001", "uuid-ddd"},
		{"a product's etched twin", "400002", "uuid-eee"},
		{"a sealed product", "500001", "uuid-box"},
		{"unknown product", "999999", ""},
		{"empty id", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.Resolve(tc.mkmID); got != tc.want {
				t.Errorf("Resolve(%q) = %q, want %q", tc.mkmID, got, tc.want)
			}
		})
	}
}

func TestResolveWithNothingPublished(t *testing.T) {
	// A deployment of a game Cardmarket does not sell has no such seller,
	// and a Parser nobody wired has no source at all. Both answer nothing
	// rather than failing.
	p, _ := newParser()
	if got := p.Resolve("265854"); got != "" {
		t.Errorf("with no sellers = %q, want empty string", got)
	}
	if got := (&Parser{}).Resolve("265854"); got != "" {
		t.Errorf("with no source = %q, want empty string", got)
	}
}

func TestIndexFollowsTheShelves(t *testing.T) {
	// The inventories are replaced without the datastore moving, so an
	// index keyed on a datastore stamp would go on answering from the
	// previous shelves - and would do it silently.
	p, live := newParser()

	live.publish(shelf("MKMTrend", map[string]string{"uuid-before": "700001"}))
	if got := p.Resolve("700001"); got != "uuid-before" {
		t.Fatalf("before the refresh = %q, want uuid-before", got)
	}

	live.publish(shelf("MKMTrend", map[string]string{"uuid-after": "700001"}))
	if got := p.Resolve("700001"); got != "uuid-after" {
		t.Errorf("after the refresh = %q, want uuid-after", got)
	}
}

func TestIndexIsPublishedWithoutALock(t *testing.T) {
	// Readers resolving while the inventories are replaced under them.
	// Every answer has to be one of the two snapshots' answers: a reader
	// may see either, having asked while the ground was moving, but never
	// a torn index. Run with -race, which is the point of it.
	p, live := newParser()

	before := shelf("MKMTrend", map[string]string{"uuid-before": "900001"})
	after := shelf("MKMTrend", map[string]string{"uuid-after": "900001"})
	live.publish(before)

	stop := make(chan struct{})
	var refresher sync.WaitGroup
	refresher.Add(1)
	go func() {
		defer refresher.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				live.publish(after)
			} else {
				live.publish(before)
			}
		}
	}()

	var readers sync.WaitGroup
	for reader := 0; reader < 8; reader++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for i := 0; i < 2000; i++ {
				switch got := p.Resolve("900001"); got {
				case "uuid-before", "uuid-after":
				default:
					t.Errorf("resolved to %q, which is neither snapshot", got)
					return
				}
			}
		}()
	}

	readers.Wait()
	close(stop)
	refresher.Wait()
}

func TestTheWalkHappensOnce(t *testing.T) {
	// What the index changed. The walk it replaced ran per uploaded row,
	// so a list of N rows read the shelves N times; this reads them once
	// and then answers from a map. Logged rather than asserted on a
	// threshold, which would fail on a slow machine and not on a
	// regression - the ratio is the claim.
	const cards = 8000
	const rows = 200

	byUUID := make(map[string]string, cards)
	for i := 0; i < cards; i++ {
		byUUID[fmt.Sprintf("uuid-%06d", i)] = fmt.Sprintf("%d", 800000+i)
	}

	p, live := newParser()
	live.publish(shelf("MKMTrend", byUUID))

	first := time.Now()
	if got := p.Resolve("800000"); got != "uuid-000000" {
		t.Fatalf("first lookup = %q, want uuid-000000", got)
	}
	walk := time.Since(first)

	rest := time.Now()
	for i := 0; i < rows; i++ {
		id := fmt.Sprintf("%d", 800000+i)
		if got := p.Resolve(id); got != fmt.Sprintf("uuid-%06d", i) {
			t.Fatalf("lookup %s = %q", id, got)
		}
	}
	perRow := time.Since(rest) / rows

	t.Logf("%d cards: one walk %v, then %v a row - the walk it replaced ran "+
		"once a row, so %d rows cost about %v", cards, walk, perRow, rows,
		time.Duration(rows)*walk)

	if perRow > walk/10 {
		t.Errorf("a row still costs %v against a %v walk: the index is not "+
			"being reused", perRow, walk)
	}
}

func TestASupersededBuildIsNotPublished(t *testing.T) {
	// A build takes milliseconds, which is long enough for a refresh to
	// land in the middle of one. The build that started earlier must not
	// install itself over the newer index already published.
	p, live := newParser()

	older := live.publish(shelf("MKMTrend", map[string]string{"uuid-before": "900001"}))
	if got := p.Resolve("900001"); got != "uuid-before" {
		t.Fatalf("before the refresh = %q, want uuid-before", got)
	}

	newer := live.publish(shelf("MKMTrend", map[string]string{"uuid-after": "900001"}))
	if got := p.Resolve("900001"); got != "uuid-after" {
		t.Fatalf("after the refresh = %q, want uuid-after", got)
	}

	// The first upload finishes its walk and tries to install what it
	// built, which describes inventories no longer live.
	p.publish(older, index{ids: map[string]string{"900001": "uuid-before"}})

	if p.cached.Load().builtFrom.Value() != newer {
		t.Error("a superseded build installed itself over the newer index")
	}
	if got := p.Resolve("900001"); got != "uuid-after" {
		t.Errorf("resolved to %q after a late publish, want uuid-after", got)
	}
}

func TestASupersededIndexIsNeverServed(t *testing.T) {
	// The read is what makes the above safe rather than merely tidy: an
	// index keyed to shelves no longer live is never served, however it
	// came to be there.
	p, live := newParser()

	older := []mtgban.Seller{shelf("MKMTrend", map[string]string{"uuid-before": "900001"})}
	live.publish(shelf("MKMTrend", map[string]string{"uuid-after": "900001"}))

	p.cached.Store(&built{
		builtFrom: weak.Make(&older),
		shelves:   weakShelves(shelvesOf(older)),
		index:     index{ids: map[string]string{"900001": "uuid-before"}},
	})

	if got := p.Resolve("900001"); got != "uuid-after" {
		t.Errorf("served a superseded index: %q, want uuid-after", got)
	}
}

// elsewhere is a seller this package does not read, for the test about
// what a refresh of one costs.
func elsewhere(shorthand string) mtgban.Seller {
	inv := mtgban.InventoryRecord{}
	inv.Add("uuid-other", &mtgban.InventoryEntry{Price: 1})
	return mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{
		Name: shorthand, Shorthand: shorthand,
	})
}

func TestAnUnrelatedSellerRefreshKeepsTheIndex(t *testing.T) {
	// Sellers are republished whole, so the snapshot moves whenever
	// anything moves - a buylist, a storefront this package does not read.
	// Only the Cardmarket shelves decide what the index says.
	p, live := newParser()

	mkm := shelf("MKMTrend", map[string]string{"uuid-mkm": "900001"})
	live.publish(mkm, elsewhere("CK"))
	if got := p.Resolve("900001"); got != "uuid-mkm" {
		t.Fatalf("first resolve = %q, want uuid-mkm", got)
	}

	// A mark a rebuild would wipe, so "did it rebuild" is answerable
	// without timing anything.
	p.cached.Load().ids["sentinel"] = "kept"

	// Cardkingdom refreshes: a new snapshot, the Cardmarket shelf copied
	// across untouched.
	after := live.publish(mkm, elsewhere("CK"))
	if got := p.Resolve("900001"); got != "uuid-mkm" {
		t.Errorf("after an unrelated refresh = %q, want uuid-mkm", got)
	}
	if p.cached.Load().ids["sentinel"] != "kept" {
		t.Error("an unrelated seller's refresh rebuilt the index")
	}
	if p.cached.Load().builtFrom.Value() != after {
		t.Error("the index was not re-keyed to the snapshot in hand")
	}

	// A Cardmarket shelf moving is the case that must rebuild.
	live.publish(shelf("MKMTrend", map[string]string{"uuid-moved": "900001"}), elsewhere("CK"))
	if got := p.Resolve("900001"); got != "uuid-moved" {
		t.Errorf("after the shelf moved = %q, want uuid-moved", got)
	}
	if p.cached.Load().ids["sentinel"] == "kept" {
		t.Error("a Cardmarket shelf moved and the index was not rebuilt")
	}
}

// freed reports whether seller is collected once replace has run. The
// caller drops its own reference inside replace.
func freed(seller mtgban.Seller, replace func()) bool {
	released := make(chan struct{})
	runtime.AddCleanup(seller.(*mtgban.BaseSeller), func(done chan struct{}) { close(done) }, released)
	replace()

	for range 20 {
		runtime.GC()
		select {
		case <-released:
			return true
		case <-time.After(10 * time.Millisecond):
		}
	}
	return false
}

// A refresh of any seller republishes the whole snapshot. What the index
// keeps to recognise the old one must not keep it alive, or every seller
// replaced since the last upload stays in memory until the next one.
func TestAReplacedSellerIsNotKeptAlive(t *testing.T) {
	p, live := newParser()
	defer runtime.KeepAlive(p)

	mkm := shelf("MKMTrend", map[string]string{"uuid-mkm": "900001"})
	store := elsewhere("CK")
	live.publish(mkm, store)
	got := p.Resolve("900001")
	if got != "uuid-mkm" {
		t.Fatalf("resolve = %q, want uuid-mkm", got)
	}

	// Card Kingdom refreshes, and nothing resolves an id afterwards.
	if !freed(store, func() {
		store = nil
		live.publish(mkm, elsewhere("CK"))
	}) {
		t.Error("the replaced seller is still alive: the index is holding the snapshot it was in")
	}
}

// The same holds for the Cardmarket shelves themselves, which the index
// keeps to tell its own refresh from everybody else's.
func TestAReplacedShelfIsNotKeptAlive(t *testing.T) {
	p, live := newParser()
	defer runtime.KeepAlive(p)

	mkm := shelf("MKMTrend", map[string]string{"uuid-mkm": "900001"})
	store := elsewhere("CK")
	live.publish(mkm, store)
	got := p.Resolve("900001")
	if got != "uuid-mkm" {
		t.Fatalf("resolve = %q, want uuid-mkm", got)
	}

	// Cardmarket refreshes, and nothing resolves an id afterwards.
	if !freed(mkm, func() {
		mkm = nil
		live.publish(shelf("MKMTrend", map[string]string{"uuid-mkm": "900001"}), store)
	}) {
		t.Error("the replaced shelf is still alive: the index is holding it")
	}
}

func TestProductID(t *testing.T) {
	p, live := newParser()
	live.publish(
		shelf("MKMTrend", map[string]string{
			"uuid-aaa":   "265854",
			"uuid-bbb":   "300001",
			"uuid-ccc":   "300001",
			"uuid-ddd":   "400001",
			"uuid-etc_e": "400009",
		}),
		shelf("MKMLow", map[string]string{
			// The index the shelves are read first from wins.
			"uuid-aaa": "999999",
			// A uuid only the other index prices.
			"uuid-low": "600001",
		}),
		shelf("MKMSealed", map[string]string{
			"uuid-box": "500001",
		}),
	)

	for _, tc := range []struct {
		name string
		uuid string
		own  string
		want string
	}{
		{"priced on the shelves", "uuid-aaa", "", "265854"},
		{"the shelves over the datastore", "uuid-aaa", "111111", "265854"},
		{"priced by the second index only", "uuid-low", "", "600001"},
		{"a sealed product", "uuid-box", "", "500001"},
		{"one product priced onto two printings", "uuid-ccc", "", "300001"},
		{"not priced, datastore id unclaimed", "uuid-zzz", "700001", "700001"},
		{"not priced, datastore id is another card's", "uuid-zzz", "265854", ""},
		{"not priced, datastore id names several cards", "uuid-zzz", "300001", ""},
		{"a finish not priced, datastore id is its printing's", "uuid-ddd_f", "400001", "400001"},
		{"a finish not priced, no datastore id", "uuid-ddd_f", "", "400001"},
		{"a finish not priced, datastore id unclaimed", "uuid-ddd_e", "700002", "700002"},
		{"a finish priced as itself", "uuid-etc_e", "", "400009"},
		{"neither priced nor in the datastore", "uuid-zzz", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.ProductID(tc.uuid, tc.own); got != tc.want {
				t.Errorf("ProductID(%q, %q) = %q, want %q", tc.uuid, tc.own, got, tc.want)
			}
		})
	}
}

func TestProductIDWithNothingPublished(t *testing.T) {
	// No Cardmarket shelves at all leaves the datastore as the only answer.
	p, _ := newParser()
	if got := p.ProductID("uuid-aaa", "265854"); got != "265854" {
		t.Errorf("with no sellers = %q, want 265854", got)
	}
	if got := (&Parser{}).ProductID("uuid-aaa", ""); got != "" {
		t.Errorf("with no source = %q, want empty string", got)
	}
}

func TestShelvesAreReadInOrder(t *testing.T) {
	// The snapshot lists sellers in whatever order they were loaded; which
	// index answers first must not follow it.
	p, live := newParser()
	live.publish(
		shelf("MKMLow", map[string]string{"uuid-aaa": "999999"}),
		shelf("MKMTrend", map[string]string{"uuid-aaa": "265854"}),
	)
	if got := p.ProductID("uuid-aaa", ""); got != "265854" {
		t.Errorf("ProductID = %q, want the Trend shelf's 265854", got)
	}
}
