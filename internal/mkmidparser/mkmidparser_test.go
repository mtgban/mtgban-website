package mkmidparser

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

func TestParserFollowsTheShelves(t *testing.T) {
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

func TestParserIsPublishedWithoutALock(t *testing.T) {
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
