package mkmidparser

import (
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
