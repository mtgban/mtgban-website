package mkmidparser

import (
	"fmt"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

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

// elsewhere is a seller this package does not read, which publishes a
// product id of its own all the same.
func elsewhere(shorthand string) mtgban.Seller {
	inv := mtgban.InventoryRecord{}
	inv.Add("uuid-other", &mtgban.InventoryEntry{OriginalID: "265854", Price: 1})
	return mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{
		Name: shorthand, Shorthand: shorthand,
	})
}

func TestResolve(t *testing.T) {
	ids := Build([]mtgban.Seller{
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
	})

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
			if got := ids.Resolve(tc.mkmID); got != tc.want {
				t.Errorf("Resolve(%q) = %q, want %q", tc.mkmID, got, tc.want)
			}
		})
	}
}

func TestBuildWithNoShelves(t *testing.T) {
	// A deployment of a game Cardmarket does not sell has no such seller,
	// and before the first publish there are no sellers at all. Both
	// answer nothing rather than failing, and so does an Index nobody
	// built.
	if got := Build(nil); got != nil {
		t.Errorf("Build(nil) = %v, want nil", got)
	}
	if got := Build([]mtgban.Seller{elsewhere("CK")}); got != nil {
		t.Errorf("Build with no shelf = %v, want nil", got)
	}
	if got := Index(nil).Resolve("265854"); got != "" {
		t.Errorf("a nil Index resolved %q, want empty string", got)
	}
}

func TestBuildReadsOnlyTheShelves(t *testing.T) {
	// Other sellers carry an OriginalID too, naming whatever their store
	// keys a listing by. Only the Cardmarket shelves say which product a
	// Cardmarket id is.
	ids := Build([]mtgban.Seller{
		elsewhere("CK"),
		shelf("MKMTrend", map[string]string{"uuid-mkm": "265854"}),
	})
	if got := ids.Resolve("265854"); got != "uuid-mkm" {
		t.Errorf("Resolve = %q, want uuid-mkm", got)
	}
}

// bigShelf is a shelf the size of one Magic singles index, for the cost of
// a build. The site pays it on every prices publish, so the number matters.
func bigShelf(shorthand string, cards int) mtgban.Seller {
	byUUID := make(map[string]string, cards)
	for i := range cards {
		byUUID[fmt.Sprintf("uuid-%06d", i)] = fmt.Sprintf("%d", 800000+i)
	}
	return shelf(shorthand, byUUID)
}

func BenchmarkBuild(b *testing.B) {
	sellers := []mtgban.Seller{
		bigShelf("MKMTrend", 100000),
		bigShelf("MKMLow", 100000),
		elsewhere("CK"),
	}
	b.ResetTimer()
	for range b.N {
		if Build(sellers).Resolve("800000") != "uuid-000000" {
			b.Fatal("build resolved nothing")
		}
	}
}
