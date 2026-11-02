package tcgskuparser

import (
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// shelf is one TCGplayer seller, keyed by uuid with each offer's SKU and
// condition - the shape the scrapers publish. Entries are {uuid, sku,
// condition}.
func shelf(shorthand string, entries [][3]string) mtgban.Seller {
	inv := mtgban.InventoryRecord{}
	for _, entry := range entries {
		inv.Add(entry[0], &mtgban.InventoryEntry{InstanceID: entry[1], Conditions: mtgban.Condition(entry[2]), Price: 1})
	}
	return mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{
		Name: shorthand, Shorthand: shorthand, MetadataOnly: true,
	})
}

func TestResolve(t *testing.T) {
	singles := shelf("TCGPlayer", [][3]string{
		{"uuid-aaa", "100", "NM"},
		{"uuid-aaa", "101", "SP"},
		// An offer without a SKU indexes nothing.
		{"uuid-bbb", "", "NM"},
		{"uuid-ccc", "300", "MP"},
	})
	sealed := shelf("TCGSealed", [][3]string{
		{"uuid-box", "200", "NM"},
		// Priced by the singles seller too, which is read first.
		{"uuid-box", "100", "NM"},
	})
	// Another seller's SKUs are not TCGplayer's, whatever they look like.
	other := shelf("CK", [][3]string{{"uuid-other", "400", "NM"}})
	idx := Build([]mtgban.Seller{other, sealed, singles})

	for _, tc := range []struct {
		sku  string
		uuid string
		cond mtgban.Condition
	}{
		{"100", "uuid-aaa", "NM"},
		{"101", "uuid-aaa", "SP"},
		{"200", "uuid-box", "NM"},
		{"300", "uuid-ccc", "MP"},
		{"400", "", ""},
		{"999", "", ""},
		{"", "", ""},
	} {
		if got := idx.Resolve(tc.sku); got != tc.uuid {
			t.Errorf("Resolve(%q) = %q, want %q", tc.sku, got, tc.uuid)
		}
		if got := idx.Condition(tc.sku); got != tc.cond {
			t.Errorf("Condition(%q) = %q, want %q", tc.sku, got, tc.cond)
		}
	}
	if len(idx) != 4 {
		t.Errorf("indexed %d SKUs, want 4", len(idx))
	}
}

func TestSellersAndTheirAbsence(t *testing.T) {
	// The shorthands are matched the way the site looks stores up: without
	// regard to case.
	singles := shelf("tcgplayer", [][3]string{{"uuid-aaa", "100", "NM"}})
	sealed := shelf("TCGSEALED", [][3]string{{"uuid-box", "200", "NM"}})
	other := shelf("CK", nil)

	if got := Sellers([]mtgban.Seller{other, sealed, singles}); !slices.Equal(got, []mtgban.Seller{singles, sealed}) {
		t.Errorf("Sellers picked %v", got)
	}

	// Either seller may be missing, and with both missing there is no
	// index, which resolves nothing all the same.
	if got := Sellers([]mtgban.Seller{other, sealed}); !slices.Equal(got, []mtgban.Seller{sealed}) {
		t.Errorf("Sellers picked %v without the singles", got)
	}
	if got := Build([]mtgban.Seller{sealed}).Resolve("200"); got != "uuid-box" {
		t.Errorf("sealed alone: Resolve(200) = %q", got)
	}
	if idx := Build([]mtgban.Seller{other}); idx != nil || idx.Resolve("100") != "" || idx.Condition("100") != "" {
		t.Errorf("no TCGplayer seller: index %v", idx)
	}
	if idx := Build(nil); idx != nil {
		t.Errorf("no sellers: index %v", idx)
	}
}
