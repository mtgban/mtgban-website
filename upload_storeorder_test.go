package main

import (
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// TestSortStoreOrder lays real tables out by their stores' invoices: Mint
// buylist order 6072 from the printings' own sets and frames, CK sell order
// 160597924 from CK's fields on its buylist entries, and SCG, and ABU before
// its entries carry its fields, as they came.
func TestSortStoreOrder(t *testing.T) {
	skipWithoutDatastore(t)

	mint := []string{
		"091c88e3-0ea6-5d37-b3f7-7fa01e86da5d",   // Selective Memory, Worldwake
		"0b922fe8-0130-5a97-bea1-141f9e6705f4",   // Kiora Bests the Sea God, Theros Beyond Death
		"7bd8dbc4-ca8f-5895-926e-f071b78d3bbd",   // Tortured Existence, The List
		"e6456927-05f5-5682-a76d-f9df6caaedef",   // Archon of Emeria, Zendikar Rising
		"fd36161f-e1c8-5c22-87ef-7b90694c72a7",   // Shalai and Hallar, March of the Machine Commander
		"8387d9f9-cb2c-5485-8b9b-ebe5e86e105b_f", // Lurking Skirge, Urza's Legacy foil
		"157b7cc9-d634-5a18-b749-5c0815355815_f", // Bear's Companion, Khans of Tarkir foil
		"2ecba824-4c05-5cdf-8377-e46e4b9d757e_f", // Cursed Totem, Modern Horizons 2 foil
		"4209e887-b83d-593f-8a1c-381e4c8b8521",   // Wish (Extended Art), Adventures in the Forgotten Realms
	}
	ck := []string{
		"d911812a-7531-5935-a707-0a7240629679_f", // Wine of Blood and Iron, Saviors of Kamigawa foil
		"f4c730c1-39d6-5b43-b623-18f7e5c88a19_f", // Lord Windgrace, oversized
	}
	ckList := mtgban.BuylistRecord{}
	ckList.Add(ck[0], &mtgban.BuylistEntry{Conditions: mtgban.NM, BuyPrice: 1, CustomFields: map[string]string{"CKEdition": "Saviors of Kamigawa", "CKTitle": "Wine of Blood and Iron", "CKFoil": "true"}})
	ckList.Add(ck[1], &mtgban.BuylistEntry{Conditions: mtgban.NM, BuyPrice: 1, CustomFields: map[string]string{"CKEdition": "Commander 2018", "CKTitle": "Lord Windgrace (Oversized Foil)", "CKFoil": "true"}})
	mintList := mtgban.BuylistRecord{}
	for _, id := range mint {
		mintList.Add(id, &mtgban.BuylistEntry{Conditions: mtgban.NM, BuyPrice: 1})
	}
	withPrices(t, nil, []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(ckList, mtgban.ScraperInfo{Shorthand: "CK"}),
		mtgban.NewVendorFromBuylist(mintList, mtgban.ScraperInfo{Shorthand: "MMC"}),
		mtgban.NewVendorFromBuylist(mintList, mtgban.ScraperInfo{Shorthand: "ABUGames"}),
	})

	reversed := func(ids []string) []OptimizedUploadEntry {
		var entries []OptimizedUploadEntry
		for _, id := range slices.Backward(ids) {
			entries = append(entries, OptimizedUploadEntry{CardID: id})
		}
		return entries
	}
	results := map[string][]OptimizedUploadEntry{
		"MMC":      reversed(mint),
		"CK":       reversed(ck),
		"SCG":      reversed(ck),
		"ABUGames": reversed(mint),
	}
	sortStoreOrder(backend(), currentPrices(), results)

	scg := slices.Clone(ck)
	slices.Reverse(scg)
	abu := slices.Clone(mint)
	slices.Reverse(abu)
	for store, want := range map[string][]string{"MMC": mint, "CK": ck, "SCG": scg, "ABUGames": abu} {
		var got []string
		for _, entry := range results[store] {
			got = append(got, entry.CardID)
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s laid out as %q, want %q", store, got, want)
		}
	}
}
