package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// finishBackend files printings the way every loader does: each finish a
// card of its own, sharing the printing's FoilUUIDs.
func finishBackend(printings ...map[string]string) *mtgmatcher.Backend {
	b := &mtgmatcher.Backend{UUIDs: map[string]*mtgmatcher.CardObject{}}
	for _, finishes := range printings {
		for finish, uuid := range finishes {
			b.UUIDs[uuid] = &mtgmatcher.CardObject{
				Card: mtgmatcher.Card{
					UUID:        uuid,
					FoilUUIDs:   finishes,
					Finish:      finish,
					Identifiers: map[string]string{},
				},
				Foil:   mtgmatcher.IsFoilFinish(finish) && finish != mtgmatcher.FinishEtched,
				Etched: finish == mtgmatcher.FinishEtched,
			}
		}
	}
	return b
}

// setMKMShelf publishes one Cardmarket shelf as the only seller, restoring
// whatever was loaded when the test ends.
func setMKMShelf(t *testing.T, products map[string]string) {
	t.Helper()
	prev := sellersPtr.Load()
	t.Cleanup(func() { sellersPtr.Store(prev) })

	trend := mtgban.InventoryRecord{}
	for uuid, id := range products {
		trend.Add(uuid, &mtgban.InventoryEntry{OriginalID: id, Price: 1})
	}
	sellers := []mtgban.Seller{mtgban.NewSellerFromInventory(trend, mtgban.ScraperInfo{
		Shorthand: "MKMTrend", MetadataOnly: true,
	})}
	sellersPtr.Store(&sellers)
}

// TestMKMIDModeReadsTheShelves keys the price API's Cardmarket ids on the
// product the Cardmarket shelves price a card under, which covers every
// card they price, and keeps the datastore's id for the cards they do not.
func TestMKMIDModeReadsTheShelves(t *testing.T) {
	b := finishBackend(
		map[string]string{"nonfoil": "uuid-priced", "foil": "uuid-priced_f"},
		map[string]string{"nonfoil": "uuid-other"},
	)
	setMKMShelf(t, map[string]string{"uuid-priced": "265854"})

	card := func(uuid, mcmID string) *mtgmatcher.CardObject {
		co := *b.UUIDs[uuid]
		co.Identifiers = map[string]string{}
		if mcmID != "" {
			co.Identifiers["mcmId"] = mcmID
		}
		return &co
	}

	for _, tc := range []struct {
		name string
		co   *mtgmatcher.CardObject
		want string
	}{
		{"priced, no datastore id", card("uuid-priced", ""), "265854"},
		{"priced, datastore disagrees", card("uuid-priced", "111111"), "265854"},
		{"its foil, not priced on its own", card("uuid-priced_f", ""), "265854"},
		{"not priced, datastore id", card("uuid-other", "700001"), "700001"},
		{"not priced, datastore id is another card's", card("uuid-other", "265854"), ""},
		{"neither", card("uuid-other", ""), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := getIDFromMode(b, "mkm", tc.co); got != tc.want {
				t.Errorf("getIDFromMode(mkm, %s) = %q, want %q", tc.co.UUID, got, tc.want)
			}
		})
	}
}

// TestEveryFinishKeepsItsPrice files the finishes of one printing under the
// one product id they share, as id=mkm and id=tcg do. Each keeps a price of
// its own, where a cold foil used to overwrite the foil it shares a flag
// with.
func TestEveryFinishKeepsItsPrice(t *testing.T) {
	b := finishBackend(map[string]string{"nonfoil": "lor-1", "foil": "lor-2", "coldfoil": "lor-3"})
	setMKMShelf(t, map[string]string{"lor-1": "600001", "lor-2": "600001", "lor-3": "600001"})

	out := map[string]map[string]*BanPrice{}
	for uuid, price := range map[string]float64{"lor-1": 1, "lor-2": 4, "lor-3": 38} {
		entries := []mtgban.InventoryEntry{{Conditions: mtgban.NM, Price: price, Quantity: 2}}
		processEntry(b, out, entries, "mkm", uuid, "CT", true, true, true)
	}

	got := out["600001"]["CT"]
	if got == nil {
		t.Fatalf("no price filed under the product: %v", out)
	}
	if got.Regular != 1 || got.Foil != 4 || got.MoreFinishes == nil || got.ColdFoil != 38 {
		t.Errorf("prices = regular %v, foil %v, more %+v; want 1, 4 and a cold foil of 38",
			got.Regular, got.Foil, got.MoreFinishes)
	}
	if got.Qty != 2 || got.QtyFoil != 2 || got.GetQty("coldfoil") != 2 {
		t.Errorf("quantities = %d, %d, %d; want 2 each", got.Qty, got.QtyFoil, got.GetQty("coldfoil"))
	}
	for tag, want := range map[string]float64{"NM": 1, "NM_foil": 4, "NM_coldfoil": 38} {
		if got := got.Conditions.Get(tag); got != want {
			t.Errorf("conditions[%s] = %v, want %v", tag, got, want)
		}
	}

	wire, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"regular":1`, `"foil":4`, `"coldfoil":38`, `"qty_coldfoil":2`, `"NM_coldfoil":38`} {
		if !strings.Contains(string(wire), key) {
			t.Errorf("wire %s lacks %s", wire, key)
		}
	}

	// The upload reads one uuid's price whichever finish carries it.
	cold := &BanPrice{}
	cold.Set("coldfoil", 38)
	if got := getPrice(cold, ""); got != 38 {
		t.Errorf("getPrice of a cold foil = %v, want 38", got)
	}
}

func TestAPIFinish(t *testing.T) {
	card := func(uuid, finish string, foil, etched bool, finishes map[string]string) *mtgmatcher.CardObject {
		return &mtgmatcher.CardObject{
			Card: mtgmatcher.Card{UUID: uuid, Finish: finish, FoilUUIDs: finishes},
			Foil: foil, Etched: etched,
		}
	}
	magic := map[string]string{"nonfoil": "m", "foil": "m_f", "etched": "m_e"}
	// Gundam's foil is its holofoil: the flag answers with that uuid.
	gundam := map[string]string{"nonfoil": "g-1", "holofoil": "g-2", "foil": "g-2"}
	// A card sold in runs is regular in its unlimited one.
	pokemon := map[string]string{"1stedition": "p-1", "unlimited": "p-2", "nonfoil": "p-2",
		"1steditionholofoil": "p-3", "unlimitedholofoil": "p-4", "foil": "p-4"}

	for _, tc := range []struct {
		name string
		co   *mtgmatcher.CardObject
		want string
	}{
		{"magic nonfoil", card("m", "nonfoil", false, false, magic), "nonfoil"},
		{"magic foil", card("m_f", "foil", true, false, magic), "foil"},
		{"magic etched", card("m_e", "etched", false, true, magic), "etched"},
		{"a foil sold as holofoil", card("g-2", "holofoil", true, false, gundam), "foil"},
		{"the unlimited run", card("p-2", "unlimited", false, false, pokemon), "nonfoil"},
		{"the 1st edition run", card("p-1", "1stedition", false, false, pokemon), "1stedition"},
		{"the unlimited holofoil", card("p-4", "unlimitedholofoil", true, false, pokemon), "foil"},
		{"the 1st edition holofoil", card("p-3", "1steditionholofoil", true, false, pokemon), "1steditionholofoil"},
		{"a finish with no field", card("x", "glitterfoil", true, false, nil), "foil"},
		{"no finish at all", card("y", "", false, false, nil), "nonfoil"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := apiFinish(tc.co, "product-id"); got != tc.want {
				t.Errorf("apiFinish(%s) = %q, want %q", tc.co.UUID, got, tc.want)
			}
		})
	}

	// Keyed by its own uuid a card shares its id with nothing, so it keeps
	// the slot its flags name, as every uuid-keyed reader expects.
	for _, tc := range []struct {
		co   *mtgmatcher.CardObject
		want string
	}{
		{card("p-1", "1stedition", false, false, pokemon), "nonfoil"},
		{card("p-3", "1steditionholofoil", true, false, pokemon), "foil"},
		{card("m_e", "etched", false, true, magic), "etched"},
	} {
		if got := apiFinish(tc.co, tc.co.UUID); got != tc.want {
			t.Errorf("apiFinish(%s) by its uuid = %q, want %q", tc.co.UUID, got, tc.want)
		}
	}
}

// TestOfflinePayloadKeepsEveryFinish: the offline payload is keyed by uuid
// and carries the regular, foil and etched slots only, so a finish past
// those - a reverse holofoil beside a printing's holofoil - has to arrive
// in the slot its flag names rather than in a field the payload drops.
func TestOfflinePayloadKeepsEveryFinish(t *testing.T) {
	b := finishBackend(map[string]string{"nonfoil": "pk-a", "reverseholofoil": "pk-c"})
	setMKMShelf(t, nil)

	out := map[string]map[string]*BanPrice{}
	entries := []mtgban.InventoryEntry{{Conditions: mtgban.NM, Price: 4.5, Quantity: 3}}
	processEntry(b, out, entries, "", "pk-c", "TCGPlayer", true, true, true)

	payload := banprice2offline("SV1", time.Now(), out, nil)
	got := payload.Retail["pk-c"]["TCGPlayer"]
	if got == nil || got.Foil != 4.5 || got.QtyFoil != 3 || got.Conditions["NM_foil"] != 4.5 {
		t.Errorf("offline entry = %+v, want foil 4.5, qty_foil 3 and NM_foil 4.5", got)
	}
}
