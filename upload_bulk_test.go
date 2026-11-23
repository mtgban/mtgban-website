package main

import (
	"math"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/mtgban-website/internal/bulkrates"
)

// bulkCase is a printing and the bulk row that takes it, "" for none.
type bulkCase struct {
	id   string
	want string
}

func checkBulkOffers(t *testing.T, b *matcher.Backend, cases []bulkCase) {
	t.Helper()
	rates := bulkrates.New(b)
	for _, tc := range cases {
		co, err := b.GetUUID(tc.id)
		if err != nil {
			t.Errorf("%s: %v", tc.id, err)
			continue
		}
		tier, _ := rates.Offer(co)
		if tier.Name != tc.want {
			t.Errorf("%s (%s): got %q, want %q", tc.id, co, tier.Name, tc.want)
		}
	}
}

func TestBulkOffersMagic(t *testing.T) {
	t.Parallel()
	skipWithoutDatastore(t)
	checkBulkOffers(t, backend(), []bulkCase{
		// Caravan Vigil, ISD
		{"0003caab-9ff5-5d1a-bc06-976dd0457f19", "1000 Bulk Commons/Uncommons"},
		{"0003caab-9ff5-5d1a-bc06-976dd0457f19_f", "Bulk Foil Commons and Uncommons"},
		// Goblin King, 3ED
		{"0001e0d0-2dcd-5640-aadc-a84765cf5fc9", "Bulk Rare"},
		// Form of the Dragon, 9ED 187★
		{"000da741-09c0-511a-96fc-9668f310abd8", "Bulk Foil Rares"},
		// Clone Legion, TLE
		{"0004822c-c181-5564-808d-a6cc48359a1a", "Bulk Mythic Rare"},
		{"0004822c-c181-5564-808d-a6cc48359a1a_f", "Bulk Foil Mythic Rare"},
		// Sphinx of the Final Word, POGW
		{"00010d56-fe38-5e35-8aed-518019aa36a5", "Bulk Promos"},
		// Island, CM2; Swamp, BFZ full art, in foil too
		{"00102364-7540-511e-8178-04dcc5725f16", "1000 Basic Land"},
		{"00631b32-5cfa-551a-9b2d-5c1ad960f368", "Any Full Art Basic Land"},
		{"00631b32-5cfa-551a-9b2d-5c1ad960f368_f", "Any Full Art Basic Land"},
		// Commander: a foil mythic of a Commander set, or of a Commander
		// deck elsewhere, is refused; nonfoil is a Bulk Mythic
		{"0a0cba19-eaa9-5e7d-b381-3bbf5938d889", ""},                 // Wildsear, BLC
		{"0404d63b-eeee-5e67-aa59-ac82514b7cf4", "Bulk Mythic Rare"}, // Inferno Titan, BLC
		{"0c04a6ce-ddbe-58d5-ae1d-fe31b2174b22", ""},                 // Rukarumel, CMM deck
		{"0964bdbf-acd7-516e-8c89-f0a116c0da3a", ""},                 // Burakos, CLB deck
		{"1a24b2fd-0631-5e66-b50e-fa36df50588c", "Bulk Mythic Rare"}, // Primeval Bounty, CLB deck
		// Not a Commander deck's: a CMM booster foil, a Secret Lair deck's
		{"04ef11e8-3918-5332-9f7c-3dc29d972c5e_f", "Bulk Foil Mythic Rare"}, // Kozilek, CMM
		{"00a1f936-ee43-55a3-aaa2-03adeb7d8f81_f", "Bulk Foil Mythic Rare"}, // Hexdrinker, SLD
		// Timeshifted rares and mythics are refused in any finish; TSR's
		// modern-frame cards are not timeshifted
		{"16790491-a95d-5f99-8ae4-1f3bc0d78f4f", ""},          // Solitude, H2R
		{"16790491-a95d-5f99-8ae4-1f3bc0d78f4f_f", ""},        // Solitude, H2R foil
		{"485ea57b-16d8-54ba-a84a-c86e57cc70d7", ""},          // The First Sliver, H1R foil
		{"00dc5683-b09e-5860-8ebb-ed9ad78bf9b0", "Bulk Rare"}, // Glittering Wish, TSR
		// Refused: memorabilia, book promo, Un-set, gold border, token,
		// Japanese, Phyrexian
		{"d15b218d-411f-5517-98b7-ff366fe7f0a6", ""},   // Shivan Dragon, CED
		{"35a44c3b-c344-5685-ba89-2e227233e94f", ""},   // Shivan Dragon, 30A
		{"4bfcac0c-4b5f-5821-a126-8dfba5d2d384", ""},   // Mana Crypt, PHPR
		{"03c64bd2-e1f9-5451-bc06-aee5f1db8612", ""},   // Hardy of Myra's Marvels, UNF
		{"00460d79-3570-58b8-af87-7b89106eb48c", ""},   // Balance, PTC
		{"00093ed9-5b6b-5a88-bd12-7c3e260abf1c", ""},   // Inkling, TBRC
		{"00b8e1e4-70e7-5d35-80ae-8b5acdd9c29e", ""},   // Royal Assassin, 4BB
		{"001b516c-09a3-5776-92d3-944fee7c18e6_f", ""}, // Forest, ONE 271
	})
}

func TestBulkOffersGames(t *testing.T) {
	t.Parallel()
	for game, cases := range map[matcher.Game][]bulkCase{
		matcher.GameLorcana: {
			{"1", "1000 Bulk Commons/Uncommons"},
			{"1003_coldfoil", "Bulk Cold Foil"},
			{"1001", "Bulk Rare"},
			{"10", "Bulk Super Rare"},
			{"1005", "Bulk Legendary"},
			// The rarity's row wins over the foil's
			{"1005_coldfoil", "Bulk Legendary"},
			{"1161_holofoil", ""}, // enchanted
		},
		matcher.GameRiftbound: {
			{"ogn-001-298", "1000 Bulk Commons/Uncommons"},
			{"ogn-001-298_foil", "Bulk Foil Riftbound Card"},
			{"ogn-025-298_foil", "Bulk Rare"},
			{"ogn-037-298_foil", "Bulk Epic"},
			{"ogn-007a-298_foil", ""}, // showcase
		},
		matcher.GameOnePiece: {
			{"eb01-004_544528", "1000 Bulk Commons/Uncommons"},
			{"eb01-002_544525_foil", "Bulk Rare"},
			{"eb01-006_544530_foil", "Bulk Super Rare"},
			{"eb01-001_544523", ""}, // leader
		},
		matcher.GameYuGiOh: {
			{"108333_limited", "Bulk Holos"},
			{"200570_unlimited", ""}, // common
		},
		matcher.GamePokemon: {
			{"001-064_560311", "1,000 Bulk Commons/Uncommons"},
			{"001-064_560311_reverseholofoil", "Bulk Reverse Foil Common/Uncommon"},
			{"001-017_83542", "Bulk Rare"},
			{"001-110_83496_reverseholofoil", "Bulk Reverse Foil Rare"},
			{"001-025_250300_holofoil", "Bulk Holo Rare"},
			{"001-102_106996_1steditionholofoil", "Bulk 1st Edition"},
			{"001-005_162268", "Bulk Promos"},
			{"017_645286_reverseholofoil", "Bulk Reverse Foil Basic Energy"},
			{"017_645286", ""}, // basic energy
		},
	} {
		t.Run(string(game), func(t *testing.T) {
			t.Parallel()
			checkBulkOffers(t, gameDatastore(t, game).backend, cases)
		})
	}
}

// A row goes to Filtered out at its bulk rate, in any condition, when no
// store buys it or the bulk shelf pays more a copy than the best one; a
// store keeps a tie and a row the reader placed, and one the datastore
// lacks, or any with no bulk shelf, goes where it went before.
func TestUploadBulkRows(t *testing.T) {
	skipWithoutDatastore(t)
	const (
		vigil   = "0003caab-9ff5-5d1a-bc06-976dd0457f19" // common, 0.01
		goblin  = "0001e0d0-2dcd-5640-aadc-a84765cf5fc9" // rare, 0.10
		legion  = "0004822c-c181-5564-808d-a6cc48359a1a" // mythic, 0.25
		inferno = "0404d63b-eeee-5e67-aa59-ac82514b7cf4" // mythic, 0.25
	)
	entries := []UploadEntry{
		{CardID: "card", OriginalPrice: 10},
		{CardID: vigil, OriginalCondition: "HP", OriginalPrice: 0.05},
		{CardID: vigil + "_f", OriginalPrice: 0.10},
		{CardID: "nothing", OriginalPrice: 1},
		{CardID: goblin, OriginalPrice: 0.50},
		{CardID: legion, OriginalPrice: 0.50},
		{CardID: inferno, OriginalPrice: 0.50},
	}
	prices := uploadPrices{
		results: map[string]map[string]*BanPrice{
			"card":  {"CK": {Regular: 5}},
			goblin:  {"CK": {Regular: 0.02}},
			legion:  {"CK": {Regular: 0.25}},
			inferno: {"CK": {Regular: 0.05}},
		},
		enabledStores: []string{"CK"},
	}
	st := uploadSettings{percMargin: 1, multiplier: 1, moves: map[string]string{vigil + "_f": notBoughtMove, inferno: "CK"}}

	rows := priceUploadRows(backend(), true, st, prices, uploadIndexes{}, bulkrates.New(backend()), entries)
	for card, want := range map[string]string{"card": "CK", legion: "CK", inferno: "CK moved", goblin: ""} {
		got := strings.Join(sectionOf(rows, card), ",")
		if got != want {
			t.Errorf("%s at %q, want %q", card, got, want)
		}
	}
	bulkRows := map[string]LeftoverEntry{}
	for _, e := range rows.filteredOut.rows {
		bulkRows[e.CardID] = e
	}
	hp := bulkRows[vigil]
	if len(bulkRows) != 2 || hp.Condition != "HP" || hp.Store != "" ||
		hp.Bulk.Name != "1000 Bulk Commons/Uncommons" || hp.Price != 0.01 || hp.Spread != 20 {
		t.Errorf("filtered out %+v, want the HP Vigil at the bulk rate, 20%% of its 0.05, and Goblin King", rows.filteredOut.rows)
	}
	rare := bulkRows[goblin]
	if rare.Store != "" || rare.Bulk.Name != "Bulk Rare" || rare.Price != 0.10 {
		t.Errorf("Goblin King %+v, want Bulk Rare at 0.10 over CK's 0.02", rare)
	}
	var notBought []string
	for _, e := range rows.notBought.rows {
		notBought = append(notBought, e.CardID)
	}
	if strings.Join(notBought, ",") != vigil+"_f,nothing" {
		t.Errorf("not bought %q, want the moved foil Vigil and the unknown id", notBought)
	}

	none := priceUploadRows(backend(), true, st, prices, uploadIndexes{}, nil, entries)
	got := strings.Join(sectionOf(none, goblin), ",")
	if len(none.filteredOut.rows) != 0 || len(none.notBought.rows) != 3 || got != "CK" {
		t.Errorf("no bulk: Goblin King at %q, filtered out %+v, not bought %+v", got, none.filteredOut.rows, none.notBought.rows)
	}
}

// Priced in credit, the bulk shelf's offer is its credit, so a store whose
// credit beats it keeps a rare the shelf would take for cash; in market
// credit, a shelf with no market credit pays nothing, so a common no store
// buys stays in Not bought.
func TestUploadBulkCredit(t *testing.T) {
	skipWithoutDatastore(t)
	withConfigCopy(t)
	const (
		goblin = "0001e0d0-2dcd-5640-aadc-a84765cf5fc9" // rare, 0.10, 0.125 in credit
		vigil  = "0003caab-9ff5-5d1a-bc06-976dd0457f19" // common, no store
	)
	entries := []UploadEntry{{CardID: goblin, OriginalPrice: 0.50}, {CardID: vigil, OriginalPrice: 0.05}}
	for _, tc := range []struct {
		source string
		credit float64
		market map[string]float64
		store  string
		bulk   float64
	}{
		{"", 1.5, nil, "", 0.10},                                                        // cash: CK's 0.09 loses
		{"credit", 1.5, nil, "CK", 0},                                                   // CK's 0.135 in credit wins
		{"credit", 1.2, nil, "", 0.10 * 1.25},                                           // CK's 0.108 loses to 0.125
		{"marketCredit", 1.2, map[string]float64{"CK": 1, "CSI": 0.8}, "CK", 0},         // 0.108 beats 0.10
		{"marketCredit", 1.2, map[string]float64{"CK": 0.8, "CSI": 1}, "", 0.10 * 1.25}, // 0.0864 loses
		{"marketCredit", 1.2, map[string]float64{"CK": 1}, "CK", 0},                     // the shelf pays nothing
	} {
		Config().BuylistMarketCredit = tc.market
		prices := uploadPrices{
			results:       map[string]map[string]*BanPrice{goblin: {"CK": {Regular: 0.09}}},
			credits:       map[string]float64{"CK": tc.credit},
			enabledStores: []string{"CK"},
		}
		st := uploadSettings{percMargin: 1, multiplier: 1, priceSource: tc.source}
		rows := priceUploadRows(backend(), true, st, prices, uploadIndexes{}, bulkrates.New(backend()), entries)
		got := strings.Join(sectionOf(rows, goblin), ",")
		var bulk float64
		for _, e := range rows.filteredOut.rows {
			if e.CardID == goblin {
				bulk = e.Price
			}
		}
		if got != tc.store || math.Abs(bulk-tc.bulk) > 1e-9 {
			t.Errorf("%q at %v credit, %v: at %q, bulk %v; want %q, %v", tc.source, tc.credit, tc.market, got, bulk, tc.store, tc.bulk)
		}
		var vigilNotBought bool
		for _, e := range rows.notBought.rows {
			vigilNotBought = vigilNotBought || e.CardID == vigil
		}
		if vigilNotBought != (tc.source == "marketCredit" && tc.market["CSI"] == 0) {
			t.Errorf("%q, %v: Vigil in Not bought %v", tc.source, tc.market, vigilNotBought)
		}
	}
}

// A bulk row names the shelf for its store, links its offer to it, shows a
// boxed rate as the box's price, sorts by the price a card, can be moved to
// Not bought, and keeps the alert bell a Not bought row has.
func TestUploadBulkRender(t *testing.T) {
	lot := bulkrates.Tier{Name: "1000 Bulk Commons/Uncommons", Price: 3, Lot: 1000, Link: "https://example.com/bulk"}
	out := renderUpload(t, PageVars{CanAlerts: true, UploadVars: UploadVars{
		IsBuylist:     true,
		ScraperKeys:   []string{"CK"},
		UploadEntries: []UploadEntry{{CardID: "a"}},
		FilteredOut:   []LeftoverEntry{{CardID: "a", Quantity: 1, Bulk: lot, Price: lot.Each()}},
	}})
	section := leftoverRows(out, "opt-filtered-out")
	for _, want := range []string{
		`<span title="1000 Bulk Commons/Uncommons">CSI Bulk</span>`,
		`data-sort="0.0030"><span class="offer">$ <a href="https://example.com/bulk" target="_blank" rel="noopener" title="1000 Bulk Commons/Uncommons">3.00 / 1000</a>`,
		`class="opt-move-btn"`,
		`class="opt-move-btn opt-alert-btn alert-link" data-card-id="a" data-side="buylist"`,
	} {
		if !strings.Contains(section, want) {
			t.Errorf("no %s in %s", want, section)
		}
	}
	if strings.Contains(section, "/go/b/") {
		t.Errorf("a bulk row links through a store: %s", section)
	}
}
