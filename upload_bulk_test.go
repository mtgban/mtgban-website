package main

import (
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
