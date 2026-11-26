// Package bulkrates prices a card at what Cool Stuff Inc's bulk shelf pays
// for it, for the upload's cards no store on the page buys.
//
// The rates are copied by hand from CSI's "Sell Bulk" page of each game,
// https://www.coolstuffinc.com/main_selllist.php?name=&bo=1&min=&max=&a=1&s=mtg
// and the same with s=lorcana, riftbound, optcg, yugioh or pokemon, and
// change only when CSI changes them. Each row's notes are read as rules on
// the card; the "near mint only" ones are not, so any condition is priced.
package bulkrates

import (
	"slices"
	"strings"

	"github.com/mtgban/go-mtgban/matcher"
)

// Tier is one row of a game's bulk shelf.
type Tier struct {
	// Name is CSI's name for the row
	Name string
	// Price is what CSI pays for Lot cards, in USD
	Price float64
	// Lot is how many cards Price buys: 1, or 100 or 1000 for the rows
	// CSI buys only by the box
	Lot int
	// Link is the game's bulk shelf
	Link string
}

// Each is what one card of the tier is worth.
func (t Tier) Each() float64 {
	return t.Price / float64(t.Lot)
}

// Times is the tier paid at rate times its cash price, as in store credit.
func (t Tier) Times(rate float64) Tier {
	t.Price *= rate
	return t
}

// Store is the shorthand of the store whose bulk shelf this is.
const Store = "CSI"

// CreditRate is what the bulk shelf pays in store credit for a dollar of
// cash, as its page quotes it.
const CreditRate = 1.25

const shelf = "https://www.coolstuffinc.com/main_selllist.php?name=&bo=1&min=&max=&a=1&s="

var (
	magicPromo       = Tier{"Bulk Promos", 0.06, 1, shelf + "mtg"}
	magicFullArtLand = Tier{"Any Full Art Basic Land", 0.05, 1, shelf + "mtg"}
	magicBasicLand   = Tier{"1000 Basic Land", 10, 1000, shelf + "mtg"}
	magicFoilMythic  = Tier{"Bulk Foil Mythic Rare", 0.35, 1, shelf + "mtg"}
	magicFoilRare    = Tier{"Bulk Foil Rares", 0.10, 1, shelf + "mtg"}
	magicFoilCommon  = Tier{"Bulk Foil Commons and Uncommons", 0.01, 1, shelf + "mtg"}
	magicMythic      = Tier{"Bulk Mythic Rare", 0.25, 1, shelf + "mtg"}
	magicRare        = Tier{"Bulk Rare", 0.10, 1, shelf + "mtg"}
	magicCommon      = Tier{"1000 Bulk Commons/Uncommons", 10, 1000, shelf + "mtg"}

	lorcanaLegendary = Tier{"Bulk Legendary", 0.35, 1, shelf + "lorcana"}
	lorcanaSuperRare = Tier{"Bulk Super Rare", 0.03, 1, shelf + "lorcana"}
	lorcanaRare      = Tier{"Bulk Rare", 0.03, 1, shelf + "lorcana"}
	lorcanaColdFoil  = Tier{"Bulk Cold Foil", 0.02, 1, shelf + "lorcana"}
	lorcanaCommon    = Tier{"1000 Bulk Commons/Uncommons", 3, 1000, shelf + "lorcana"}

	riftboundEpic   = Tier{"Bulk Epic", 0.35, 1, shelf + "riftbound"}
	riftboundRare   = Tier{"Bulk Rare", 0.10, 1, shelf + "riftbound"}
	riftboundFoil   = Tier{"Bulk Foil Riftbound Card", 0.02, 1, shelf + "riftbound"}
	riftboundCommon = Tier{"1000 Bulk Commons/Uncommons", 3, 1000, shelf + "riftbound"}

	onePieceSuperRare = Tier{"Bulk Super Rare", 0.10, 1, shelf + "optcg"}
	onePieceRare      = Tier{"Bulk Rare", 0.04, 1, shelf + "optcg"}
	onePieceCommon    = Tier{"1000 Bulk Commons/Uncommons", 3, 1000, shelf + "optcg"}

	yugiohHolo = Tier{"Bulk Holos", 0.01, 1, shelf + "yugioh"}

	pokemonPromo         = Tier{"Bulk Promos", 0.04, 1, shelf + "pokemon"}
	pokemonFirstEdition  = Tier{"Bulk 1st Edition", 0.50, 1, shelf + "pokemon"}
	pokemonReverseEnergy = Tier{"Bulk Reverse Foil Basic Energy", 0.05, 1, shelf + "pokemon"}
	pokemonReverseRare   = Tier{"Bulk Reverse Foil Rare", 0.03, 1, shelf + "pokemon"}
	pokemonReverseCommon = Tier{"Bulk Reverse Foil Common/Uncommon", 0.03, 1, shelf + "pokemon"}
	pokemonHoloRare      = Tier{"Bulk Holo Rare", 0.03, 1, shelf + "pokemon"}
	pokemonRare          = Tier{"Bulk Rare", 0.03, 1, shelf + "pokemon"}
	pokemonCommon        = Tier{"1,000 Bulk Commons/Uncommons", 25, 1000, shelf + "pokemon"}
)

// timeshifted are the sets whose cards carry the purple timeshifted symbol,
// which every rare and mythic row refuses, foil or not. The datastore has no
// flag for it; TSR's are only its retro-frame cards.
var timeshifted = []string{"TSB", "H1R", "H2R", "TSR"}

// organizedPlay are the Pokemon sets the notes keep off the shelf: "Exclude
// Play! Pokemon Prize Pack Cards" and "Excludes Pokemon League and Organized
// Play promos".
var organizedPlay = []string{
	"G22880",  // Prize Pack Series Cards
	"PR-1539", // League & Championship Cards
	"PPP",     // Professor Program Promos
	"G24529",  // Player Placement Trainer Promos
}

// Rates prices cards at the bulk shelf of the backend's game.
type Rates struct {
	b *matcher.Backend
	// commanderDecks are the sealed Commander decks outside Secret Lair,
	// whose mythics the Magic mythic rows refuse in foil
	commanderDecks map[string]bool
}

// New reads what pricing needs from the backend, once per datastore.
func New(b *matcher.Backend) *Rates {
	decks := map[string]bool{}
	for code, set := range b.Sets {
		// A Secret Lair deck does not make its cards Commander ones
		if code == "SLD" {
			continue
		}
		for _, product := range set.SealedProduct {
			if product.Category == "deck" && product.Subtype == "commander" {
				decks[product.UUID] = true
			}
		}
	}
	return &Rates{b: b, commanderDecks: decks}
}

// Offer is the tier CSI's bulk shelf takes the printing at; false for a
// sealed product, a card in another language, a game with no bulk shelf, or
// a card no row of it takes. A nil Rates takes nothing.
func (r *Rates) Offer(co *matcher.CardObject) (Tier, bool) {
	if r == nil || co.Sealed || co.Language != "English" || r.b.Sets[co.SetCode] == nil {
		return Tier{}, false
	}
	switch r.b.Game {
	case matcher.GameMagic:
		return r.magic(co)
	case matcher.GameLorcana:
		return lorcana(co)
	case matcher.GameRiftbound:
		return riftbound(co)
	case matcher.GameOnePiece:
		return onePiece(co)
	case matcher.GameYuGiOh:
		return yugioh(co)
	case matcher.GamePokemon:
		return pokemon(co)
	}
	return Tier{}, false
}

func (r *Rates) magic(co *matcher.CardObject) (Tier, bool) {
	// Un-sets, memorabilia (CED, 30A, the World Championship decks), and
	// the online-only printings are on no row. Tokens, oversized cards and
	// TSB's timeshifted ones are rarities of their own, which no row names.
	set := r.b.Sets[co.SetCode]
	if set.Type == "funny" || set.Type == "memorabilia" || co.BorderColor == "gold" || co.IsOnlineOnly {
		return Tier{}, false
	}
	switch co.Rarity {
	case "common", "uncommon", "rare", "mythic":
	default:
		return Tier{}, false
	}
	// Mystery Booster 2's playtest cards are CMB1's and CMB2's kind, whose
	// sets are Un-sets to the datastore
	if co.SetCode == "MB2" && co.HasPromoType("playtest") {
		return Tier{}, false
	}

	if co.IsPromo {
		// Book promos and an Un-set's, filed in a promo set of its own,
		// are refused
		parent := r.b.Sets[set.ParentCode]
		if co.SetCode == "PHPR" || (parent != nil && parent.Type == "funny") {
			return Tier{}, false
		}
		return magicPromo, true
	}
	if slices.Contains(co.Supertypes, "Basic") && slices.Contains(co.Types, "Land") {
		if co.IsFullArt {
			return magicFullArtLand, true
		}
		return magicBasicLand, true
	}

	timeshift := slices.Contains(timeshifted, co.SetCode) && (co.SetCode != "TSR" || co.FrameVersion == "1997")
	if timeshift && (co.Rarity == "rare" || co.Rarity == "mythic") {
		return Tier{}, false
	}

	if co.Foil || co.Etched {
		switch co.Rarity {
		case "mythic":
			if r.commander(co) {
				return Tier{}, false
			}
			return magicFoilMythic, true
		case "rare":
			return magicFoilRare, true
		}
		return magicFoilCommon, true
	}

	switch co.Rarity {
	case "mythic":
		return magicMythic, true
	case "rare":
		return magicRare, true
	}
	return magicCommon, true
}

// commander reports whether a foil printing is a Commander one: from a
// Commander set, or sold in that finish in a Commander deck.
func (r *Rates) commander(co *matcher.CardObject) bool {
	if r.b.Sets[co.SetCode].Type == "commander" {
		return true
	}
	finish := matcher.FinishFoil
	if co.Etched {
		finish = matcher.FinishEtched
	}
	return slices.ContainsFunc(co.SourceProducts[finish], func(uuid string) bool {
		return r.commanderDecks[uuid]
	})
}

func lorcana(co *matcher.CardObject) (Tier, bool) {
	switch co.Rarity {
	case "legendary":
		return lorcanaLegendary, true
	case "superrare":
		return lorcanaSuperRare, true
	case "rare":
		return lorcanaRare, true
	case "common", "uncommon":
		switch co.Finish {
		case "coldfoil":
			return lorcanaColdFoil, true
		case matcher.FinishNonfoil:
			return lorcanaCommon, true
		}
	}
	return Tier{}, false
}

func riftbound(co *matcher.CardObject) (Tier, bool) {
	switch co.Rarity {
	case "epic":
		return riftboundEpic, true
	case "rare":
		return riftboundRare, true
	case "common", "uncommon":
		if co.Foil {
			return riftboundFoil, true
		}
		return riftboundCommon, true
	}
	return Tier{}, false
}

func onePiece(co *matcher.CardObject) (Tier, bool) {
	switch co.Rarity {
	case "superrare":
		return onePieceSuperRare, true
	case "rare":
		return onePieceRare, true
	case "common", "uncommon":
		return onePieceCommon, true
	}
	return Tier{}, false
}

// yugioh takes every rarity printed in foil as a holo: all but common, rare
// (silver-lettered, not foil) and promo.
func yugioh(co *matcher.CardObject) (Tier, bool) {
	switch co.Rarity {
	case "common", "rare", "promo":
		return Tier{}, false
	}
	return yugiohHolo, true
}

func pokemon(co *matcher.CardObject) (Tier, bool) {
	if slices.Contains(organizedPlay, co.SetCode) {
		return Tier{}, false
	}
	if co.IsPromo || co.Rarity == "promo" {
		return pokemonPromo, true
	}
	if strings.HasPrefix(co.Finish, "1stedition") {
		return pokemonFirstEdition, true
	}
	basicEnergy := slices.ContainsFunc(co.Types, func(t string) bool {
		return strings.HasPrefix(t, "Basic ") && strings.HasSuffix(t, "Energy")
	})
	if co.Finish == "reverseholofoil" {
		switch {
		case basicEnergy:
			return pokemonReverseEnergy, true
		case co.Rarity == "rare" || co.Rarity == "holorare":
			return pokemonReverseRare, true
		case co.Rarity == "common" || co.Rarity == "uncommon":
			return pokemonReverseCommon, true
		}
		return Tier{}, false
	}
	switch co.Rarity {
	case "holorare":
		return pokemonHoloRare, true
	case "prismrare", "radiantrare", "acespecrare":
		// World Championship decks print theirs without the foil
		if co.Finish == "holofoil" {
			return pokemonHoloRare, true
		}
	case "rare":
		return pokemonRare, true
	case "common", "uncommon":
		// Holo commons are on no row, nor are basic energies
		if !basicEnergy && (co.Finish == matcher.FinishNonfoil || co.Finish == "unlimited") {
			return pokemonCommon, true
		}
	}
	return Tier{}, false
}
