// Package storeorder lays an optimizer table out in the order its store's
// buylist invoice lists cards, so the pile pulled top to bottom matches the
// invoice every store asks cards to be shipped in. Each order was learned
// from real invoices and holds on them as follows:
//
//   - Card Kingdom: oversized cards last, then CK's edition compared
//     naturally ("7th Edition" before "2013 Core Set"), its foil section
//     before the rest, then CK's title byte by byte ("(1001 - Foil)" before
//     "(701 - Foil)"). Exact on 1,295 of 1,309 confirmations, 2018 to 2026;
//     the misses are foils CK files apart in editions from late 2022 on.
//   - ABU Games: ABU's edition, then the card's title, byte by byte, then
//     non-foil first. ABU files many promos under one "Promo" edition that
//     its catalog does not show; promo-named editions go there. Exact on
//     146 of 190 confirmations, 99% of neighbouring lines.
//   - Cool Stuff Inc: CSI's set id, lowest (newest set) first, then its
//     product name. Exact on all 26 sell orders.
//   - MTG Mint Card: non-foils, then foils, then special frames (extended
//     art, showcase, borderless, retro), each by set release, promo sets
//     first; within a set it keeps the order the cards were sent in. Holds
//     on every neighbouring line of 12 orders.
//
// Any other store (Star City Games among them) keeps the order cards were
// submitted in, so its table is left as it came.
package storeorder

import (
	"cmp"
	"slices"
	"strconv"
	"strings"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/mtgban-website/internal/natcmp"
)

// Row is one table row as the store orders read it. Each store's order reads
// only its own fields.
type Row struct {
	// The store's own edition and title: CK's and ABU's from their buylist
	// entries, CSI's product name as Title
	Edition string
	Title   string

	// CSI's set id
	SetID int

	// The printing's set release date, as 2006-01-02, and whether the set is
	// a promo set
	Released string
	PromoSet bool

	Foil bool

	// A special frame: extended art, showcase, borderless, or an old frame
	// on a recent printing
	Frame bool

	// The store's order has nothing to read on the row
	missing bool
}

// For is store's row for the printing cardID names, from the backend and
// the fields of the store's buylist entry for it, which may be nil. A row
// missing what its store's order reads files after the others, as it came.
func For(b *matcher.Backend, store, cardID string, fields map[string]string) Row {
	switch store {
	case "CK":
		if fields["CKEdition"] == "" {
			return Row{missing: true}
		}
		return Row{Edition: fields["CKEdition"], Title: fields["CKTitle"], Foil: fields["CKFoil"] == "true"}
	case "ABUGames", "ABUCredit":
		if fields["ABUEdition"] == "" {
			return Row{missing: true}
		}
		row := Row{Edition: fields["ABUEdition"], Title: fields["ABUTitle"]}
		co, err := b.GetUUID(cardID)
		if err == nil {
			row.Foil = co.Foil || co.Etched
		}
		return row
	case "CSI":
		setID, err := strconv.Atoi(fields["CSIItemSetID"])
		if err != nil {
			return Row{missing: true}
		}
		return Row{SetID: setID, Title: fields["CSIName"]}
	}

	co, err := b.GetUUID(cardID)
	if err != nil {
		return Row{missing: true}
	}
	return printingRow(b, co)
}

// printingRow is the row the printing itself gives: its finish, its set's
// release and kind, and its frame.
func printingRow(b *matcher.Backend, co *matcher.CardObject) Row {
	row := Row{Foil: co.Foil || co.Etched}
	set, err := b.GetSet(co.SetCode)
	if err == nil {
		row.Released = set.ReleaseDate
		row.PromoSet = set.Type == "promo"
	}
	// Mint files both under one edition, dated at Mystery Booster's retail
	// release: after Theros Beyond Death, before Double Masters
	list := co.SetCode == "PLST" || co.SetCode == "MB1"
	if list {
		row.Released = "2020-03-13"
	}

	row.Frame = slices.ContainsFunc(co.FrameEffects, func(effect string) bool {
		return effect == "extendedart" || effect == "showcase" || effect == "shatteredglass"
	}) || co.BorderColor == "borderless"
	// An old frame is a variant only on a recent printing, not on a reprint
	// keeping its first one
	oldFrame := co.FrameVersion == "1993" || co.FrameVersion == "1997"
	if oldFrame && row.Released >= "2020" && !list {
		row.Frame = true
	}
	return row
}

// Ordered reports whether store has an order of its own; a store without
// one keeps the order cards were sent in.
func Ordered(store string) bool {
	switch store {
	case "CK", "ABUGames", "ABUCredit", "CSI", "MMC":
		return true
	}
	return false
}

// Compare orders a and b as store's invoice lists them, 0 where it keeps
// them as they came.
func Compare(store string, a, b Row) int {
	if a.missing || b.missing {
		return cmpFalseFirst(a.missing, b.missing)
	}
	switch store {
	case "CK":
		return cardKingdom(a, b)
	case "ABUGames", "ABUCredit":
		return abuGames(a, b)
	case "CSI":
		return coolStuff(a, b)
	case "MMC":
		return mintCard(a, b)
	}
	return 0
}

func cardKingdom(a, b Row) int {
	c := cmpFalseFirst(strings.Contains(a.Title, "Oversized"), strings.Contains(b.Title, "Oversized"))
	if c == 0 {
		c = natcmp.Compare(a.Edition, b.Edition)
	}
	if c == 0 {
		c = cmpFalseFirst(!ckFoilSection(a), !ckFoilSection(b))
	}
	if c == 0 {
		c = strings.Compare(a.Title, b.Title)
	}
	return c
}

// ckFoilSection reports whether CK lists a foil under its edition's foil
// heading ("Guildpact Foil"). A foil whose title names its finish, as Secret
// Lair's "(1003 - Foil)" does, and any Promotional one stay under the plain
// heading. The finish is looked for in the variation alone, the card "Foil"
// having it in its name.
func ckFoilSection(row Row) bool {
	var variation string
	i := strings.Index(row.Title, " (")
	if i >= 0 {
		variation = row.Title[i:]
	}
	return row.Foil && row.Edition != "Promotional" && !strings.Contains(variation, "Foil")
}

func abuGames(a, b Row) int {
	c := strings.Compare(abuEdition(a.Edition), abuEdition(b.Edition))
	if c == 0 {
		c = strings.Compare(a.Title, b.Title)
	}
	if c == 0 {
		c = cmpFalseFirst(a.Foil, b.Foil)
	}
	return c
}

// abuEdition is the edition ABU's invoice files an edition under: promo
// editions go under one "Promo", as its older invoices still print it.
func abuEdition(edition string) string {
	if strings.HasSuffix(edition, " Promos") || strings.HasSuffix(edition, " Promo") {
		return "Promo"
	}
	for _, prefix := range []string{"Friday Night Magic", "Arena League", "Judge Gift", "Magic Player Rewards", "Wizards Play Network"} {
		if strings.HasPrefix(edition, prefix) {
			return "Promo"
		}
	}
	return edition
}

func coolStuff(a, b Row) int {
	c := cmp.Compare(a.SetID, b.SetID)
	if c == 0 {
		c = strings.Compare(a.Title, b.Title)
	}
	return c
}

func mintCard(a, b Row) int {
	c := cmp.Compare(mintGroup(a), mintGroup(b))
	if c == 0 {
		c = cmpFalseFirst(!a.PromoSet, !b.PromoSet)
	}
	if c == 0 {
		c = strings.Compare(a.Released, b.Released)
	}
	return c
}

// mintGroup is the part of Mint's invoice a row goes in: non-foils, foils,
// then special frames.
func mintGroup(row Row) int {
	switch {
	case row.Frame:
		return 2
	case row.Foil:
		return 1
	}
	return 0
}

// cmpFalseFirst orders false before true.
func cmpFalseFirst(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	}
	return -1
}
