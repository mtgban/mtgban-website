// Package uploadsort holds what the upload page's rows sort by when the
// reader breaks ties by card properties: one string per property, written on
// each row, which the page's sorter compares as it stands. Each game's own
// color and rarity order comes from its backend.
package uploadsort

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/mtgban/go-mtgban/matcher"
)

// Keys are a printing's sort keys. A string compares as written, numbers
// compared naturally; Rarity is a number. An empty key sorts last.
type Keys struct {
	// The name, lowercased
	Name string

	// The release date, then the lowercased edition
	Set string

	// The collector number
	Number string

	// Nonfoil, foil, etched, then the finish's name
	Finish string

	// One color in the game's order, then several (fewer first, then the
	// game's order), then none
	Color string

	// The rarity's rank, rarest first; empty for one the game does not rank
	Rarity string
}

// For is the keys of the printing cardID names, or none for an id the
// backend does not know.
func For(b *matcher.Backend, cardID string) Keys {
	co, err := b.GetUUID(cardID)
	if err != nil {
		return Keys{}
	}

	keys := Keys{
		Name:   strings.ToLower(co.Name),
		Set:    strings.ToLower(co.Edition),
		Number: co.Number,
		Color:  colorKey(b.Colors, co.Colors),
	}
	released, err := b.CardReleaseDate(cardID)
	if err == nil {
		keys.Set = released.Format("2006-01-02") + " " + keys.Set
	}

	finish := 0
	switch {
	case co.Etched:
		finish = 2
	case co.Foil:
		finish = 1
	}
	keys.Finish = strconv.Itoa(finish) + " " + strings.ToLower(co.Finish)

	rank, ranked := b.RarityRank(co.Rarity)
	if ranked {
		keys.Rarity = strconv.Itoa(rank)
	}
	return keys
}

// colorKey files colors by order, the game's: "1" and the color's place for
// one, "2", how many and each place for several, "3" for none. A color the
// game does not list, "colorless" among them, counts as none.
func colorKey(order, colors []string) string {
	var places []int
	for _, color := range colors {
		place := slices.Index(order, color)
		if place >= 0 && color != "colorless" {
			places = append(places, place)
		}
	}
	if len(places) == 0 {
		return "3"
	}
	slices.Sort(places)

	var key strings.Builder
	if len(places) == 1 {
		key.WriteString("1")
	} else {
		fmt.Fprintf(&key, "2.%02d", len(places))
	}
	for _, place := range places {
		fmt.Fprintf(&key, ".%02d", place)
	}
	return key.String()
}
