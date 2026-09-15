package main

import (
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// Every value in PromoTypes or Treatments is a value "is:" can filter on
// directly - the same string cardFilterIs compares co.PromoTypes against,
// with no relabelling in between. If this stops holding, a card's own link
// stops finding it. "retro" is the one value not drawn from co.PromoTypes
// itself, so it is checked here too rather than assumed.
func TestPromoTypeLinksMatchIsFilter(t *testing.T) {
	if !datastoreLoaded() {
		t.Skip("no datastore loaded")
	}
	plain, chipped := promoTypeCards(t)
	if plain == "" || chipped == "" {
		t.Skip("this datastore has no printing carrying a promo type")
	}

	var checked int
	for _, uuid := range []string{plain, chipped} {
		co, err := mtgmatcher.GetUUID(uuid)
		if err != nil {
			continue
		}
		card := uuid2card(uuid, false, false, false)
		values := append(append([]string{}, card.PromoTypes...), card.Treatments...)
		for _, value := range values {
			checked++
			if cardFilterIs([]string{value}, co) {
				t.Errorf("%s (%s): is:%s does not match the card its own link names", co.Name, co.SetCode, value)
			}
		}
	}
	if checked == 0 {
		t.Fatal("found no promo-type links to check")
	}

	// is:retro is real even though "retro" never appears in AllPromoTypes.
	var retroUUID string
	for _, uuid := range mtgmatcher.GetUUIDs() {
		co, err := mtgmatcher.GetUUID(uuid)
		if err != nil || co.Sealed || co.FrameVersion != "1997" {
			continue
		}
		card := uuid2card(uuid, false, false, false)
		for _, p := range card.PromoTypes {
			if p == "retro" {
				retroUUID = uuid
			}
		}
		if retroUUID != "" {
			break
		}
	}
	if retroUUID == "" {
		t.Skip("this datastore has no retro-framed printing recent enough to show it")
	}
	co, _ := mtgmatcher.GetUUID(retroUUID)
	if cardFilterIs([]string{"retro"}, co) {
		t.Errorf("%s (%s): is:retro does not match a card whose own PromoTypes names it", co.Name, co.SetCode)
	}
}

// Rendered through the real templates: PromoTypes and Treatments both carry
// a working "?q=is:<value>" link and show the spelled-out label, not the raw
// token, and mobile's version stops the tap from also opening the card
// drawer the row's own onclick would trigger.
func TestSearchTemplatesLinkPromoTypes(t *testing.T) {
	if !datastoreLoaded() {
		t.Skip("no datastore loaded")
	}
	_, chipped := promoTypeCards(t)
	if chipped == "" {
		t.Skip("this datastore has no printing with a treatment chip")
	}
	card := uuid2card(chipped, false, false, false)
	value := card.Treatments[0]
	label := promoTypeLabel(value)
	pageVars := PageVars{
		SearchQuery: card.Name,
		CardHashes:  []string{chipped},
		AllKeys:     []string{chipped},
		Metadata:    map[string]GenericCard{chipped: card},
	}

	desktop := renderSearch(t, "search.html", pageVars)
	if !strings.Contains(desktop, `href="?q=is:`+value+`"`) {
		t.Errorf("search.html has no link for is:%s", value)
	}
	if !strings.Contains(desktop, `>`+label+`<`) {
		t.Errorf("search.html does not show the spelled-out label %q for is:%s", label, value)
	}

	mobile := renderSearch(t, "mobile/search.html", pageVars)
	if !strings.Contains(mobile, `href="?q=is:`+value+`" onclick="event.stopPropagation()"`) {
		t.Errorf("mobile/search.html's link for is:%s does not stop the row's own tap handler", value)
	}
	if !strings.Contains(mobile, `>`+label+`<`) {
		t.Errorf("mobile/search.html does not show the spelled-out label %q for is:%s", label, value)
	}
}
