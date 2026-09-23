package main

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// tcgplayerLinkFor spells the address TCGplayer files a printing under, the
// way a reader pastes it: the product id, and the Printing parameter the page
// carries for a foil. The slug is deliberately not the card's name - a name
// holding one of the store's Skip words ("Helpful ...") would have the bot
// ignore the message, which is a property of the skip list and not of the
// mapping these tests are about.
func tcgplayerLinkFor(co *mtgmatcher.CardObject) string {
	id := co.Identifiers["tcgplayerProductId"]
	if co.Etched {
		id = co.Identifiers["tcgplayerEtchedProductId"]
	}
	if id == "" {
		return ""
	}
	link := "https://www.tcgplayer.com/product/" + id + "/magic-product"
	if co.Foil {
		link += "?Printing=Foil"
	}
	return link
}

// A store link the bot answers has to name the printing it points at, or name
// nothing: the website link built from it is the reader's next click, and one
// that lands on a different card is worse than one that is not offered.
//
// The fixtures are built from the datastore rather than written down, so the
// test asks the question for whatever cards this datastore holds instead of
// going stale against a set it no longer carries.
func TestCheckForLinksResolvesTheProductItNames(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	uuids := backend().GetUUIDs()
	step := len(uuids) / 400
	if step < 1 {
		step = 1
	}

	var checkedTCG, checkedMP int
	for i := 0; i < len(uuids); i += step {
		co, err := backend().GetUUID(uuids[i])
		if err != nil || co.Sealed {
			continue
		}

		if link := tcgplayerLinkFor(co); link != "" {
			checkedTCG++
			_, _, got := checkForLinks(discordGuildID(), "look at "+link)
			if got == nil {
				t.Errorf("%s %s #%s: %s named no printing", co.Name, co.SetCode, co.Number, link)
			} else if got.UUID != co.UUID {
				t.Errorf("%s named %s %s #%s (%s), want %s %s #%s (%s)",
					link, got.Name, got.SetCode, got.Number, got.UUID,
					co.Name, co.SetCode, co.Number, co.UUID)
			}
		}

		// Mana Pool files a card under its set and its number as printed,
		// and names the finish in the query rather than in the path.
		if co.Number != "" {
			finish := "nonfoil"
			if co.Etched {
				finish = "etched"
			} else if co.Foil {
				finish = "foil"
			}
			link := fmt.Sprintf("https://manapool.com/card/%s/%s/a-card?conditions=NM&finish=%s",
				strings.ToLower(co.SetCode), strings.ToLower(co.Number), finish)
			checkedMP++
			_, _, got := checkForLinks(discordGuildID(), link)
			if got == nil {
				// A number two cards answer to names neither of them. Magic
				// files one name per number, so this does not fire here; it
				// keeps the test honest against a datastore for a game that
				// does - see openingName in redirect.go.
				if openingName(printingsAt(co.SetCode, co.Number)) == "" {
					continue
				}
				t.Errorf("%s %s #%s: %s named no printing", co.Name, co.SetCode, co.Number, link)
			} else if got.UUID != co.UUID {
				t.Errorf("%s named %s %s #%s (%s), want %s %s #%s (%s)",
					link, got.Name, got.SetCode, got.Number, got.UUID,
					co.Name, co.SetCode, co.Number, co.UUID)
			}
		}
	}

	if checkedTCG == 0 || checkedMP == 0 {
		t.Fatalf("nothing was checked: %d tcgplayer, %d mana pool", checkedTCG, checkedMP)
	}
}

// A finish the printing was never sold in is answered with nothing, not with
// the finish the set happens to file first. Mana Pool priced one row; the
// other is a different card at a different price, and offering it would be
// the wrong-card mistake wearing the right name.
func TestManaPoolFinishItDoesNotSellNamesNothing(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	var checked int
	for _, uuid := range backend().GetUUIDs() {
		co, err := backend().GetUUID(uuid)
		if err != nil || co.Sealed || co.Number == "" || co.Etched {
			continue
		}
		if backend().FinishUUID(&co.Card, "etched") != "" {
			continue
		}

		link := fmt.Sprintf("https://manapool.com/card/%s/%s/a-card?finish=etched",
			strings.ToLower(co.SetCode), strings.ToLower(co.Number))
		if _, _, got := checkForLinks(discordGuildID(), link); got != nil {
			t.Errorf("%s %s #%s is not sold etched, yet %s named %s (etched=%v)",
				co.Name, co.SetCode, co.Number, link, got.UUID, got.Etched)
		}

		checked++
		if checked >= 50 {
			break
		}
	}

	if checked == 0 {
		t.Skip("every printing in this datastore is sold etched")
	}
}

// An etched product is one TCGplayer sells under an id of its own while its
// page still says Printing=Foil, so reading the finish off the URL lands on
// the plain foil wherever the printing has one. Reading it off the id does
// not, and this is the whole population rather than a sample: the one card
// that still misses is a printing this datastore holds no etched sibling for,
// which no finish flag can conjure.
func TestTCGplayerEtchedIDNamesTheEtchedPrinting(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	var checked, missed int
	for id, uuid := range backend().ExternalIdentifiers[mtgmatcher.IDSpaceTCGplayer] {
		base, err := backend().GetUUID(uuid)
		if err != nil || base.Identifiers["tcgplayerEtchedProductId"] != id {
			continue
		}
		checked++

		// The finish the page would carry, which is the misleading half.
		link, err := url.Parse("https://www.tcgplayer.com/product/" + id + "/magic-product?Printing=Foil")
		if err != nil {
			t.Fatalf("parsing the link for %s: %v", id, err)
		}
		co := tcgplayerCard(link)
		if co == nil {
			t.Errorf("etched product %s named no printing", id)
			continue
		}
		if !co.Etched {
			missed++
			if missed < 4 {
				t.Logf("etched product %s names %s %s #%s, which is not etched (it has no etched sibling here: %v)",
					id, co.Name, co.SetCode, co.Number, backend().FinishUUID(&co.Card, "etched") == "")
			}
		}
	}

	if checked == 0 {
		t.Skip("this datastore files no etched products")
	}
	// One card over 1,219 ids as measured on the September datastore. A
	// regression here is a resolver reading the URL again, which moves this
	// into the hundreds, not a datastore gaining one more odd printing.
	if missed > checked/100 {
		t.Errorf("%d of %d etched products name a printing that is not etched", missed, checked)
	}
}

// A store whose links carry no identifier of ours is answered with the
// affiliate link alone. The website link is the part that needs one, and
// guessing it is the mistake this pins shut.
//
// Cool Stuff Inc is the fixture that matters: its addresses are /p/<id> with
// an id of its own (coolstuffinc.go:653), so a resolver that reads "the first
// whole number in the path" the way the TCGplayer one does would answer with
// whatever card TCGplayer happens to file under that number. The number here
// is a real TCGplayer product id, so that mistake cannot pass quietly.
func TestCheckForLinksNamesNothingItCannotResolve(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	for _, tt := range []struct{ name, message string }{
		{"card kingdom", "https://www.cardkingdom.com/mtg/revised-edition/goblin-king"},
		{"card kingdom buylist", "https://www.cardkingdom.com/purchasing/mtg_singles?filter[name]=Goblin+King"},
		{"cool stuff inc", "https://www.coolstuffinc.com/p/1435"},
		{"star city games", "https://starcitygames.com/goblin-king-sgl-mtg-3ed-en/"},
		{"cardtrader", "https://www.cardtrader.com/cards/goblin-king"},
		{"amazon", "https://www.amazon.com/dp/B0123456"},
		{"a tcgplayer product this datastore does not hold", "https://www.tcgplayer.com/product/999999999/magic-product"},
		{"a mana pool set this datastore does not hold", "https://manapool.com/card/zzz/1/a-card"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			title, link, co := checkForLinks(discordGuildID(), tt.message)
			if title == "" || link == "" {
				t.Fatalf("the affiliate link itself went missing: title=%q link=%q", title, link)
			}
			if co != nil {
				t.Errorf("named %s %s #%s, want nothing", co.Name, co.SetCode, co.Number)
			}
		})
	}
}

// The bot speaks for one guild and one game. Everything below rides on
// checkForLinks, so these are the gates that keep it off every other server.
func TestCheckForLinksStaysOnItsOwnGuildAndGame(t *testing.T) {
	message := "https://www.tcgplayer.com/product/1435/magic-product"

	title, link, co := checkForLinks("some-other-guild", message)
	if title != "" || link != "" || co != nil {
		t.Errorf("another guild was answered: %q %q %v", title, link, co)
	}

	previous := Config.Game
	Config.Game = "lorcana"
	defer func() { Config.Game = previous }()

	title, link, co = checkForLinks(discordGuildID(), message)
	if title != "" || link != "" || co != nil {
		t.Errorf("another game was answered: %q %q %v", title, link, co)
	}
}

// The website link is the one the bot has always built for a card lookup, so
// it goes to the page that answers for the product's kind and keeps the tags
// that attribute the visit back to the bot.
func TestBanSearchLinkAddressesThePrinting(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	single, err := backend().GetUUID(randomUUID(false))
	if err != nil {
		t.Fatalf("a single: %v", err)
	}
	sealed, err := backend().GetUUID(randomUUID(true))
	if err != nil {
		t.Fatalf("a sealed product: %v", err)
	}

	for _, tt := range []struct {
		co   *mtgmatcher.CardObject
		page string
	}{
		{single, "https://www.mtgban.com/search"},
		{sealed, "https://www.mtgban.com/sealed"},
	} {
		link := banSearchLink(tt.co, "1234")
		if !strings.HasPrefix(link, tt.page+"?") {
			t.Errorf("%s links to %q, want the %s page", tt.co.Name, link, tt.page)
			continue
		}

		parsed, err := url.Parse(link)
		if err != nil {
			t.Errorf("parsing %q: %v", link, err)
			continue
		}
		v := parsed.Query()
		if got := v.Get("q"); got != tt.co.UUID {
			t.Errorf("%s asks %q, want %q", tt.co.Name, got, tt.co.UUID)
		}
		if got := v.Get("utm_source"); got != "banbot" {
			t.Errorf("%s is attributed to %q, want %q", tt.co.Name, got, "banbot")
		}
		if got := v.Get("utm_affiliate"); got != "1234" {
			t.Errorf("%s names guild %q, want %q", tt.co.Name, got, "1234")
		}
	}
}

// The link has to find the printing it was made for, the way the site's own
// links are held to it. A uuid query is answered by searchAndFilter directly,
// so this asks the search the same question the reader's click does.
func TestBanSearchLinkFindsItsPrinting(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	uuids := backend().GetUUIDs()
	step := len(uuids) / 100
	if step < 1 {
		step = 1
	}

	var checked, missed int
	for i := 0; i < len(uuids); i += step {
		co, err := backend().GetUUID(uuids[i])
		if err != nil {
			continue
		}
		checked++

		parsed, err := url.Parse(banSearchLink(co, "1234"))
		if err != nil {
			t.Fatalf("parsing the link for %s: %v", co.Name, err)
		}
		query := parsed.Query().Get("q")
		keys, err := searchAndFilter(parseSearchOptionsNG(query, nil, nil, nil))
		if err != nil {
			t.Errorf("%s %s #%s: %v", co.Name, co.SetCode, co.Number, err)
			continue
		}

		var found bool
		for _, key := range keys {
			if key == co.UUID {
				found = true
				break
			}
		}
		if !found {
			missed++
			if missed < 6 {
				t.Errorf("the bot's link for %s %s #%s asks %q and does not find it (%d results)",
					co.Name, co.SetCode, co.Number, query, len(keys))
			}
		}
	}

	if checked == 0 {
		t.Fatal("no cards were checked")
	}
	if missed != 0 {
		t.Errorf("%d of %d links miss the printing they point at", missed, checked)
	}
}
