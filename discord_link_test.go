package main

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/bwmarrin/discordgo"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// offeredPrinting is the printing a reply offers on this site: the uuid its
// second line asks for, or "" where it offered none. Reading it back out of
// the rendered description rather than off an intermediate is the point - it
// is the address the reader's click actually goes to.
func offeredPrinting(t *testing.T, reply *discordgo.MessageEmbed) string {
	t.Helper()
	if reply == nil {
		return ""
	}

	offer := offeredLinkRE.FindStringSubmatch(reply.Description)
	if offer == nil {
		return ""
	}
	parsed, err := url.Parse(offer[1])
	if err != nil {
		t.Fatalf("the offer in %q is not a URL: %v", reply.Description, err)
	}
	return parsed.Query().Get("q")
}

// offeredLinkRE picks the markdown link out of a reply's second line.
var offeredLinkRE = regexp.MustCompile(`\]\((https://[^)]+)\)`)

// tcgplayerProductIDOf is the id TCGplayer files a printing under: the etched
// product where the printing is etched, the plain one otherwise. The two are
// one id space, which is what lets a single lookup answer either.
func tcgplayerProductIDOf(co *mtgmatcher.CardObject) string {
	if co.Etched {
		return co.Identifiers["tcgplayerEtchedProductId"]
	}
	return co.Identifiers["tcgplayerProductId"]
}

// tcgplayerLinkFor spells the address TCGplayer files a printing under, the
// way a reader pastes it: the product id, and the Printing parameter the page
// carries for a foil. The slug is deliberately not the card's name - a name
// holding one of the store's Skip words ("Helpful ...") would have the bot
// ignore the message, which is a property of the skip list and not of the
// mapping these tests are about.
func tcgplayerLinkFor(co *mtgmatcher.CardObject) string {
	id := tcgplayerProductIDOf(co)
	if id == "" {
		return ""
	}
	link := "https://www.tcgplayer.com/product/" + id + "/magic-product"
	if co.Foil {
		link += "?Printing=Foil"
	}
	return link
}

// tcgplayerSharedProductIDs are the ids more than one printing answers to, so
// no lookup can tell which of them a link meant. TCGplayer sells a Secret
// Lair's English and Japanese printings as one product - SLD #1112 and
// #1112jpn both file under 450544 - and a handful of dagger variants the same
// way. mtgmatcher keeps the first filer and drops the rest, deterministically,
// so the answer is a real printing of the right card under the right name; it
// just is not always the one a caller started from.
func tcgplayerSharedProductIDs() map[string]bool {
	printings := map[string]map[string]bool{}
	for _, uuid := range backend().GetUUIDs() {
		co, err := backend().GetUUID(uuid)
		if err != nil {
			continue
		}
		id := tcgplayerProductIDOf(co)
		if id == "" {
			continue
		}
		if printings[id] == nil {
			printings[id] = map[string]bool{}
		}
		printings[id][co.SetCode+" "+co.Number] = true
	}

	shared := map[string]bool{}
	for id, under := range printings {
		if len(under) > 1 {
			shared[id] = true
		}
	}
	return shared
}

// A store link the bot answers has to name the printing it points at, or name
// nothing: the website link built from it is the reader's next click, and one
// that lands on a different card is worse than one that is not offered.
//
// The fixtures are built from the datastore rather than written down, so the
// test asks the question for whatever cards this datastore holds instead of
// going stale against a set it no longer carries. Every printing is asked,
// not a sample: a wrong answer is one card, and a sample that misses it
// reads exactly like a population that does not hold it. Some 300k lookups,
// about three seconds beside the datastore's own load.
func TestCheckForLinksResolvesTheProductItNames(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	shared := tcgplayerSharedProductIDs()

	var checkedTCG, checkedMP, sharedTCG int
	for _, uuid := range backend().GetUUIDs() {
		co, err := backend().GetUUID(uuid)
		if err != nil || co.Sealed {
			continue
		}

		if link := tcgplayerLinkFor(co); link != "" {
			// An id several printings answer to cannot name one of them, so
			// asking it to would be testing the datastore's filing order.
			if shared[tcgplayerProductIDOf(co)] {
				sharedTCG++
			} else {
				checkedTCG++
				got := offeredPrinting(t, checkForLinks(backend(), discordGuildID(), "look at "+link))
				if got == "" {
					t.Errorf("%s %s #%s: %s offered no printing", co.Name, co.SetCode, co.Number, link)
				} else if got != co.UUID {
					t.Errorf("%s offers %s, want %s %s #%s (%s)",
						link, got, co.Name, co.SetCode, co.Number, co.UUID)
				}
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
			reply := checkForLinks(backend(), discordGuildID(), link)
			got := offeredPrinting(t, reply)
			title := printingTitle(co) + " at Manapool"
			if got == "" {
				// A number two cards answer to names neither of them. Magic
				// files one name per number, so this does not fire here; it
				// keeps the test honest against a datastore for a game that
				// does - see openingName in redirect.go.
				if openingName(printingsAt(backend(), co.SetCode, co.Number)) == "" {
					continue
				}
				t.Errorf("%s %s #%s: %s offered no printing", co.Name, co.SetCode, co.Number, link)
			} else if got != co.UUID {
				t.Errorf("%s offers %s, want %s %s #%s (%s)",
					link, got, co.Name, co.SetCode, co.Number, co.UUID)
			} else if !strings.HasSuffix(reply.Title, title) {
				// The tail is no name, so a title read off the URL says
				// "A Card".
				t.Errorf("%s is titled %q, want %q", link, reply.Title, title)
			}
		}
	}

	if checkedTCG == 0 || checkedMP == 0 {
		t.Fatalf("nothing was checked: %d tcgplayer, %d mana pool", checkedTCG, checkedMP)
	}
	t.Logf("%d tcgplayer printings, %d mana pool; %d printings share a product id with another and were not asked",
		checkedTCG, checkedMP, sharedTCG)

	// The shared ids are a property of how TCGplayer sells Secret Lairs, not
	// of this code, but a jump would mean the id space had stopped naming one
	// printing - which is the assumption the link rests on. 2,543 of 150,619
	// printings, 1.7%, on the September datastore; this fires at 3%.
	if sharedTCG*100 > (checkedTCG+sharedTCG)*3 {
		t.Errorf("%d of %d printings share a product id, well past the 1.7%% this datastore has carried",
			sharedTCG, checkedTCG+sharedTCG)
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
		if got := offeredPrinting(t, checkForLinks(backend(), discordGuildID(), link)); got != "" {
			t.Errorf("%s %s #%s is not sold etched, yet %s offers %s",
				co.Name, co.SetCode, co.Number, link, got)
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
		co := tcgplayerCard(backend(), link)
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
		{"a mana pool card across every set", "https://manapool.com/card/caravan-vigil"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reply := checkForLinks(backend(), discordGuildID(), tt.message)
			if reply == nil {
				t.Fatal("the store's own link went unanswered")
			}
			if reply.Title == "" || reply.URL == "" {
				t.Fatalf("the affiliate link itself went missing: title=%q url=%q", reply.Title, reply.URL)
			}
			if got := offeredPrinting(t, reply); got != "" {
				t.Errorf("offered %s, want nothing", got)
			}
		})
	}
}

// The bot speaks for one guild and one game. Everything below rides on
// checkForLinks, so these are the gates that keep it off every other server.
func TestCheckForLinksStaysOnItsOwnGuildAndGame(t *testing.T) {
	message := "https://www.tcgplayer.com/product/1435/magic-product"

	if reply := checkForLinks(backend(), "some-other-guild", message); reply != nil {
		t.Errorf("another guild was answered: %q", reply.Title)
	}

	previous := Config.Game
	Config.Game = "lorcana"
	defer func() { Config.Game = previous }()

	if reply := checkForLinks(backend(), discordGuildID(), message); reply != nil {
		t.Errorf("another game was answered: %q", reply.Title)
	}
}

// The website link is the one the bot has always built for a card lookup, so
// it goes to the page that answers for the product's kind and keeps the tags
// that attribute the visit back to the bot.
func TestBanSearchLinkAddressesThePrinting(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	single, err := backend().GetUUID(randomUUID(backend(), false))
	if err != nil {
		t.Fatalf("a single: %v", err)
	}
	sealed, err := backend().GetUUID(randomUUID(backend(), true))
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

// The reply's wording is what the reader actually sees, and it is the one
// part of this that a live Discord session would otherwise be the first to
// render. A store link that named no printing has to read exactly as it did
// before any of this existed.
func TestStoreLinkDescriptionOffersOnlyWhatItResolved(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	const affiliateLine = "Support **MTGBAN** by using this link"

	if got := storeLinkDescription(nil, "1234"); got != affiliateLine {
		t.Errorf("a link that named nothing reads %q, want %q", got, affiliateLine)
	}

	single, err := backend().GetUUID(randomUUID(backend(), false))
	if err != nil {
		t.Fatalf("a single: %v", err)
	}
	sealed, err := backend().GetUUID(randomUUID(backend(), true))
	if err != nil {
		t.Fatalf("a sealed product: %v", err)
	}

	for _, tt := range []struct {
		name string
		co   *mtgmatcher.CardObject
		want string
	}{
		{"a card", single, "[Check the card on our website too](" + banSearchLink(single, "1234") + ")"},
		{"a sealed product", sealed, "[Check the product on our website too](" + banSearchLink(sealed, "1234") + ")"},
	} {
		got := storeLinkDescription(tt.co, "1234")
		if !strings.HasPrefix(got, affiliateLine+"\n") {
			t.Errorf("%s dropped the affiliate line: %q", tt.name, got)
		}
		if !strings.HasSuffix(got, tt.want) {
			t.Errorf("%s offers %q, want it to end with %q", tt.name, got, tt.want)
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
		keys, err := searchAndFilter(currentDatastore(), parseSearchOptionsNG(backend(), query, nil, nil, nil))
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
