package main

import (
	"net/url"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// linkQuery is the query an internal card link asks.
func linkQuery(t *testing.T, link string) string {
	t.Helper()
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parsing %q: %v", link, err)
	}
	return parsed.Query().Get("q")
}

// The link on a page has to find the printing it was made for. A number
// carrying a language or variant suffix - 59ita, 349alt, 1110jpn - once went
// out as cn:, which reads the number without it, and the link came back empty.
func TestCardLinkResolvesToItsPrinting(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	uuids := mtgmatcher.GetUUIDs()
	step := len(uuids) / 300
	if step < 1 {
		step = 1
	}

	var checked, missed int
	for i := 0; i < len(uuids); i += step {
		co, err := mtgmatcher.GetUUID(uuids[i])
		if err != nil || co.Sealed {
			continue
		}
		checked++

		card := uuid2card(uuids[i], true, false, false)
		query := linkQuery(t, card.SearchURL)
		keys, err := searchAndFilter(parseSearchOptionsNG(query, nil, nil, nil))
		if err != nil {
			t.Errorf("%s #%s: %v", co.SetCode, co.Number, err)
			continue
		}

		var found bool
		for _, key := range keys {
			if key == uuids[i] {
				found = true
				break
			}
		}
		if !found {
			missed++
			if missed < 6 {
				t.Errorf("the link for %s %s #%s asks %q and does not find it (%d results)",
					co.Name, co.SetCode, co.Number, query, len(keys))
			}
		}
	}

	if checked == 0 {
		t.Fatal("no cards were checked")
	}
	if missed != 0 {
		t.Errorf("%d of %d links miss the card they point at", missed, checked)
	}
}

// The link is the printing's own query, on the page that answers it: a card
// on the search, a product on the sealed page. No hop in between, so what the
// address bar shows after the click is what the link said.
func TestCardLinkIsThePrintingsQuery(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	var card, sealed string
	for _, uuid := range mtgmatcher.GetUUIDs() {
		co, err := mtgmatcher.GetUUID(uuid)
		if err != nil {
			continue
		}
		if co.Sealed {
			if sealed == "" {
				sealed = uuid
			}
		} else if card == "" {
			card = uuid
		}
		if card != "" && sealed != "" {
			break
		}
	}

	for _, tt := range []struct{ id, page string }{{card, "/search?q="}, {sealed, "/sealed?q="}} {
		if tt.id == "" {
			continue
		}
		co, _ := mtgmatcher.GetUUID(tt.id)
		want := tt.page + url.QueryEscape(genQuery(co))
		if got := uuid2card(tt.id, true, false, false).SearchURL; got != want {
			t.Errorf("%s links to %q, want %q", co.Name, got, want)
		}
	}
}
