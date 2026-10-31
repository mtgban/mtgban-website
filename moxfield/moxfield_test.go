package moxfield

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
)

// A deck entry aggregates all copies of a card under one representative
// printing; the real per-copy breakdown arrives in printingData and must
// expand to one item per printing (the source of "the uploader lumps my
// land variations together").
func TestPrepareDecklistExpandsPrintings(t *testing.T) {
	blob := `{"name":"Galaxy Lands","boards":{"mainboard":{"count":8,"cards":{
		"aaa":{"quantity":7,"finish":"nonFoil","card":{"scryfall_id":"scry-island","name":"Island"},
			"printingData":[
				{"quantity":2,"finish":"nonFoil","set":"unf","cn":"236"},
				{"quantity":2,"finish":"foil","set":"unf","cn":"236"},
				{"quantity":2,"finish":"foil","set":"unf","cn":"487"},
				{"quantity":1,"finish":"foil","set":"unf","cn":"492"}]},
		"bbb":{"quantity":1,"finish":"foil","card":{"scryfall_id":"scry-swamp","name":"Swamp"}}
	}}}}`

	var deck Deck
	if err := json.Unmarshal([]byte(blob), &deck); err != nil {
		t.Fatal(err)
	}
	if deck.Name != "Galaxy Lands" {
		t.Errorf("deck name = %q, want Galaxy Lands", deck.Name)
	}

	items := prepareDecklist(&deck, 100)
	if len(items) != 5 {
		t.Fatalf("items = %d, want 5 (4 printings + 1 without breakdown)", len(items))
	}

	var galaxy, nonfoil, fallback *Item
	for i := range items {
		switch {
		case items[i].Number == "487":
			galaxy = &items[i]
		case items[i].Number == "236" && !items[i].IsFoil:
			nonfoil = &items[i]
		case items[i].ScryfallID == "scry-swamp":
			fallback = &items[i]
		}
	}

	if galaxy == nil || galaxy.Name != "Island" || galaxy.SetCode != "unf" ||
		!galaxy.IsFoil || galaxy.Quantity != 2 || galaxy.ScryfallID != "" {
		t.Errorf("galaxy printing item wrong: %+v", galaxy)
	}
	if nonfoil == nil || nonfoil.Quantity != 2 {
		t.Errorf("nonfoil printing item wrong: %+v", nonfoil)
	}
	if fallback == nil || !fallback.IsFoil || fallback.Quantity != 1 {
		t.Errorf("entry without printingData should fall back to the representative printing: %+v", fallback)
	}
}

// The cap counts the items produced, not the deck entries: one entry with a
// per-copy breakdown yields an item per printing, and a deck of such entries
// must still stop at maxRows, as the CSV and sheet uploads do.
func TestPrepareDecklistCapsProducedRows(t *testing.T) {
	for _, tc := range []struct {
		blob    string
		maxRows int
	}{
		// The fuzz seed: one card, three printings, a cap of one
		{`{"boards":{"main":{"cards":{"a":{"printingData":[{"set":"a","cn":"1"},{"set":"b","cn":"2"},{"set":"c","cn":"3"}]}}}}}`, 1},
		{`{"boards":{"main":{"cards":{
			"a":{"printingData":[{"set":"a","cn":"1"},{"set":"a","cn":"2"},{"set":"a","cn":"3"}]},
			"b":{"printingData":[{"set":"b","cn":"1"},{"set":"b","cn":"2"},{"set":"b","cn":"3"}]}}},
			"side":{"cards":{"c":{"quantity":1,"card":{"scryfall_id":"x"}},"d":{"quantity":1,"card":{"scryfall_id":"y"}}}}}}`, 4},
	} {
		var deck Deck
		if err := json.Unmarshal([]byte(tc.blob), &deck); err != nil {
			t.Fatal(err)
		}
		if items := prepareDecklist(&deck, tc.maxRows); len(items) != tc.maxRows {
			t.Errorf("prepareDecklist(maxRows %d) = %d items, want %d", tc.maxRows, len(items), tc.maxRows)
		}
	}
}

// Boards and cards are maps, so which items survive the cap must not depend
// on iteration order: the same deck keeps the same items every time.
func TestPrepareDecklistCapIsDeterministic(t *testing.T) {
	blob := `{"boards":{"main":{"cards":{
		"a":{"printingData":[{"set":"a","cn":"1"},{"set":"a","cn":"2"},{"set":"a","cn":"3"}]},
		"b":{"printingData":[{"set":"b","cn":"1"},{"set":"b","cn":"2"}]},
		"x":{"printingData":[{"set":"a","cn":"1","quantity":5}]},
		"c":{"quantity":1,"card":{"scryfall_id":"c"}},
		"d":{"quantity":1,"card":{"scryfall_id":"d"}},
		"e":{"quantity":1,"card":{"scryfall_id":"e"}}}},
		"side":{"cards":{"f":{"quantity":1,"card":{"scryfall_id":"f"}},"g":{"quantity":1,"card":{"scryfall_id":"g"}}}}}}`
	var deck Deck
	if err := json.Unmarshal([]byte(blob), &deck); err != nil {
		t.Fatal(err)
	}

	first := prepareDecklist(&deck, 3)
	for range 50 {
		got := prepareDecklist(&deck, 3)
		if !slices.Equal(got, first) {
			t.Fatalf("prepareDecklist kept %+v, then %+v", first, got)
		}
	}
}

func TestGetMoxDeckDecodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"name":"Breena"}`))
	}))
	defer srv.Close()

	deck, err := getMoxDeck(context.Background(), srv.URL)
	if err != nil || deck.Name != "Breena" {
		t.Fatalf("got %+v, %v, want Breena", deck, err)
	}
}

// A vendor that sends its headers and then stalls mid-body is cut off by
// the client's timeout, not left holding the upload.
func TestGetMoxDeckStalledBodyTimesOut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"name":`))
		err := http.NewResponseController(w).Flush()
		if err != nil {
			t.Error(err)
		}
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer srv.Close()

	saved := client
	client = mtgban.NewHTTPClient(mtgban.WithHTTPTimeout(200*time.Millisecond), mtgban.WithHTTPRetries(0))
	t.Cleanup(func() { client = saved })

	start := time.Now()
	_, err := getMoxDeck(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("a stalled body decoded without error")
	}
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Fatalf("stalled body took %v to fail, want about the 200ms timeout", elapsed)
	}
}

func TestGetMoxDeckOversizeBodyErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"name":"` + strings.Repeat("a", maxBody) + `"}`))
	}))
	defer srv.Close()

	_, err := getMoxDeck(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("a body past maxBody decoded without error")
	}
}

// A 5xx is answered at once, with its status, and not retried.
func TestGetMoxDeckServerErrorIsNotRetried(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	_, err := getMoxDeck(context.Background(), srv.URL)
	if err == nil || err.Error() != "status code: 502" || hits != 1 {
		t.Fatalf("got %v after %d requests, want status code: 502 after 1", err, hits)
	}
}

// A collection whose every page answers well inside the client's timeout
// still stops at the one deadline the whole walk shares.
func TestCollectionWalkSharesOneDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("pageNumber") == "0" {
			w.Write([]byte(`{"totalResults":10000}`))
			return
		}
		time.Sleep(50 * time.Millisecond)
		w.Write([]byte(`{"data":[{"game":"arena"}]}`))
	}))
	defer srv.Close()

	saved := collectionTimeout
	collectionTimeout = 300 * time.Millisecond
	t.Cleanup(func() { collectionTimeout = saved })

	start := time.Now()
	_, err := getMoxCollection(context.Background(), srv.URL, 1000)
	if err == nil {
		t.Fatal("a 101-page walk finished inside a 300ms deadline")
	}
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Fatalf("walk took %v to fail, want about the 300ms deadline", elapsed)
	}
}
