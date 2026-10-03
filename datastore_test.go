package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"

	"github.com/mtgban/mtgban-website/internal/suggest"
)

// fixtureBackend builds a small in-memory Backend the way a game loader
// would: Sets and UUIDs filed directly, then indexed with the same exported
// builders a loader calls (IndexSets, IndexSetUUIDs, AddName). setCode must
// already be upper case, matching what GetSet looks up. Each cards entry is
// {name, number}; every card also carries a promo type and a finish named
// after the set, so the palette lists have something of this load's own.
func fixtureBackend(setCode, setName, releaseDate string, cards [][2]string) *mtgmatcher.Backend {
	b := &mtgmatcher.Backend{
		Sets:  map[string]*mtgmatcher.Set{},
		UUIDs: map[string]*mtgmatcher.CardObject{},
	}
	set := &mtgmatcher.Set{
		Code:          setCode,
		Name:          setName,
		ReleaseDate:   releaseDate,
		Type:          "expansion",
		SealedProduct: []mtgmatcher.SealedProduct{{UUID: setCode + "-box"}},
	}
	for _, nameNumber := range cards {
		name, number := nameNumber[0], nameNumber[1]
		card := mtgmatcher.Card{
			UUID:        setCode + "-" + number,
			Name:        name,
			Number:      number,
			PlainNumber: number,
			SetCode:     setCode,
			Finish:      strings.ToLower(setCode),
			PromoTypes:  []string{strings.ToLower(setCode)},
		}
		set.Cards = append(set.Cards, card)
		b.UUIDs[card.UUID] = &mtgmatcher.CardObject{Card: card}
		b.AllUUIDs = append(b.AllUUIDs, card.UUID)
		b.AddName(name)
	}
	b.Sets[setCode] = set
	b.AllSets = append(b.AllSets, setCode)
	b.AllPromoTypes = []string{strings.ToLower(setCode)}
	b.IndexSets()
	b.IndexSetUUIDs()
	return b
}

// TestDatastorePublishSwapsEverySnapshotAtOnce publishes two small, distinct
// fixture backends in turn and checks that every derived snapshot - numbers,
// editions, names and the palette lists - describes the same load as the
// backend and loadedAt after each publish. A builder that reads the live
// datastore instead of the b it was handed indexes the previous load
// instead; this test catches it.
func TestDatastorePublishSwapsEverySnapshotAtOnce(t *testing.T) {
	fixtureA := fixtureBackend("FIXTUREA", "Fixture Edition Alpha", "2020-01-01", [][2]string{
		{"Fixture Card Alpha", "1"},
		{"Fixture Card Alpha Two", "2"},
	})
	fixtureB := fixtureBackend("FIXTUREB", "Fixture Edition Beta", "2021-06-15", [][2]string{
		{"Fixture Card Beta", "3"},
		{"Fixture Card Beta Two", "4"},
	})
	loadedA := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	loadedB := time.Date(2021, 6, 15, 0, 0, 0, 0, time.UTC)

	// A private site, not testSite: publishing twice here must not leak
	// into any other test.
	s := newSite()
	s.ds.Store(s.newDatastore(fixtureA, loadedA))
	assertDatastoreDescribesLoad(t, s, "FIXTUREA", "1", "fixture card alpha", loadedA)

	s.ds.Store(s.newDatastore(fixtureB, loadedB))
	assertDatastoreDescribesLoad(t, s, "FIXTUREB", "3", "fixture card beta", loadedB)
}

// assertDatastoreDescribesLoad checks that the backend, numbers, editions,
// names and the palette lists of s's currently published datastore all
// resolve to the load named by setCode/number/namePrefix, rather than some
// other one.
func assertDatastoreDescribesLoad(t *testing.T, s *site, setCode, number, namePrefix string, loadedAt time.Time) {
	t.Helper()
	ds := s.datastore()
	wantUUID := setCode + "-" + number

	_, err := ds.backend.GetSet(setCode)
	if err != nil {
		t.Errorf("backend: GetSet(%q) = %v, want this load's own set", setCode, err)
	}

	uuids, ok := numberSeedUUIDs(ds.numbers, []FilterElem{{Name: "number", Values: []string{number}}})
	if !ok || !slices.Contains(uuids, wantUUID) {
		t.Errorf("numbers: seeding %q gave %v, want to find %q", number, uuids, wantUUID)
	}

	// Every edition view a load can appear in - getAllEditions,
	// getTreeEditions, getAllEditionsByCategory and getSealedEditions
	// each build their own, and newEditionsSnapshot itself reads
	// GetUUIDs directly - so a builder that reads the wrong backend
	// has nowhere to hide.
	editions := ds.editions
	var codes []string
	for _, entries := range [][]EditionEntry{
		{editions.AllEditionsMap[setCode]},
		editions.TreeEditionsMap[setCode],
		editions.AllEditionsByCategory["Expansions"],
		editions.SealedEditionsList["Expansions"],
	} {
		for _, entry := range entries {
			codes = append(codes, entry.Code)
		}
	}
	if !slices.Equal(codes, slices.Repeat([]string{setCode}, 4)) || editions.TotalUnique != len(ds.backend.GetUUIDs()) {
		t.Errorf("editions: views name %v over %d printings, want only %q", codes, editions.TotalUnique, setCode)
	}

	matches := ds.names.Matches(suggest.Fold(namePrefix), false)
	if len(matches) == 0 {
		t.Errorf("names: %q did not match this load's own name", namePrefix)
	}

	// The fixture gives each load a promo type and a finish named after its
	// set, so each palette list has one entry that says which load it is.
	for _, list := range []struct {
		serve     func(http.ResponseWriter, *http.Request)
		key, want string
	}{
		{s.palette.Sets, "code", setCode},
		{s.palette.Promos, "value", strings.ToLower(setCode)},
		{s.palette.Finishes, "value", strings.ToLower(setCode)},
	} {
		rec := httptest.NewRecorder()
		list.serve(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		var entries []map[string]any
		err = json.Unmarshal(rec.Body.Bytes(), &entries)
		if err != nil || len(entries) != 1 || entries[0][list.key] != list.want {
			t.Errorf("palette: listed %s, want only %q", rec.Body.Bytes(), list.want)
		}
	}

	if !ds.loadedAt.Equal(loadedAt) {
		t.Errorf("loadedAt = %v, want %v", ds.loadedAt, loadedAt)
	}
}

// A card row carries its own set symbol and TCG id in the page data it was
// given, so drawing it reads no datastore.
func TestCardRowKeepsItsDatastoreAcrossAReload(t *testing.T) {
	a := fixtureBackend("FIXTUREA", "Fixture Edition Alpha", "2020-01-01", [][2]string{{"Fixture Card Alpha", "1"}})
	a.Sets["FIXTUREA"].Symbol = "https://example.test/fixturea.webp"
	a.UUIDs["FIXTUREA-1"].Identifiers = map[string]string{"tcgplayerProductId": "4242"}
	card := uuid2card(a, "FIXTUREA-1", false)

	metadata := map[string]GenericCard{"FIXTUREA-1": card}
	search := PageVars{
		SearchVars: SearchVars{
			SearchRan:   true,
			AllKeys:     []string{"FIXTUREA-1"},
			SearchQuery: card.Name,
		},
		CardHashes: []string{"FIXTUREA-1"},
		Metadata:   metadata,
	}
	for _, page := range []string{"search.html", "mobile/search.html"} {
		if out := renderSearch(t, page, search); !strings.Contains(out, `src="https://example.test/fixturea.webp"`) {
			t.Errorf("%s: the row lost its set symbol to the datastore published after it was built", page)
		}
	}

	out := renderArbit(t, PageVars{ScraperShort: "TCGPlayer", UserNav: &NavElem{}, Metadata: metadata,
		Arb: []Arbitrage{{Name: "CK", Key: "CK", Arbit: []mtgban.ArbitEntry{{CardID: "FIXTUREA-1"}}}}})
	for _, want := range []string{`data-arb-tcgid="4242"`, `1-4242||`} {
		if !strings.Contains(out, want) {
			t.Errorf("arbit.html does not carry %s", want)
		}
	}
}

// TestEmptyDatastoreServesPaletteListsUncached pins what a request gets
// before the first load completes: a backend with no cards, and every
// palette list empty and marked no-store, per the pre-stored datastore's
// nil palette snapshot.
func TestEmptyDatastoreServesPaletteListsUncached(t *testing.T) {
	// A private site, not testSite: this wants the state before anything
	// has published, which testSite left behind in TestMain.
	s := newSite()
	cards := s.datastore().backend.GetUUIDs()
	if len(cards) != 0 {
		t.Errorf("before the first load the backend held %d cards", len(cards))
	}
	for _, serve := range []func(http.ResponseWriter, *http.Request){
		s.palette.Sets, s.palette.Promos, s.palette.Finishes,
	} {
		rec := httptest.NewRecorder()
		serve(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Header().Get("Cache-Control") != "no-store" || rec.Body.String() != "[]" {
			t.Errorf("before the first load a palette list answered %q, %s",
				rec.Header().Get("Cache-Control"), rec.Body.Bytes())
		}
	}
}
