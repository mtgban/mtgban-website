package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
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

	useDatastore(t, newDatastore(fixtureA, loadedA))
	assertDatastoreDescribesLoad(t, "FIXTUREA", "1", "fixture card alpha", loadedA)

	useDatastore(t, newDatastore(fixtureB, loadedB))
	assertDatastoreDescribesLoad(t, "FIXTUREB", "3", "fixture card beta", loadedB)
}

// assertDatastoreDescribesLoad checks that the backend, numbers, editions,
// names and the palette lists of the currently published datastore all
// resolve to the load named by setCode/number/namePrefix, rather than some
// other one.
func assertDatastoreDescribesLoad(t *testing.T, setCode, number, namePrefix string, loadedAt time.Time) {
	t.Helper()
	ds := currentDatastore()
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
	// GetSet/GetUUIDs directly - so a builder that reads the wrong backend
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
	codes = append(codes, editions.AllEditionsKeysNoFoilOrPromos...)
	if !slices.Equal(codes, slices.Repeat([]string{setCode}, 5)) || editions.TotalUnique != len(ds.backend.GetUUIDs()) {
		t.Errorf("editions: views name %v over %d printings, want only %q", codes, editions.TotalUnique, setCode)
	}

	matches := ds.names.matchesFor(namePrefix, false)
	if len(matches) == 0 {
		t.Errorf("names: %q did not match this load's own name", namePrefix)
	}

	// The fixture gives each load a promo type and a finish named after its
	// set, so each palette list has one entry that says which load it is.
	for _, list := range []struct {
		serve     func(http.ResponseWriter, *http.Request)
		key, want string
	}{
		{paletteService.Sets, "code", setCode},
		{paletteService.Promos, "value", strings.ToLower(setCode)},
		{paletteService.Finishes, "value", strings.ToLower(setCode)},
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

// TestEmptyDatastoreServesPaletteListsUncached pins what a request gets
// before the first load completes: every palette list empty and marked
// no-store, per emptyDatastore's nil palette snapshot.
func TestEmptyDatastoreServesPaletteListsUncached(t *testing.T) {
	useDatastore(t, nil)
	for _, serve := range []func(http.ResponseWriter, *http.Request){
		paletteService.Sets, paletteService.Promos, paletteService.Finishes,
	} {
		rec := httptest.NewRecorder()
		serve(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Header().Get("Cache-Control") != "no-store" || rec.Body.String() != "[]" {
			t.Errorf("before the first load a palette list answered %q, %s",
				rec.Header().Get("Cache-Control"), rec.Body.Bytes())
		}
	}
}
