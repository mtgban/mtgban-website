package offlineapi

import (
	"encoding/json"
	"hash/fnv"
	"strconv"
	"testing"
)

// The catalog used to be marshalled as one map and is now assembled from
// separately marshalled halves. The bytes have to come out the same, or
// every client re-downloads 12MB for a document that did not change.
func TestCatalogAssemblyMatchesWholeMarshal(t *testing.T) {
	cards := map[string]catalogCard{
		"uuid-b": {Name: "Beta", Number: "2", Rarity: "rare", SetCode: "AAA", Foil: true},
		"uuid-a": {Name: "Alpha", Number: "1", SetCode: "ZZZ", Products: []string{"p1", "p2"}},
		"uuid-c": {Name: "Gamma", Sealed: true, Image: "img"},
	}
	sets := map[string]catalogSet{
		"ZZZ": {Name: "Zed", Keyrune: "zzz", Date: "2020-01-01"},
		"AAA": {Name: "Ay"},
	}
	stores := map[string]catalogStore{
		"TCG": {Name: "TCGplayer", Country: "US", Buylist: true},
		"CK":  {Name: "Card Kingdom", Index: true},
	}

	// what the old code produced
	whole, err := json.Marshal(map[string]any{"sets": sets, "cards": cards, "stores": stores})
	if err != nil {
		t.Fatalf("marshal whole: %v", err)
	}

	// what the new code produces
	rawCards, err := json.Marshal(cards)
	if err != nil {
		t.Fatalf("marshal cards: %v", err)
	}
	rawSets, err := json.Marshal(sets)
	if err != nil {
		t.Fatalf("marshal sets: %v", err)
	}
	rawStores, err := json.Marshal(stores)
	if err != nil {
		t.Fatalf("marshal stores: %v", err)
	}
	var assembled []byte
	for _, part := range [][]byte{
		[]byte(`{"cards":`), rawCards,
		[]byte(`,"sets":`), rawSets,
		[]byte(`,"stores":`), rawStores,
		[]byte(`}`),
	} {
		assembled = append(assembled, part...)
	}

	if string(assembled) != string(whole) {
		t.Errorf("assembled document differs from the whole marshal:\n got %s\nwant %s", assembled, whole)
	}

	// and so the version derived from it is the same
	hw, ha := fnv.New64a(), fnv.New64a()
	hw.Write(whole)
	ha.Write(assembled)
	if strconv.FormatUint(ha.Sum64(), 16) != strconv.FormatUint(hw.Sum64(), 16) {
		t.Error("version differs between the two forms")
	}
}

// An empty store list still has to produce the same document as before,
// since a site whose scrapers have not landed serves the catalog anyway.
func TestCatalogAssemblyWithNoStores(t *testing.T) {
	cards := map[string]catalogCard{"u": {Name: "One"}}
	sets := map[string]catalogSet{"S": {Name: "Set"}}
	stores := map[string]catalogStore{}

	whole, _ := json.Marshal(map[string]any{"sets": sets, "cards": cards, "stores": stores})
	rawCards, _ := json.Marshal(cards)
	rawSets, _ := json.Marshal(sets)
	rawStores, _ := json.Marshal(stores)

	assembled := string(`{"cards":`) + string(rawCards) + `,"sets":` + string(rawSets) + `,"stores":` + string(rawStores) + `}`
	if assembled != string(whole) {
		t.Errorf("got %s, want %s", assembled, whole)
	}
}
