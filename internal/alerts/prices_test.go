package alerts

import (
	"slices"
	"testing"
)

func TestBestStorePrice(t *testing.T) {
	buylist := []StorePrice{
		{Shorthand: "CK", Prices: map[string]float64{"NM": 12}},
		{Shorthand: "SCG", Prices: map[string]float64{"NM": 14}},
	}
	best, store, ok := bestStorePrice(buylist, SideBuylist, "NM", nil)
	if !ok || best != 14 || store != "SCG" {
		t.Fatalf("best buylist = %v %s %v", best, store, ok)
	}
	best, _, ok = bestStorePrice(buylist, SideBuylist, "NM", []string{"ck"})
	if !ok || best != 12 {
		t.Fatalf("scoped best = %v %v", best, ok)
	}
	_, _, ok = bestStorePrice(buylist, SideBuylist, "PO", nil)
	if ok {
		t.Fatal("no PO offer should report ok")
	}
	retail := []StorePrice{
		{Shorthand: "CK", Prices: map[string]float64{"NM": 20}},
		{Shorthand: "SCG", Prices: map[string]float64{"NM": 15}},
	}
	best, store, _ = bestStorePrice(retail, SideRetail, "NM", nil)
	if best != 15 || store != "SCG" {
		t.Fatalf("best retail = %v %s, want the lowest", best, store)
	}
}

func TestWithKeptStores(t *testing.T) {
	visible := []StorePrice{{Shorthand: "CK", Name: "Card Kingdom", Prices: map[string]float64{"NM": 12}}}
	label := func(s string) string { return "label-" + s }
	got := withKeptStores(visible, []string{"CK", "SCG"}, label)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Shorthand != "CK" || len(got[0].Prices) != 1 {
		t.Fatalf("existing store changed: %+v", got[0])
	}
	if got[1].Shorthand != "SCG" || got[1].Name != "label-SCG" || len(got[1].Prices) != 0 {
		t.Fatalf("kept store = %+v", got[1])
	}
}

func TestScopeStores(t *testing.T) {
	visible := []StorePrice{{Shorthand: "CK"}, {Shorthand: "SCG"}}
	got, err := scopeStores([]string{"ck", "SCG", "ck"}, visible)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	want := []string{"CK", "SCG"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	_, err = scopeStores([]string{"GONE"}, visible)
	if err == nil {
		t.Fatal("expected an error for an unknown store")
	}
}
