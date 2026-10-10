package main

import (
	"regexp"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// listInputs are the hidden inputs a load form sends a whole list in.
var listInputs = regexp.MustCompile(`<input type="hidden" name="(?:c|sList|deck|json)"[^>]*>`)

// Every list a load button sends on the upload and arbit pages is one
// js/load-lists.js can rebuild from the rows left ticked: each names its
// format, and each row its place in the lists.
func TestLoadListsAreMarked(t *testing.T) {
	stubCartStores(t)
	entries := []OptimizedUploadEntry{{CardID: "card-a", Quantity: 2}}
	arbit := []mtgban.ArbitEntry{{
		CardID:         "card-a",
		InventoryEntry: mtgban.InventoryEntry{Conditions: mtgban.NM, Price: 1},
		Quantity:       2,
	}}

	upload := func(buylist bool, keys ...string) string {
		optimized := map[string][]OptimizedUploadEntry{}
		totals := map[string]float64{}
		for _, key := range keys {
			optimized[key] = entries
			totals[key] = 1
		}
		return renderUpload(t, PageVars{UploadVars: UploadVars{
			IsBuylist:       buylist,
			Optimized:       optimized,
			OptimizedKeys:   keys,
			OptimizedTotals: totals,
		}})
	}

	type page struct {
		out     string
		formats []string
	}
	pages := map[string]page{
		"upload retail":  {upload(false, "CK", "CSI", "TCGPlayer", "MP", "ABUScans"), []string{"ck", "csi", "tcg", "manapool", "cart"}},
		"upload buylist": {upload(true, "CK", "ABUGames"), []string{"ckbuylist", "cart"}},
	}
	for _, source := range []string{"CK", "CSI", "TCGPlayer", "MP", "ABUScans"} {
		out := renderArbit(t, PageVars{
			ScraperShort: source,
			UserNav:      &NavElem{Short: "beta"},
			Arb:          []Arbitrage{{Name: "CK", Key: "CK", Arbit: arbit}, {Name: "CSI", Key: "CSI", Arbit: arbit}},
		})
		pages["arbit "+source] = page{out: out}
	}

	var arbitAll strings.Builder
	for name, p := range pages {
		for _, input := range listInputs.FindAllString(p.out, -1) {
			if !strings.Contains(input, `data-load-list="`) {
				t.Errorf("%s: a list names no format: %s", name, input)
			}
		}
		for _, format := range p.formats {
			if !strings.Contains(p.out, `data-load-list="`+format+`"`) {
				t.Errorf("%s: no %s list", name, format)
			}
		}
		if !strings.Contains(p.out, `data-load-idx="0"`) {
			t.Errorf("%s: its rows carry no place in the lists", name)
		}
		if strings.HasPrefix(name, "arbit") {
			arbitAll.WriteString(p.out)
		}
	}
	for _, format := range []string{"ck", "csi", "tcg", "manapool", "ckbuylist", "cart"} {
		if !strings.Contains(arbitAll.String(), `data-load-list="`+format+`"`) {
			t.Errorf("arbit: no %s list", format)
		}
	}
	if !strings.Contains(arbitAll.String(), `data-load-items="301"`) {
		t.Error("arbit: a cart button carries no item ids")
	}
}
