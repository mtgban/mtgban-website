package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// The arbitrage pages list sellers of slabs in a section of their own, after
// the sealed one, and their tables after the raw stores' tables, whatever
// the raw stores are called.
func TestArbitListsGradedStoresApart(t *testing.T) {
	withSigMode(t, true, false)
	store := func(name, shorthand string, price float64, info mtgban.ScraperInfo) mtgban.Seller {
		inv := mtgban.InventoryRecord{}
		if price > 0 {
			inv["FIXTUREA-1"] = []mtgban.InventoryEntry{{Conditions: "NM", Price: price, Quantity: 1}}
		}
		info.Name, info.Shorthand = name, shorthand
		return mtgban.NewSellerFromInventory(inv, info)
	}
	// The slab seller loads first, so only the page puts it last
	s := fixtureSite(t, fixtureBackend("FIXTUREA", "Fixture Edition Alpha", "2020-01-01", [][2]string{{"Fixture Card Alpha", "1"}}), []mtgban.Seller{
		store("Slab Shop", "ZZSLAB", 900, mtgban.ScraperInfo{GradedMode: true}),
		store("Raw Shop", "ZZRAW", 100, mtgban.ScraperInfo{}),
		store("Other Raw", "ZZOTHER", 300, mtgban.ScraperInfo{}),
		store("Graded Goods", "ZZGOODS", 0, mtgban.ScraperInfo{}),
		store("Box Shop", "ZZBOX", 0, mtgban.ScraperInfo{SealedMode: true}),
	}, nil)
	allow := []string{"ZZSLAB", "ZZRAW", "ZZOTHER", "ZZGOODS", "ZZBOX"}
	render := func(path string, pageVars PageVars) string {
		rec := httptest.NewRecorder()
		pageVars.UserNav = &NavElem{Short: "beta"}
		s.scraperCompare(rec, httptest.NewRequest(http.MethodGet, path, nil), s.prices(), pageVars, allow, nil, scraperCompareOpts{AllResults: true, AnySpread: true})
		return rec.Body.String()
	}
	inOrder := func(page, where string, parts ...string) {
		t.Helper()
		at := 0
		for _, part := range parts {
			i := strings.Index(page[at:], part)
			if i < 0 {
				t.Errorf("%s: no %s after %s", where, part, page[:at][max(0, at-40):])
				return
			}
			at += i + len(part)
		}
	}
	sep := "<option disabled>──────────</option>"

	landing := render("/arbit", PageVars{})
	inOrder(landing, "landing", "Select Store", "Graded Goods", "Other Raw", "Raw Shop", "Sealed Products", "Box Shop Sealed", "Graded Cards", "Slab Shop (Graded)")
	if strings.Count(landing, "Slab Shop (Graded)") != 1 {
		t.Error("landing: the slab seller is listed with the raw stores too")
	}

	page := render("/global?source=ZZRAW&legit=0", PageVars{ArbitVars: ArbitVars{GlobalMode: true}})
	inOrder(page, "store picker", `data-pick="store"`, ">Graded Goods</option>", ">Other Raw</option>", ">Raw Shop</option>", sep, ">Box Shop Sealed</option>", sep, ">Slab Shop (Graded)</option>", "</select>")
	inOrder(page, "jump menu", `data-pick="jump"`, ">Other Raw (1)</option>", sep, ">Slab Shop (Graded) (1)</option>", "</select>")
	inOrder(page, "tables", `id="Other Raw"`, `id="Slab Shop (Graded)"`)

	// With no raw table before them, the slab tables need no separator
	page = render("/global?source=ZZOTHER&legit=0", PageVars{ArbitVars: ArbitVars{GlobalMode: true}})
	jump, _, _ := strings.Cut(page[strings.Index(page, `data-pick="jump"`):], "</select>")
	if !strings.Contains(jump, ">Slab Shop (Graded) (1)</option>") || strings.Contains(jump, ">Raw Shop") || strings.Contains(jump, sep) {
		t.Errorf("jump menu of slab tables alone: %s", jump)
	}
}
