package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/cardtrader"
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// ctFixture is a Magic seller with one Lorcana listing on the side: a
// nonfoil Black Lotus, a foil French Lotus renamed by CardTrader, a listing
// whose blueprint the catalog did not serve, and the Lorcana row.
func ctFixture() *cardtrader.Inventory {
	lotus := &cardtrader.Blueprint{ID: 100, Name: "Black Lotus", GameID: cardtrader.GameMagic, CategoryID: 1, ExpansionID: 10, ScryfallID: "abc", TCGplayerID: 1234}
	lotus.Expansion.Name = "Limited Edition Alpha"
	lotus.Expansion.Code = "lea"
	lotus.Properties.Number = "232"
	elsa := &cardtrader.Blueprint{ID: 200, Name: "Elsa - Snow Queen", GameID: cardtrader.GameLorcana, CategoryID: 30, ExpansionID: 20, TCGplayerID: 5678}
	elsa.Expansion.Name = "The First Chapter"
	elsa.Expansion.Code = "tfc"

	p := func(id, bp, game, qty, cents int, name, currency, cond string) cardtrader.Product {
		var out cardtrader.Product
		out.ID, out.BlueprintID, out.GameID, out.Quantity, out.PriceCents = id, bp, game, qty, cents
		out.Name, out.PriceCurrency, out.Properties.Condition = name, currency, cond
		return out
	}
	nonfoil := p(1, 100, cardtrader.GameMagic, 2, 1000000, "Black Lotus", "EUR", "Near Mint")
	nonfoil.Properties.MTGLanguage = "en"
	nonfoil.Description = "pack fresh, \"really\""
	foil := p(2, 100, cardtrader.GameMagic, 0, 50, "Black Lotus (renamed)", "USD", "Played")
	foil.Properties.MTGLanguage, foil.Properties.MTGFoil, foil.Properties.Signed = "fr", true, true
	orphan := p(3, 999, cardtrader.GameMagic, 1, 100, "Mystery Card", "EUR", "Slightly Played")
	lorcana := p(4, 200, cardtrader.GameLorcana, 1, 250, "Elsa - Snow Queen", "GBP", "Moderately Played")
	lorcana.Properties.LorcanaLanguage, lorcana.Properties.LorcanaFoil = "en", true

	return &cardtrader.Inventory{
		Products:    []cardtrader.Product{nonfoil, foil, orphan, lorcana},
		Blueprints:  map[int]*cardtrader.Blueprint{100: lotus, 200: elsa},
		Expansions:  map[int]cardtrader.Expansion{10: {ID: 10, GameID: 1, Code: "lea", Name: "Limited Edition Alpha"}, 20: {ID: 20, GameID: 18, Code: "tfc", Name: "The First Chapter"}},
		Unavailable: map[int]error{},
	}
}

var ctRates = map[string]float64{"eur": 1.10, "gbp": 1.25}

// column reads one named column of a row by the table's header.
func column(t *testing.T, table [][]string, row int, name string) string {
	t.Helper()
	i := slices.Index(table[0], name)
	if i < 0 {
		t.Fatalf("no column %q in %v", name, table[0])
	}
	if len(table[row]) != len(table[0]) {
		t.Fatalf("row %d has %d fields, header has %d", row, len(table[row]), len(table[0]))
	}
	return table[row][i]
}

func TestCTRawCSVCopiesEveryListing(t *testing.T) {
	export, _, _ := buildCTExport(mtgmatcher.NewBackend(), mtgmatcher.GameMagic, ctFixture(), ctRates)

	if !slices.Equal(export.Raw[0], ctRawHeader) {
		t.Fatalf("header: %v", export.Raw[0])
	}
	if len(export.Raw) != 5 {
		t.Fatalf("rows: got %d, want header plus 4", len(export.Raw))
	}
	for name, want := range map[string]string{
		"product_id": "1", "blueprint_id": "100", "game_id": "1", "name": "Black Lotus",
		"expansion_code": "lea", "expansion_name": "Limited Edition Alpha", "quantity": "2", "bundle": "false",
		"price_cents": "1000000", "price_currency": "EUR", "condition": "Near Mint",
		"language": "en", "foil": "false", "signed": "false", "altered": "false", "first_edition": "false",
		"tcgplayer_id": "1234", "scryfall_id": "abc", "description": "pack fresh, \"really\"",
	} {
		if got := column(t, export.Raw, 1, name); got != want {
			t.Errorf("row 1 %s: got %q, want %q", name, got, want)
		}
	}
	// CardTrader's own name for the listing, and the price never converted.
	if got := column(t, export.Raw, 2, "name"); got != "Black Lotus (renamed)" {
		t.Errorf("renamed listing: %q", got)
	}
	if got := column(t, export.Raw, 2, "foil"); got != "true" {
		t.Errorf("foil flag: %q", got)
	}
	if got := column(t, export.Raw, 2, "signed"); got != "true" {
		t.Errorf("signed flag: %q", got)
	}
	// No blueprint: the catalog columns stay empty, the listing stays.
	for _, name := range []string{"expansion_code", "expansion_name", "tcgplayer_id", "scryfall_id"} {
		if got := column(t, export.Raw, 3, name); got != "" {
			t.Errorf("orphan %s: %q, want empty", name, got)
		}
	}
	if got := column(t, export.Raw, 3, "name"); got != "Mystery Card" {
		t.Errorf("orphan name: %q", got)
	}
	// Another game's listing, with its own foil property.
	if got := column(t, export.Raw, 4, "foil"); got != "true" {
		t.Errorf("lorcana foil: %q", got)
	}
	if got := column(t, export.Raw, 4, "language"); got != "en" {
		t.Errorf("lorcana language: %q", got)
	}
}

func TestCTBanCSVKeepsThisGameOnly(t *testing.T) {
	export, summary, unmatched := buildCTExport(mtgmatcher.NewBackend(), mtgmatcher.GameMagic, ctFixture(), ctRates)

	if !slices.Equal(export.Ban[0], ctBanHeader) {
		t.Fatalf("header: %v", export.Ban[0])
	}
	if len(export.Ban) != 4 {
		t.Fatalf("rows: got %d, want header plus the 3 Magic listings", len(export.Ban))
	}
	// Nothing matches on an empty backend, so every row is unmatched with
	// the blueprint's own words.
	if got := column(t, export.Ban, 1, "name"); got != "Black Lotus" {
		t.Errorf("name from the blueprint: %q", got)
	}
	if got := column(t, export.Ban, 2, "name"); got != "Black Lotus" {
		t.Errorf("renamed listing should use the blueprint name: %q", got)
	}
	if got := column(t, export.Ban, 1, "edition"); got != "Limited Edition Alpha" {
		t.Errorf("edition: %q", got)
	}
	if got := column(t, export.Ban, 1, "number"); got != "232" {
		t.Errorf("number: %q", got)
	}
	for row, want := range map[int]string{1: "nonfoil", 2: "foil", 3: "nonfoil"} {
		if got := column(t, export.Ban, row, "finish"); got != want {
			t.Errorf("row %d finish: %q, want %q", row, got, want)
		}
	}
	for row, want := range map[int]string{1: "NM", 2: "HP", 3: "SP"} {
		if got := column(t, export.Ban, row, "condition"); got != want {
			t.Errorf("row %d condition: %q, want %q", row, got, want)
		}
	}
	if got := column(t, export.Ban, 2, "quantity"); got != "0" {
		t.Errorf("zero quantity kept: %q", got)
	}
	if got := column(t, export.Ban, 1, "price"); got != "11000.00" {
		t.Errorf("EUR price at 1.10: %q", got)
	}
	if got := column(t, export.Ban, 2, "price"); got != "0.50" {
		t.Errorf("USD price untouched: %q", got)
	}
	if got := column(t, export.Ban, 3, "name"); got != "Mystery Card" {
		t.Errorf("orphan falls back to name_en: %q", got)
	}
	if got := column(t, export.Ban, 3, "edition"); got != "" {
		t.Errorf("orphan edition: %q", got)
	}
	for row := 1; row < 4; row++ {
		if got := column(t, export.Ban, row, "id"); got != "" {
			t.Errorf("row %d id on an empty backend: %q", row, got)
		}
	}

	want := ctSummary{Listings: 4, ThisGame: 3, Matched: 0, Unmatched: 3, OtherGames: 1, NoCatalog: 0}
	if summary != want {
		t.Errorf("summary: %+v, want %+v", summary, want)
	}
	if len(unmatched) != 3 {
		t.Fatalf("unmatched: %d", len(unmatched))
	}
	if unmatched[2].Reason != "unknown blueprint" || unmatched[2].Name != "Mystery Card" {
		t.Errorf("orphan: %+v", unmatched[2])
	}
}

func TestCTBundleCountsFourCopies(t *testing.T) {
	inv := ctFixture()
	inv.Products[2].Bundle = true
	export, _, unmatched := buildCTExport(mtgmatcher.NewBackend(), mtgmatcher.GameMagic, inv, ctRates)
	if got := column(t, export.Raw, 3, "quantity"); got != "1" {
		t.Errorf("raw quantity: %q, want as sent", got)
	}
	if got := column(t, export.Raw, 3, "bundle"); got != "true" {
		t.Errorf("raw bundle: %q", got)
	}
	if got := column(t, export.Ban, 3, "quantity"); got != "4" {
		t.Errorf("BAN quantity: %q, want a playset", got)
	}
	if unmatched[2].Quantity != 4 {
		t.Errorf("unmatched quantity: %d", unmatched[2].Quantity)
	}
}

func TestCTBanCSVLeavesPriceEmptyWithoutARate(t *testing.T) {
	inv := ctFixture()
	export, summary, _ := buildCTExport(mtgmatcher.NewBackend(), mtgmatcher.GameMagic, inv, map[string]float64{})
	if got := column(t, export.Ban, 1, "price"); got != "" {
		t.Errorf("EUR with no rate: %q, want empty", got)
	}
	if got := column(t, export.Ban, 2, "price"); got != "0.50" {
		t.Errorf("USD needs no rate: %q", got)
	}
	if summary.NoRates {
		t.Error("a rate table, even an empty one, is not missing rates")
	}

	_, summary, _ = buildCTExport(mtgmatcher.NewBackend(), mtgmatcher.GameMagic, inv, nil)
	if !summary.NoRates {
		t.Error("nil rates should set NoRates")
	}
}

func TestCTUnavailableCatalogNamesTheReason(t *testing.T) {
	inv := ctFixture()
	inv.Unavailable[10] = errContext("Expansion not found")
	_, summary, unmatched := buildCTExport(mtgmatcher.NewBackend(), mtgmatcher.GameMagic, inv, ctRates)
	if unmatched[2].Reason != "catalog unavailable" {
		t.Errorf("orphan with a failed catalog: %q", unmatched[2].Reason)
	}
	if summary.NoCatalog != 1 {
		t.Errorf("NoCatalog: %d", summary.NoCatalog)
	}
}

type errContext string

func (e errContext) Error() string { return string(e) }

func TestCTConditionCodes(t *testing.T) {
	for in, want := range map[string]string{
		"": "", "Mint": "NM", "Near Mint": "NM", "Slightly Played": "SP",
		"Moderately Played": "MP", "Played": "HP", "Heavily Played": "HP", "Poor": "PO",
		"Shiny": "",
	} {
		if got := ctBanCondition(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestCTFinishPerGame(t *testing.T) {
	var p cardtrader.ProductProperties
	p.MTGFoil, p.LorcanaFoil, p.PokemonReverse, p.FabFoilNew = true, true, true, "Rainbow Foil"
	for game, want := range map[int]string{
		cardtrader.GameMagic: "foil", cardtrader.GameLorcana: "foil", cardtrader.GamePokemon: "foil",
		cardtrader.GameFleshAndBlood: "foil", cardtrader.GameYuGiOh: "", cardtrader.GameGundam: "", cardtrader.GamePalworld: "",
	} {
		if got := ctFinish(game, p); got != want {
			t.Errorf("game %d: got %q, want %q", game, got, want)
		}
	}
	var plain cardtrader.ProductProperties
	plain.FabFoilNew = "Regular"
	if got := ctFinish(cardtrader.GameMagic, plain); got != "nonfoil" {
		t.Errorf("magic nonfoil: %q", got)
	}
	if got := ctFinish(cardtrader.GameFleshAndBlood, plain); got != "nonfoil" {
		t.Errorf("fab regular: %q", got)
	}
	plain.FabFoilNew = "false"
	if got := ctFinish(cardtrader.GameFleshAndBlood, plain); got != "nonfoil" {
		t.Errorf("fab false: %q", got)
	}
}

func TestCTMatchesMagicThroughTheDatastore(t *testing.T) {
	skipWithoutDatastore(t)
	inv := ctFixture()
	// The fixture ids are made up, and Preprocess trusts a TCGplayer id first.
	inv.Blueprints[100].TCGplayerID = 0
	// The foil row moves to an English Bolt, a card printed in both finishes,
	// with a nonfoil copy of it beside.
	bolt := &cardtrader.Blueprint{ID: 101, Name: "Lightning Bolt", GameID: cardtrader.GameMagic, CategoryID: 1, ExpansionID: 11}
	bolt.Expansion.Name = "Magic 2010"
	bolt.Expansion.Code = "m10"
	bolt.Properties.Number = "146"
	inv.Blueprints[101] = bolt
	inv.Products[1].BlueprintID, inv.Products[1].Properties.MTGLanguage = 101, "en"
	plainBolt := inv.Products[1]
	plainBolt.ID, plainBolt.Properties.MTGFoil = 8, false
	inv.Products = append(inv.Products, plainBolt)
	export, summary, unmatched := buildCTExport(backend(), mtgmatcher.GameMagic, inv, ctRates)

	match := func(name, edition string, foil bool) string {
		t.Helper()
		uuid, err := backend().Match(&mtgmatcher.InputCard{Name: name, Edition: edition, Foil: foil})
		if err != nil || uuid == "" {
			t.Fatalf("%s from %s, foil %v: %v", name, edition, foil, err)
		}
		return uuid
	}
	for row, want := range map[int]string{
		1: match("Black Lotus", "Limited Edition Alpha", false),
		2: match("Lightning Bolt", "Magic 2010", true),
		4: match("Lightning Bolt", "Magic 2010", false),
	} {
		if got := column(t, export.Ban, row, "id"); got != want {
			t.Errorf("row %d: %q, want %q", row, got, want)
		}
	}
	if summary.Matched != 3 || summary.Unmatched != 1 {
		t.Errorf("summary: %+v", summary)
	}
	if len(unmatched) != 1 || unmatched[0].Reason != "unknown blueprint" {
		t.Errorf("unmatched: %+v", unmatched)
	}
}

func TestCTMatchesMagicByItsTCGplayerID(t *testing.T) {
	skipWithoutDatastore(t)
	lotus, err := backend().Match(&mtgmatcher.InputCard{Name: "Black Lotus", Edition: "Limited Edition Alpha"})
	if err != nil {
		t.Fatal(err)
	}
	co, err := backend().GetUUID(lotus)
	if err != nil {
		t.Fatal(err)
	}
	tcgID, err := strconv.Atoi(co.Identifiers["tcgplayerProductId"])
	if err != nil {
		t.Fatalf("no TCGplayer id on %s: %v", lotus, err)
	}

	inv := ctFixture()
	inv.Blueprints[100].TCGplayerID = tcgID
	// A name Preprocess cannot resolve, so only the id can place the row.
	inv.Blueprints[100].Name = "Not A Real Card Name"
	inv.Products = inv.Products[:1]
	export, _, _ := buildCTExport(backend(), mtgmatcher.GameMagic, inv, ctRates)
	if got := column(t, export.Ban, 1, "id"); got != lotus {
		t.Errorf("by TCGplayer id: %q, want %q", got, lotus)
	}
}

func TestCTTokenBlueprintIsNotACard(t *testing.T) {
	skipWithoutDatastore(t)
	inv := ctFixture()
	token := &cardtrader.Blueprint{ID: 300, Name: "Soldier Token", GameID: cardtrader.GameMagic, CategoryID: 2, ExpansionID: 10}
	token.Expansion.Name = "Limited Edition Alpha"
	inv.Blueprints[300] = token
	var p cardtrader.Product
	p.ID, p.BlueprintID, p.GameID, p.Quantity, p.Name = 5, 300, cardtrader.GameMagic, 1, "Soldier Token"
	inv.Products = append(inv.Products, p)

	_, _, unmatched := buildCTExport(backend(), mtgmatcher.GameMagic, inv, ctRates)
	last := unmatched[len(unmatched)-1]
	// Preprocess lets it through; Alpha has no Soldier Token for it to match.
	if last.Name != "Soldier Token" || last.Reason != "no match" {
		t.Errorf("token: %+v", last)
	}
}

func TestCTUnsupportedLanguageIsNotGuessedAsEnglish(t *testing.T) {
	inv := ctFixture()
	inv.Products[0].Properties.MTGLanguage = "xx"
	export, summary, unmatched := buildCTExport(mtgmatcher.NewBackend(), mtgmatcher.GameMagic, inv, ctRates)
	if unmatched[0].Reason != "unsupported language" {
		t.Errorf("reason: %+v", unmatched[0])
	}
	if len(export.Ban) != 4 || column(t, export.Ban, 1, "name") != "Black Lotus" {
		t.Errorf("the row should still be written: %v", export.Ban)
	}
	if summary.Unmatched != 3 {
		t.Errorf("summary: %+v", summary)
	}
}

func TestCTUnknownGameKeepsOnlyTheRawTable(t *testing.T) {
	inv := ctFixture()
	var zero cardtrader.Product
	zero.ID, zero.BlueprintID, zero.Quantity, zero.Name = 7, 998, 1, "No Game"
	inv.Products = append(inv.Products, zero)
	export, summary, _ := buildCTExport(mtgmatcher.NewBackend(), mtgmatcher.Game("digimon"), inv, ctRates)
	if summary.ThisGame != 0 || summary.OtherGames != 5 || len(export.Ban) != 1 {
		t.Errorf("summary %+v, ban rows %d", summary, len(export.Ban))
	}
}

func TestCTNonMagicMatchingReasons(t *testing.T) {
	inv := ctFixture()
	bare := &cardtrader.Blueprint{ID: 201, Name: "Anna", GameID: cardtrader.GameLorcana, CategoryID: 30, ExpansionID: 20}
	inv.Blueprints[201] = bare
	var p cardtrader.Product
	p.ID, p.BlueprintID, p.GameID, p.Quantity, p.Name = 6, 201, cardtrader.GameLorcana, 1, "Anna"
	inv.Products = append(inv.Products, p)

	export, summary, unmatched := buildCTExport(mtgmatcher.NewBackend(), mtgmatcher.GameLorcana, inv, ctRates)
	if len(export.Ban) != 3 || summary.OtherGames != 3 || summary.ThisGame != 2 {
		t.Fatalf("ban rows %d, summary %+v", len(export.Ban), summary)
	}
	if len(unmatched) != 2 || unmatched[0].Reason != "no match" || unmatched[1].Reason != "no id to match by" {
		t.Errorf("unmatched: %+v", unmatched)
	}
}

// ctPost posts a form to the inventory page through the Upload handler, the
// way the mux reaches it.
func ctPost(t *testing.T, s *site, form string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/upload/cardtrader", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.Upload(rec, req)
	return rec
}

// swapCTExport points the page at a fake seller for one test.
func swapCTExport(t *testing.T, fn func(context.Context, string) (*cardtrader.Inventory, error)) *[]string {
	t.Helper()
	saved, savedRates := ctExportInventory, ctExchangeRates
	t.Cleanup(func() { ctExportInventory, ctExchangeRates = saved, savedRates })
	var tokens []string
	ctExportInventory = func(ctx context.Context, token string) (*cardtrader.Inventory, error) {
		tokens = append(tokens, token)
		return fn(ctx, token)
	}
	ctExchangeRates = func(context.Context) (map[string]float64, error) { return ctRates, nil }
	return &tokens
}

func TestCardTraderPageRendersTheForm(t *testing.T) {
	withSigMode(t, true, false)
	s := newSite()
	req := httptest.NewRequest(http.MethodGet, "/upload/cardtrader?token=leaked", nil)
	rec := httptest.NewRecorder()
	tokens := swapCTExport(t, func(context.Context, string) (*cardtrader.Inventory, error) {
		t.Fatal("a GET must not fetch anything")
		return nil, nil
	})
	s.Upload(rec, req)

	body := rec.Body.String()
	for _, want := range []string{`action="/upload/cardtrader"`, `method="post"`, `name="token"`, `type="password"`, `autocomplete="off"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the form is missing %s", want)
		}
	}
	if strings.Contains(body, "BAN_CT_EXPORT") {
		t.Error("an export script on a page with nothing loaded")
	}
	if len(*tokens) != 0 {
		t.Error("the query string token was used")
	}
}

func TestCardTraderPageAsksForAToken(t *testing.T) {
	withSigMode(t, true, false)
	s := newSite()
	swapCTExport(t, func(context.Context, string) (*cardtrader.Inventory, error) {
		t.Fatal("an empty token must not fetch anything")
		return nil, nil
	})
	body := ctPost(t, s, "token=++").Body.String()
	if !strings.Contains(body, "Paste your CardTrader API token first.") {
		t.Error("no prompt for the missing token")
	}
}

func TestCardTraderPageTrimsTheToken(t *testing.T) {
	withSigMode(t, true, false)
	s := newSite()
	tokens := swapCTExport(t, func(context.Context, string) (*cardtrader.Inventory, error) {
		return ctFixture(), nil
	})
	ctPost(t, s, "token=+Bearer+abc123+")
	if len(*tokens) != 1 || (*tokens)[0] != "abc123" {
		t.Errorf("token handed to CardTrader: %q", *tokens)
	}
}

func TestCardTraderPageSaysWhenTheTokenIsRefused(t *testing.T) {
	withSigMode(t, true, false)
	s := newSite()
	swapCTExport(t, func(context.Context, string) (*cardtrader.Inventory, error) {
		return nil, errors.New("expansions export: 401 Unauthorized")
	})
	body := ctPost(t, s, "token=bad").Body.String()
	if !strings.Contains(body, "CardTrader did not accept that token.") {
		t.Error("a 401 did not say the token was refused")
	}
	if !strings.Contains(body, `name="token"`) {
		t.Error("the form is gone after an error")
	}
}

func TestCardTraderPageSaysWhenCardTraderIsDown(t *testing.T) {
	withSigMode(t, true, false)
	s := newSite()
	swapCTExport(t, func(context.Context, string) (*cardtrader.Inventory, error) {
		return nil, errors.New("dial tcp: i/o timeout")
	})
	body := ctPost(t, s, "token=abc").Body.String()
	if !strings.Contains(body, "CardTrader did not answer. Try again in a minute.") {
		t.Error("a network error did not get the generic message")
	}
}

func TestCardTraderPageSaysWhenTheStockIsEmpty(t *testing.T) {
	withSigMode(t, true, false)
	s := newSite()
	swapCTExport(t, func(context.Context, string) (*cardtrader.Inventory, error) {
		return &cardtrader.Inventory{Blueprints: map[int]*cardtrader.Blueprint{}, Expansions: map[int]cardtrader.Expansion{}, Unavailable: map[int]error{}}, nil
	})
	body := ctPost(t, s, "token=abc").Body.String()
	if !strings.Contains(body, "CardTrader returned no listings for that token.") {
		t.Error("an empty stock did not say so")
	}
}

func TestCardTraderPageRefusesPastTheExportCap(t *testing.T) {
	withSigMode(t, true, false)
	s := newSite()
	saved := ctExportSlots
	t.Cleanup(func() { ctExportSlots = saved })
	ctExportSlots = make(chan struct{}, 4)
	for range cap(ctExportSlots) {
		ctExportSlots <- struct{}{}
	}
	tokens := swapCTExport(t, func(context.Context, string) (*cardtrader.Inventory, error) { return ctFixture(), nil })
	body := ctPost(t, s, "token=abc").Body.String()
	if !strings.Contains(body, "Too many exports are running. Try again in a minute.") {
		t.Error("a full export cap did not say so")
	}
	if len(*tokens) != 0 {
		t.Error("an export ran past the cap")
	}
}

func TestCardTraderPageCapsTheUnmatchedTable(t *testing.T) {
	withSigMode(t, true, false)
	s := newSite()
	inv := ctFixture()
	orphan := inv.Products[2]
	inv.Products = nil
	for i := range 501 {
		orphan.ID = 1000 + i
		inv.Products = append(inv.Products, orphan)
	}
	swapCTExport(t, func(context.Context, string) (*cardtrader.Inventory, error) { return inv, nil })

	body := ctPost(t, s, "token=abc").Body.String()
	if rows := strings.Count(body, "<td>unknown blueprint</td>"); rows != 500 {
		t.Errorf("unmatched rows drawn: %d, want 500", rows)
	}
	if !strings.Contains(body, "and 1 more in the BAN CSV") {
		t.Error("no line for the rows past the cap")
	}
}

func TestCardTraderPageRendersALoad(t *testing.T) {
	withSigMode(t, true, false)
	s := newSite()
	inv := ctFixture()
	// Only the orphan, so the empty backend is never asked to preprocess.
	inv.Products = inv.Products[2:]
	swapCTExport(t, func(context.Context, string) (*cardtrader.Inventory, error) { return inv, nil })

	body := ctPost(t, s, "token=secret-token-123").Body.String()
	if strings.Contains(body, "secret-token-123") {
		t.Fatal("the token is on the page")
	}
	for _, want := range []string{
		"BAN_CT_EXPORT", `id="ct-download-raw"`, `id="ct-download-ban"`, "/js/cardtrader-export.js",
		"Mystery Card", "unknown blueprint", `name="token"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("a loaded page is missing %s", want)
		}
	}
	// Counts land on the page: 2 listings, 1 of this game, 1 other game.
	for _, want := range []string{"<strong>2</strong> listings", "<strong>1</strong> in other games"} {
		if !strings.Contains(body, want) {
			t.Errorf("summary fragment %q missing", want)
		}
	}
}

func TestCardTraderIsAnUploadSubPage(t *testing.T) {
	var found *NavElem
	for i := range ExtraNavs["Upload"].SubPages {
		if ExtraNavs["Upload"].SubPages[i].Name == "CardTrader" {
			found = &ExtraNavs["Upload"].SubPages[i]
		}
	}
	if found == nil {
		t.Fatal("no CardTrader sub-page under Upload")
	}
	if found.Link != "/upload/cardtrader" || found.Description == "" {
		t.Errorf("sub-page: %+v", found)
	}
	if navKey("CardTrader") != "Upload" {
		t.Errorf("navKey: %q", navKey("CardTrader"))
	}
	if !slices.Contains(mobileEnabledPages, "CardTrader") {
		t.Error("the page is served in the mobile base but hidden from the mobile nav")
	}
}

func TestCardTraderPageRendersOnMobile(t *testing.T) {
	page := renderPage(t, "cardtrader_inventory.html", true, PageVars{
		UserNav: &NavElem{Short: "b"},
		Title:   "CardTrader inventory",
	})
	if !strings.Contains(page, `name="token"`) {
		t.Error("the mobile page has no form")
	}
}

func TestCardTraderPageIgnoresAQueryStringToken(t *testing.T) {
	withSigMode(t, true, false)
	s := newSite()
	tokens := swapCTExport(t, func(context.Context, string) (*cardtrader.Inventory, error) {
		t.Fatal("a query string token must not fetch anything")
		return nil, nil
	})
	req := httptest.NewRequest(http.MethodPost, "/upload/cardtrader?token=leaked", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.Upload(rec, req)
	if !strings.Contains(rec.Body.String(), "Paste your CardTrader API token first.") {
		t.Error("no prompt for the missing token")
	}
	if len(*tokens) != 0 {
		t.Error("the query string token was used")
	}
}

func TestCTTokenRefused(t *testing.T) {
	for msg, want := range map[string]bool{
		"expansions export: 401 Unauthorized":    true,
		"expansions export: 403 Forbidden":       true,
		"dial tcp 10.0.0.1:4013: i/o timeout":    false,
		"expansions export: 500 Internal Server": false,
	} {
		if got := ctTokenRefused(errors.New(msg)); got != want {
			t.Errorf("%q: got %v, want %v", msg, got, want)
		}
	}
}

// ctSigned drives the sub-page through enforceSigning the way the mux does,
// with a signature that carries the Upload grant or not.
func ctSigned(t *testing.T, s *site, method string, grant bool, form string) *httptest.ResponseRecorder {
	t.Helper()
	fields := url.Values{"UserEmail": {"ct-" + method + "-" + strconv.FormatBool(grant) + "@example.com"}, "UserTier": {"Test"}}
	if grant {
		fields.Set("Upload", "true")
	}
	sig := signedAs(t, fields, time.Now().Add(time.Hour))
	req := httptest.NewRequest(method, "/upload/cardtrader", strings.NewReader(form))
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sig})
	rec := httptest.NewRecorder()
	enforceSigning(s, http.HandlerFunc(s.Upload)).ServeHTTP(rec, req)
	return rec
}

func TestCardTraderSubPageGoesThroughUploadSigning(t *testing.T) {
	signingEnabled(t, true)
	s := newSite()
	inv := ctFixture()
	inv.Products = inv.Products[2:]
	tokens := swapCTExport(t, func(context.Context, string) (*cardtrader.Inventory, error) { return inv, nil })

	rec := ctSigned(t, s, http.MethodPost, true, "token=abc")
	if rec.Code == http.StatusMethodNotAllowed {
		t.Fatal("a POST to the sub-page was answered 405")
	}
	if len(*tokens) != 1 || !strings.Contains(rec.Body.String(), "<strong>2</strong> listings") {
		t.Errorf("a granted POST did not load: %d calls", len(*tokens))
	}

	body := ctSigned(t, s, http.MethodGet, false, "").Body.String()
	if !strings.Contains(body, ErrMsgPlus) || strings.Contains(body, `name="token"`) {
		t.Error("a GET without the Upload grant was not refused")
	}
	ctSigned(t, s, http.MethodPost, false, "token=abc")
	if len(*tokens) != 1 {
		t.Error("a POST without the Upload grant reached the exporter")
	}
}

func TestCardTraderSubPageHidesOnAnUnknownGame(t *testing.T) {
	signingEnabled(t, true)
	withConfigCopy(t)
	Config().Game = "digimon"
	s := newSite()
	body := ctSigned(t, s, http.MethodGet, true, "").Body.String()
	if !strings.Contains(body, "Unauthorized") || strings.Contains(body, `name="token"`) {
		t.Error("the sub-page served its form on a game CardTrader does not sell")
	}
}

// The API handoffs are sub-pages hidden from the nav, not refused: the
// middleware must not gate them by the API grant or their ShouldHide.
func TestAPIHandoffStaysReachableWithoutTheAPIGrant(t *testing.T) {
	signingEnabled(t, true)
	s := newSite()
	sig := signedAs(t, url.Values{"UserEmail": {"handoff@example.com"}, "UserTier": {"Test"}}, time.Now().Add(time.Hour))
	req := httptest.NewRequest(http.MethodGet, "/api-trial", nil)
	req.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sig})
	rec := httptest.NewRecorder()
	enforceSigning(s, http.HandlerFunc(s.APIPlans)).ServeHTTP(rec, req)
	body := rec.Body.String()
	if strings.Contains(body, ErrMsgPlus) || strings.Contains(body, "<title>Unauthorized") {
		t.Errorf("the trial handoff was refused: %d", rec.Code)
	}
}

func TestCardTraderPageMarksItsOwnNavEntry(t *testing.T) {
	withSigMode(t, true, false)
	s := newSite()
	req := httptest.NewRequest(http.MethodGet, "/upload/cardtrader", nil)
	rec := httptest.NewRecorder()
	s.Upload(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, `<a class="active" href="/upload/cardtrader">`) {
		t.Error("the CardTrader nav entry is not the active one")
	}
	limits := fmt.Sprintf("Upload takes up to %d rows at a time, %d with the Optimizer, and skips rows with no stock.", MaxUploadEntries, MaxUploadProEntries)
	if !strings.Contains(body, limits) {
		t.Error("the upload limits line is missing")
	}
}

func TestCardTraderPageSaysWhenRatesAreMissing(t *testing.T) {
	withSigMode(t, true, false)
	s := newSite()
	inv := ctFixture()
	inv.Products = inv.Products[2:]
	swapCTExport(t, func(context.Context, string) (*cardtrader.Inventory, error) { return inv, nil })
	ctExchangeRates = func(context.Context) (map[string]float64, error) { return nil, errors.New("down") }
	body := ctPost(t, s, "token=abc").Body.String()
	if !strings.Contains(body, "Non-dollar prices left empty: no exchange rates") {
		t.Error("missing rates were not named")
	}
}
