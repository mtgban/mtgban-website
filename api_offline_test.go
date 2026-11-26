package main

import (
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/internal/offline"
)

func offlineTestSig(email, offlineFlag string) string {
	v := url.Values{}
	v.Set("UserEmail", email)
	if offlineFlag != "" {
		v.Set("SearchOfflineMode", offlineFlag)
	}
	v.Set("Expires", "9999999999")
	return base64.StdEncoding.EncodeToString([]byte(v.Encode()))
}

func TestOfflineModeAllowed(t *testing.T) {
	withSigMode(t, false, false)

	tests := []struct {
		name  string
		sig   string
		want  bool
		email string
	}{
		{"no sig", "", false, ""},
		{"flag missing", offlineTestSig("a@b.c", ""), false, ""},
		{"flag false", offlineTestSig("a@b.c", "false"), false, ""},
		{"flag true", offlineTestSig("a@b.c", "true"), true, "a@b.c"},
	}
	for _, tt := range tests {
		r := httptest.NewRequest("GET", "/api/offline/manifest.json", nil)
		if tt.sig != "" {
			r.AddCookie(&http.Cookie{Name: "BAN_SIG", Value: tt.sig})
		}
		email, ok := offlineModeAllowed(r)
		if ok != tt.want || (tt.want && email != tt.email) {
			t.Errorf("%s: got (%q,%v), want (%q,%v)", tt.name, email, ok, tt.email, tt.want)
		}
	}
}

// The grant is read off the signature that names the reader: a valid ?sig=
// without it does not lend its email to a forged cookie that claims it.
func TestOfflineModeReadsOneCheckedSignature(t *testing.T) {
	signingEnabled(t, false)
	plain := signedAs(t, url.Values{"UserEmail": {"a@b.c"}, "UserTier": {"Test"}}, time.Now().Add(time.Hour))
	granted := signedAs(t, url.Values{"UserEmail": {"a@b.c"}, "UserTier": {"Test"}, "SearchOfflineMode": {"true"}}, time.Now().Add(time.Hour))
	forged := offlineTestSig("a@b.c", "true")

	for _, tc := range []struct {
		name          string
		query, cookie string
		want          bool
	}{
		{"valid ?sig= beside a forged cookie", plain, forged, false},
		{"forged cookie alone", "", forged, false},
		{"granted ?sig=", granted, "", true},
		{"granted cookie", "", granted, true},
	} {
		target := "/api/offline/manifest.json"
		if tc.query != "" {
			target += "?sig=" + url.QueryEscape(tc.query)
		}
		r := httptest.NewRequest(http.MethodGet, target, nil)
		if tc.cookie != "" {
			r.AddCookie(&http.Cookie{Name: "BAN_SIG", Value: tc.cookie})
		}
		email, ok := offlineModeAllowed(r)
		if ok != tc.want || (ok && email != "a@b.c") {
			t.Errorf("%s: got (%q, %v), want %v", tc.name, email, ok, tc.want)
		}
	}
}

// A store that sells and buys under one shorthand and is blocked on one side
// only ships in the offline payload on its other side alone.
func TestOfflinePricesBlockOneSide(t *testing.T) {
	withSigMode(t, true, false)
	withConfigCopy(t)
	Config().Stores.SearchRetailBlockList = []string{"NORETAIL"}
	Config().Stores.SearchBuylistBlockList = []string{"NOBUYLIST"}

	const cardID = "FIXTUREA-1"
	var sellers []mtgban.Seller
	var vendors []mtgban.Vendor
	for _, shorthand := range []string{"NORETAIL", "NOBUYLIST"} {
		inv := mtgban.InventoryRecord{}
		inv.Add(cardID, &mtgban.InventoryEntry{Conditions: "NM", Price: 10, Quantity: 1, URL: "u"})
		sellers = append(sellers, mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Name: shorthand, Shorthand: shorthand}))
		bl := mtgban.BuylistRecord{}
		bl.Add(cardID, &mtgban.BuylistEntry{Conditions: "NM", BuyPrice: 5, Quantity: 1, URL: "u"})
		vendors = append(vendors, mtgban.NewVendorFromBuylist(bl, mtgban.ScraperInfo{Name: shorthand, Shorthand: shorthand}))
	}
	s := fixtureSite(t, fixtureBackend("FIXTUREA", "Fixture Edition Alpha", "2020-01-01",
		[][2]string{{"Fixture Card Alpha", "1"}}), sellers, vendors)

	for _, tc := range []struct {
		query           string
		retail, buylist []string
	}{
		{"", []string{"NOBUYLIST"}, []string{"NORETAIL"}},
		{"?stores=NORETAIL,NOBUYLIST", []string{"NOBUYLIST"}, []string{"NORETAIL"}},
		// The one store picked is blocked on buylist, which leaves that side empty.
		{"?stores=NOBUYLIST", []string{"NOBUYLIST"}, nil},
	} {
		target := "/api/offline/prices/FIXTUREA.bin" + tc.query
		w := httptest.NewRecorder()
		s.offline.Handle(w, httptest.NewRequest(http.MethodGet, target, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d", target, w.Code)
		}
		gr, err := gzip.NewReader(w.Body)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(gr)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := offline.Decode(data)
		if err != nil {
			t.Fatal(err)
		}

		for _, shorthand := range []string{"NORETAIL", "NOBUYLIST"} {
			_, retail := payload.Retail[cardID][shorthand]
			_, buylist := payload.Buylist[cardID][shorthand]
			if retail != slices.Contains(tc.retail, shorthand) || buylist != slices.Contains(tc.buylist, shorthand) {
				t.Errorf("%s: %s in retail %v, buylist %v", target, shorthand, retail, buylist)
			}
		}
	}
}

// A slab store's prices are filed under each slab's own tag, the condition it
// folds to and then its name, while a raw store keeps the plain conditions.
func TestOfflinePricesCarryTheSlab(t *testing.T) {
	withSigMode(t, true, false)
	withConfigCopy(t)

	b := fixtureBackend("FIXTUREA", "Fixture Edition Alpha", "2020-01-01",
		[][2]string{{"Fixture Card Alpha", "1"}, {"Fixture Card Alpha Foil", "2"}})
	b.UUIDs["FIXTUREA-2"].Foil = true
	slab := func(cond mtgban.Condition, price float64, quantity int, slab *mtgban.Slab) mtgban.InventoryEntry {
		return mtgban.InventoryEntry{Conditions: cond, Price: price, Quantity: quantity, URL: "u", Slab: slab}
	}
	s := fixtureSite(t, b, []mtgban.Seller{
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{"FIXTUREA-1": {
			slab("NM", 7, 1, nil),
		}}, mtgban.ScraperInfo{Name: "RAW", Shorthand: "RAW"}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
			"FIXTUREA-1": {
				slab("NM", 5, 1, nil),
				slab("NM", 10, 1, &mtgban.Slab{Grader: "PSA", Score: 9}),
				slab("NM", 12, 2, &mtgban.Slab{Grader: "PSA", Score: 9}),
				slab("NM", 30, 1, &mtgban.Slab{Grader: "CGC", Score: 10, Label: "Pristine"}),
				slab("NM", 15, 1, &mtgban.Slab{Label: "SGC 9"}),
				slab("SP", 4, 1, &mtgban.Slab{Grader: "PSA", Score: 6}),
			},
			"FIXTUREA-2": {slab("NM", 20, 1, &mtgban.Slab{Grader: "PSA", Score: 9})},
		}, mtgban.ScraperInfo{Name: "SLAB", Shorthand: "SLAB", GradedMode: true}),
		mtgban.NewSellerFromInventory(mtgban.InventoryRecord{"FIXTUREA-1": {
			slab("NM", 9, 3, &mtgban.Slab{Grader: "BGS", Score: 9}),
		}}, mtgban.ScraperInfo{Name: "SLABNOQTY", Shorthand: "SLABNOQTY", GradedMode: true, NoQuantityInventory: true}),
	}, nil)

	w := httptest.NewRecorder()
	s.offline.Handle(w, httptest.NewRequest(http.MethodGet, "/api/offline/prices/FIXTUREA.bin", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	gr, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(gr)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := offline.Decode(data)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		cardID, store string
		prices        map[string]float64
		quantities    map[string]int
	}{
		{"FIXTUREA-1", "RAW", map[string]float64{"NM": 7}, map[string]int{"NM": 1}},
		{"FIXTUREA-1", "SLAB", map[string]float64{
			"NM":                 5,
			"NM|PSA 9":           10,
			"NM|CGC 10 Pristine": 30,
			"NM|SGC 9":           15,
			"SP|PSA 6":           4,
		}, map[string]int{"NM": 1, "NM|PSA 9": 3, "NM|CGC 10 Pristine": 1, "NM|SGC 9": 1, "SP|PSA 6": 1}},
		{"FIXTUREA-2", "SLAB", map[string]float64{"NM_foil|PSA 9": 20}, map[string]int{"NM_foil|PSA 9": 1}},
		{"FIXTUREA-1", "SLABNOQTY", map[string]float64{"NM|BGS 9": 9}, nil},
	} {
		entry := payload.Retail[tc.cardID][tc.store]
		if entry == nil {
			t.Errorf("%s at %s: no entry", tc.cardID, tc.store)
			continue
		}
		if !maps.Equal(entry.Conditions, tc.prices) || !maps.Equal(entry.Quantities, tc.quantities) {
			t.Errorf("%s at %s: prices %v quantities %v, want %v %v",
				tc.cardID, tc.store, entry.Conditions, entry.Quantities, tc.prices, tc.quantities)
		}
	}
}

// A seller of slabs named as its store is told apart by its name in the
// catalog.
func TestOfflineCatalogMarksAGradedStore(t *testing.T) {
	withSigMode(t, true, false)
	withConfigCopy(t)

	inv := mtgban.InventoryRecord{}
	inv.Add("FIXTUREA-1", &mtgban.InventoryEntry{Conditions: "NM", Price: 10, Quantity: 1, URL: "u"})
	s := fixtureSite(t, fixtureBackend("FIXTUREA", "Fixture Edition Alpha", "2020-01-01",
		[][2]string{{"Fixture Card Alpha", "1"}}), []mtgban.Seller{
		mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Name: "Same Store", Shorthand: "ZZSAME"}),
		mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Name: "Same Store", Shorthand: "ZZSLAB", GradedMode: true}),
	}, nil)
	s.offline.RefreshManifest()

	w := httptest.NewRecorder()
	s.offline.Handle(w, httptest.NewRequest(http.MethodGet, "/api/offline/catalog.json", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	gr, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	var catalog struct {
		Stores map[string]struct {
			Name string `json:"n"`
		} `json:"stores"`
	}
	err = json.NewDecoder(gr).Decode(&catalog)
	if err != nil {
		t.Fatal(err)
	}
	for shorthand, want := range map[string]string{"ZZSAME": "Same Store", "ZZSLAB": "Same Store (Graded)"} {
		if got := catalog.Stores[shorthand].Name; got != want {
			t.Errorf("%s is named %q, want %q", shorthand, got, want)
		}
	}
}
