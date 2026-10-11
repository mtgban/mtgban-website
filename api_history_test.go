package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/apisig"
	"github.com/mtgban/mtgban-website/timeseries"
)

// The budget is card-months: a request costs about as much per card per
// month of range cold whatever its shape, so the cards allowed shrink as the
// range grows, and one card is always allowed.
func TestHistoryCardsAllowed(t *testing.T) {
	for _, tc := range []struct{ days, months, cards int }{
		{1, 1, 120}, {30, 1, 120}, {44, 1, 120}, {45, 2, 60}, {90, 3, 40},
		{180, 6, 20}, {365, 12, 10}, {730, 24, 5}, {3650, 122, 1},
	} {
		if got := historyMonths(tc.days); got != tc.months {
			t.Errorf("historyMonths(%d) = %d, want %d", tc.days, got, tc.months)
		}
		if got := historyCardsAllowed(tc.days); got != tc.cards {
			t.Errorf("historyCardsAllowed(%d) = %d, want %d", tc.days, got, tc.cards)
		}
	}
}

// A response is good until the next archive write, at 00:00 and 12:00 on the
// host clock plus 21:00 off Magic, never for less than a minute, and for a
// minute in the half hour after a write hour.
func TestHistoryMaxAge(t *testing.T) {
	loc := time.FixedZone("host", 0)
	at := func(h, m, s int) time.Time { return time.Date(2026, 10, 11, h, m, s, 0, loc) }
	snapshot, tcgcsv := []int{0, 12}, []int{0, 12, 21}
	for _, tc := range []struct {
		now   time.Time
		hours []int
		want  int
	}{
		{at(3, 0, 0), snapshot, 9 * 3600},
		{at(11, 59, 0), snapshot, 60},
		{at(11, 59, 30), snapshot, 60},
		{at(12, 0, 0), snapshot, 60},
		{at(12, 29, 59), snapshot, 60},
		{at(12, 30, 0), snapshot, 11*3600 + 1800},
		{at(23, 30, 0), snapshot, 1800},
		{at(0, 0, 0), snapshot, 60},
		{at(0, 5, 0), snapshot, 60},
		{at(0, 31, 0), snapshot, 11*3600 + 29*60},
		{at(20, 30, 0), tcgcsv, 1800},
		{at(21, 0, 0), tcgcsv, 60},
		{at(21, 10, 0), tcgcsv, 60},
		{at(21, 30, 0), tcgcsv, 2*3600 + 1800},
		{at(13, 0, 0), []int{21, 12, 0}, 8 * 3600},
	} {
		if got := historyMaxAge(tc.now, tc.hours); got != tc.want {
			t.Errorf("historyMaxAge(%s, %v) = %d, want %d", tc.now.Format("15:04:05"), tc.hours, got, tc.want)
		}
	}
}

// A Magic host's archive is written at 00:00 and 12:00; any other game's at
// 21:00 too, wherever its tcgcsv ingest runs.
func TestHistoryCacheHours(t *testing.T) {
	withConfigCopy(t)
	Config().Game = DefaultGame
	if got := historyCacheHours(); !slices.Equal(got, []int{0, 12}) {
		t.Errorf("magic = %v", got)
	}
	Config().Game = "lorcana"
	if got := historyCacheHours(); !slices.Equal(got, []int{0, 12, 21}) {
		t.Errorf("lorcana = %v", got)
	}
	at := time.Date(2026, 10, 11, 21, 10, 0, 0, time.Local)
	if got := historyMaxAge(at, historyCacheHours()); got != 60 {
		t.Errorf("lorcana at 21:10 = %d, want 60", got)
	}
}

// The key table is historyDefaultKeys. A dataset with a provider id re-keys
// it to the first non-sealed entry of its list, under that list's section,
// unless another provider holds that key; one with no provider id is ignored.
func TestBuildHistoryKeys(t *testing.T) {
	if got := buildHistoryKeys(nil); !maps.Equal(got, historyDefaultKeys) {
		t.Errorf("no datasets = %v, want the defaults", got)
	}
	keys := buildHistoryKeys([]DatasetConfig{
		{Provider: 3, Retail: []string{"TCGLowX", "TCGSealed"}},
		{Provider: 5, Retail: []string{"CK"}},
		{Provider: 0, Retail: []string{"Nope"}},
		{Provider: 3, Retail: []string{"Dup"}},
		{Provider: 2, Buylist: []string{"CK", "CKSealed"}},
	})
	for _, tc := range []struct {
		provider int16
		want     historyKey
	}{
		{3, historyKey{"retail", "TCGLowX"}},
		{5, historyKey{"retail", "TCGMid"}},
		{1, historyKey{"retail", "CK"}},
		{2, historyKey{"buylist", "CK"}},
		{10, historyKey{"buylist", "SCG"}},
	} {
		if got := keys[tc.provider]; got != tc.want {
			t.Errorf("provider %d = %+v, want %+v", tc.provider, got, tc.want)
		}
	}
	if _, ok := keys[0]; ok || len(keys) != len(historyDefaultKeys) {
		t.Errorf("a dataset with no provider id was keyed: %v", keys)
	}
	held := map[historyKey]int16{}
	for id, k := range keys {
		if other, dup := held[k]; dup {
			t.Errorf("providers %d and %d share %+v", other, id, k)
		}
		held[k] = id
	}
	// Two overrides on one key: the first seen keeps it.
	both := buildHistoryKeys([]DatasetConfig{
		{Provider: 4, Retail: []string{"TCGX"}},
		{Provider: 6, Retail: []string{"TCGX"}},
	})
	if both[4] != (historyKey{"retail", "TCGX"}) || both[6] != (historyKey{"retail", "TCGHigh"}) {
		t.Errorf("two overrides on TCGX: 4 = %+v, 6 = %+v", both[4], both[6])
	}
	// A list of nothing but sealed entries keeps its first entry.
	only := buildHistoryKeys([]DatasetConfig{{Provider: 1, Retail: []string{"CKSealed"}}})
	if only[1] != (historyKey{"retail", "CKSealed"}) {
		t.Errorf("sealed-only list = %+v", only[1])
	}
}

// Overrides are checked against the table they make together, not the table
// mid-loop: a provider may take a key whose holder a later dataset moves off,
// in either dataset order. A provider refused keeps its default, which can
// in turn refuse the override that wanted it.
func TestBuildHistoryKeysOrder(t *testing.T) {
	onto := DatasetConfig{Provider: 5, Retail: []string{"CK"}}
	away := DatasetConfig{Provider: 1, Retail: []string{"CKX"}}
	for name, datasets := range map[string][]DatasetConfig{
		"onto first": {onto, away},
		"away first": {away, onto},
	} {
		keys := buildHistoryKeys(datasets)
		if keys[5] != (historyKey{"retail", "CK"}) || keys[1] != (historyKey{"retail", "CKX"}) {
			t.Errorf("%s: 5 = %+v, 1 = %+v, want CK and CKX", name, keys[5], keys[1])
		}
	}
	// 1 wants 6's default while 6 stays, so 1 keeps CK and 5 is refused too.
	keys := buildHistoryKeys([]DatasetConfig{onto, {Provider: 1, Retail: []string{"TCGHigh"}}})
	if keys[5] != historyDefaultKeys[5] || keys[1] != historyDefaultKeys[1] || keys[6] != historyDefaultKeys[6] {
		t.Errorf("cascade: 5 = %+v, 1 = %+v, 6 = %+v, want the defaults", keys[5], keys[1], keys[6])
	}
}

// A config reload that drops datasets_path charts nothing and reads history
// by the default keys, as Datasets() answers nil; one keeping it keeps both.
func TestFinishConfigWithoutDatasetsPathResetsHistoryKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "datasets.json")
	data := []byte(`[{"retail": ["TCGX"], "public_name": "TCGplayer X", "index": 1, "provider": 4}]`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	withDatasetsConfig(t, path)
	savedKeys := historyKeyTable.Load()
	t.Cleanup(func() { historyKeyTable.Store(savedKeys) })
	if err := loadDatasets(context.Background()); err != nil {
		t.Fatal(err)
	}
	moved := historyKey{"retail", "TCGX"}
	if got := historyKeys()[4]; got != moved {
		t.Fatalf("provider 4 = %+v after the file, want %+v", got, moved)
	}

	finishConfig(*Config())
	if got := historyKeys()[4]; got != moved || len(chartProviders()) != 1 {
		t.Errorf("a reload keeping datasets_path: provider 4 = %+v, %d providers", got, len(chartProviders()))
	}

	config := *Config()
	config.DatasetsPath = ""
	finishConfig(config)
	if got := historyKeys(); !maps.Equal(got, historyDefaultKeys) || len(chartProviders()) != 0 {
		t.Errorf("a reload dropping datasets_path: keys %v, %d providers, want the defaults and none", got, len(chartProviders()))
	}
}

// The default key table is the doc's source table, row for row.
func TestHistoryDefaultKeysMatchTheDoc(t *testing.T) {
	raw, err := os.ReadFile("docs/api-v2-history.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.ReplaceAll(string(raw), "\r\n", "\n")
	_, section, ok := strings.Cut(doc, "### Sources and the store keys they get")
	if !ok {
		t.Fatal("doc has no source table section")
	}
	section, _, _ = strings.Cut(section, "\n### ")
	row := regexp.MustCompile("(?m)^\\| (\\w+) \\((\\d+)\\) \\| (retail|buylist) \\| `(\\w+)` \\|$")
	got := map[int16]historyKey{}
	for _, m := range row.FindAllStringSubmatch(section, -1) {
		id, _ := strconv.Atoi(m[2])
		got[int16(id)] = historyKey{m[3], m[4]}
	}
	if len(got) != 13 {
		t.Errorf("doc table has %d rows, want 13", len(got))
	}
	if !maps.Equal(got, historyDefaultKeys) {
		t.Errorf("doc table %v\nhistoryDefaultKeys %v", got, historyDefaultKeys)
	}
	// The TCGplayer providers only tcgcsv writes, by literal.
	for id, want := range map[int16]historyKey{5: {"retail", "TCGMid"}, 6: {"retail", "TCGHigh"}, 7: {"retail", "TCGDirectLow"}} {
		if historyDefaultKeys[id] != want {
			t.Errorf("provider %d = %+v, want %+v", id, historyDefaultKeys[id], want)
		}
	}
	for _, id := range timeseries.ProviderIDs() {
		if _, ok := historyDefaultKeys[id]; !ok {
			t.Errorf("seeded provider %d has no default key", id)
		}
	}
}

// RFC 7232's weak comparison: a list, W/ prefixes and * all match.
func TestEtagMatches(t *testing.T) {
	const etag = `"abc"`
	for _, tc := range []struct {
		header string
		want   bool
	}{
		{`"abc"`, true},
		{`W/"abc"`, true},
		{`"x", W/"abc" , "y"`, true},
		{`*`, true},
		{`"abd"`, false},
		{`"x", "y"`, false},
		{``, false},
	} {
		if got := etagMatches(tc.header, etag); got != tc.want {
			t.Errorf("etagMatches(%q) = %t, want %t", tc.header, got, tc.want)
		}
	}
}

// range=N is the last N calendar days on the host clock, today included.
func TestHistorySince(t *testing.T) {
	loc := time.FixedZone("host", -5*3600)
	now := time.Date(2026, 10, 11, 14, 0, 0, 0, loc)
	for _, tc := range []struct {
		days int
		want time.Time
	}{
		{1, time.Date(2026, 10, 11, 0, 0, 0, 0, loc)},
		{2, time.Date(2026, 10, 10, 0, 0, 0, 0, loc)},
		{30, time.Date(2026, 9, 12, 0, 0, 0, 0, loc)},
	} {
		if got := historySince(now, tc.days); !got.Equal(tc.want) {
			t.Errorf("historySince(14:00, %d) = %s, want %s", tc.days, got, tc.want)
		}
	}
}

// The pivot files each card's rows under its id, finish and store key, with
// dates ascending, days without a price left out, and the newest date
// reported; two cards on one id and finish merge.
func TestHistoryPivot(t *testing.T) {
	keys := map[int16]historyKey{
		1: {"retail", "CK"}, 2: {"buylist", "CK"}, 3: {"retail", "TCGLow"},
	}
	cards := []historyCard{
		{ID: "scry-1", Finish: "nonfoil", BanID: 100},
		{ID: "scry-1", Finish: "foil", BanID: 101},
		{ID: "scry-1", Finish: "nonfoil", BanID: 102},
		{ID: "scry-2", Finish: "nonfoil", BanID: 103},
	}
	rows := map[int64]map[string]timeseries.ProviderPrices{
		100: {
			"2026-10-06": {1: 8.49, 2: 5.10, 3: 4.99},
			"2026-10-05": {1: 8.49, 3: 4.89},
			"2026-10-04": {9: 1.00}, // provider the table does not know
		},
		101: {"2026-10-06": {1: 16.99}},
		102: {"2026-10-07": {3: 5.05}},
	}
	retail, buylist, latest := historyPivot(cards, rows, keys)
	if latest != "2026-10-07" {
		t.Errorf("latest = %q", latest)
	}
	ck := retail["scry-1"]["nonfoil"]["CK"]
	if ck == nil || !slices.Equal(ck.Dates, []string{"2026-10-05", "2026-10-06"}) || !slices.Equal(ck.Prices, []float64{8.49, 8.49}) {
		t.Errorf("CK nonfoil = %+v", ck)
	}
	tcg := retail["scry-1"]["nonfoil"]["TCGLow"]
	if tcg == nil || !slices.Equal(tcg.Dates, []string{"2026-10-05", "2026-10-06", "2026-10-07"}) || !slices.Equal(tcg.Prices, []float64{4.89, 4.99, 5.05}) {
		t.Errorf("TCGLow nonfoil (merged across two ban ids) = %+v", tcg)
	}
	foil := retail["scry-1"]["foil"]["CK"]
	if foil == nil || !slices.Equal(foil.Dates, []string{"2026-10-06"}) || !slices.Equal(foil.Prices, []float64{16.99}) {
		t.Errorf("CK foil = %+v", foil)
	}
	bl := buylist["scry-1"]["nonfoil"]["CK"]
	if bl == nil || !slices.Equal(bl.Dates, []string{"2026-10-06"}) || !slices.Equal(bl.Prices, []float64{5.10}) {
		t.Errorf("CK buylist = %+v", bl)
	}
	if _, ok := retail["scry-2"]; ok {
		t.Error("a card with no rows was filed")
	}
	if _, ok := buylist["scry-1"]["foil"]; ok {
		t.Error("a finish with no buylist rows was filed under buylist")
	}
	if len(retail["scry-1"]["nonfoil"]) != 2 {
		t.Errorf("unknown provider 9 was filed: %v", retail["scry-1"]["nonfoil"])
	}
	r2, b2, l2 := historyPivot(nil, nil, keys)
	if len(r2) != 0 || len(b2) != 0 || l2 != "" {
		t.Errorf("empty pivot = %v %v %q", r2, b2, l2)
	}
}

// historyBackend holds one printing sold nonfoil and foil under one Scryfall
// id, a second printing, and a sealed product, all in set HST, and in set
// TWN a card filed as two finish twins, #4 nonfoil and #4★ foil.
func historyBackend() *mtgmatcher.Backend {
	card := func(uuid, finish, scryfall string, foil bool) *mtgmatcher.CardObject {
		co := &mtgmatcher.CardObject{Card: mtgmatcher.Card{
			UUID: uuid, Name: "Card " + uuid, SetCode: "HST", Number: "1",
			Identifiers: map[string]string{"scryfallId": scryfall, "mtgjsonId": uuid},
			Finishes:    []string{"nonfoil", "foil"},
			FoilUUIDs:   map[string]string{"nonfoil": strings.TrimSuffix(uuid, "_f"), "foil": strings.TrimSuffix(uuid, "_f") + "_f"},
		}, Foil: foil}
		co.Finish = finish
		return co
	}
	box := &mtgmatcher.CardObject{Card: mtgmatcher.Card{UUID: "box", Name: "HST Box", SetCode: "HST",
		Identifiers: map[string]string{"mtgjsonId": "box"}}, Sealed: true}
	twin := func(uuid, number, finish, other string) *mtgmatcher.CardObject {
		co := &mtgmatcher.CardObject{Card: mtgmatcher.Card{
			UUID: uuid, Name: "Twin", SetCode: "TWN", Number: number,
			Identifiers: map[string]string{"scryfallId": "scry-" + uuid, "mtgjsonId": uuid},
			Finishes:    []string{finish},
			FoilUUIDs:   map[string]string{finish: uuid},
			Variations:  []string{other},
		}, Foil: finish == "foil"}
		co.Finish = finish
		return co
	}
	return &mtgmatcher.Backend{
		AllUUIDs:       []string{"h-1", "h-1_f", "h-2", "h-4", "h-4s"},
		AllSealedUUIDs: []string{"box"},
		UUIDs: map[string]*mtgmatcher.CardObject{
			"h-1":   card("h-1", "nonfoil", "scry-1", false),
			"h-1_f": card("h-1_f", "foil", "scry-1", true),
			"h-2":   card("h-2", "nonfoil", "scry-2", false),
			"h-4":   twin("h-4", "4", "nonfoil", "h-4s"),
			"h-4s":  twin("h-4s", "4★", "foil", "h-4"),
			"box":   box,
		},
		Sets: map[string]*mtgmatcher.Set{
			"HST": {Code: "HST", Name: "History Test"},
			"TWN": {Code: "TWN", Name: "Twin Test"},
		},
		SetUUIDs:       map[string][]string{"HST": {"h-1", "h-1_f", "h-2"}, "TWN": {"h-4", "h-4s"}},
		SetSealedUUIDs: map[string][]string{"HST": {"box"}},
	}
}

// historyFixture swaps the archive read and the card-to-id map for fakes:
// h-1 is ban 100, h-1_f 101, h-2 103, h-4 104, h-4s 105, box 200. It
// returns the request log.
func historyFixture(t *testing.T, rows map[int64]map[string]timeseries.ProviderPrices, readErr error) *[][]int64 {
	t.Helper()
	prevRead, prevBan, prevKeys := historyRead, historyBanID, historyKeyTable.Load()
	t.Cleanup(func() {
		historyRead, historyBanID = prevRead, prevBan
		historyKeyTable.Store(prevKeys)
	})
	var asked [][]int64
	historyRead = func(ctx context.Context, ids []int64, since time.Time) (map[int64]map[string]timeseries.ProviderPrices, error) {
		asked = append(asked, slices.Clone(ids))
		if readErr != nil {
			return nil, readErr
		}
		out := map[int64]map[string]timeseries.ProviderPrices{}
		for _, id := range ids {
			if r, ok := rows[id]; ok {
				out[id] = r
			}
		}
		return out, nil
	}
	historyBanID = func(co *mtgmatcher.CardObject) int64 {
		return map[string]int64{"h-1": 100, "h-1_f": 101, "h-2": 103, "h-4": 104, "h-4s": 105, "box": 200}[co.UUID]
	}
	keys := map[int16]historyKey{1: {"retail", "CK"}, 2: {"buylist", "CK"}, 3: {"retail", "TCGLow"}, 13: {"retail", "TCGLowEV"}}
	historyKeyTable.Store(&keys)
	return &asked
}

var historyRows = map[int64]map[string]timeseries.ProviderPrices{
	100: {"2026-10-05": {1: 8.49, 3: 4.89}, "2026-10-06": {1: 8.49, 2: 5.10, 3: 4.99}},
	101: {"2026-10-06": {1: 16.99}},
	103: {"2026-10-06": {3: 0.25}},
	104: {"2026-10-06": {3: 1.25}},
	105: {"2026-10-06": {3: 9.75}},
	200: {"2026-10-06": {13: 120.5}},
}

type historyOut struct {
	Error string `json:"error"`
	Meta  struct {
		Date    time.Time `json:"date"`
		Version string    `json:"version"`
		Latest  string    `json:"latest"`
		Range   int       `json:"range"`
		Page    int       `json:"page"`
		Pages   int       `json:"pages"`
	} `json:"meta"`
	Retail  historyCards `json:"retail"`
	Buylist historyCards `json:"buylist"`
}

// historyServe calls the handler directly with a signature carrying fields.
func historyServe(t *testing.T, s *site, target string, fields url.Values, header http.Header) *httptest.ResponseRecorder {
	t.Helper()
	sig := signedAs(t, fields, time.Now().Add(time.Hour))
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	req := httptest.NewRequest(http.MethodGet, target+sep+"sig="+url.QueryEscape(sig), nil)
	for k, v := range header {
		req.Header[k] = v
	}
	rec := httptest.NewRecorder()
	s.HistoryAPI(rec, req)
	return rec
}

// historyFields are a key's signed fields: modes, and lookback as APIlookback when set.
func historyFields(modes, lookback string) url.Values {
	fields := url.Values{"APImode": {modes}, "UserEmail": {"h@example.com"}}
	if lookback != "" {
		fields.Set("APIlookback", lookback)
	}
	return fields
}

// historyGet calls the handler with modes and lookback signed, and decodes the JSON body.
func historyGet(t *testing.T, s *site, target, modes, lookback string, header http.Header) (*httptest.ResponseRecorder, historyOut) {
	t.Helper()
	rec := historyServe(t, s, target, historyFields(modes, lookback), header)
	var out historyOut
	if rec.Code != http.StatusNotModified {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s: %v\n%s", target, err, rec.Body.String())
		}
	}
	return rec, out
}

func historySite(t *testing.T) *site {
	t.Helper()
	signingEnabled(t, false)
	s := newSite()
	s.ds.Store(&datastore{backend: historyBackend()})
	return s
}

func TestHistoryAPIOneCard(t *testing.T) {
	s := historySite(t)
	asked := historyFixture(t, historyRows, nil)
	read := historyRead
	var since time.Time
	historyRead = func(ctx context.Context, ids []int64, from time.Time) (map[int64]map[string]timeseries.ProviderPrices, error) {
		since = from
		return read(ctx, ids, from)
	}
	rec, out := historyGet(t, s, "/api/v2/history/h-1.json", "history", "365", nil)
	if rec.Code != 200 || out.Error != "" {
		t.Fatalf("status %d error %q", rec.Code, out.Error)
	}
	if want := historySince(time.Now(), 365); !since.Equal(want) {
		t.Errorf("read since %s, want %s", since, want)
	}
	if out.Meta.Date.IsZero() {
		t.Error("meta.date is the zero time")
	}
	if len(*asked) != 1 || !slices.Equal((*asked)[0], []int64{100, 101}) {
		t.Errorf("read asked %v, want one read of [100 101]", *asked)
	}
	if out.Meta.Version != "2" || out.Meta.Latest != "2026-10-06" || out.Meta.Range != 365 || out.Meta.Page != 0 {
		t.Errorf("meta %+v", out.Meta)
	}
	ck := out.Retail["scry-1"]["nonfoil"]["CK"]
	if ck == nil || !slices.Equal(ck.Dates, []string{"2026-10-05", "2026-10-06"}) {
		t.Errorf("CK nonfoil %+v", ck)
	}
	if out.Retail["scry-1"]["foil"]["CK"] == nil || out.Buylist["scry-1"]["nonfoil"]["CK"] == nil {
		t.Errorf("foil or buylist missing: %v / %v", out.Retail, out.Buylist)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.HasPrefix(cc, "public, max-age=") {
		t.Errorf("Cache-Control %q", cc)
	}
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag")
	}
	rec2, _ := historyGet(t, s, "/api/v2/history/h-1.json", "history", "365", http.Header{"If-None-Match": {etag}})
	if rec2.Code != http.StatusNotModified || rec2.Body.Len() != 0 {
		t.Errorf("If-None-Match: status %d body %d bytes", rec2.Code, rec2.Body.Len())
	}
	rec3, _ := historyGet(t, s, "/api/v2/history/h-1.json", "history", "365", http.Header{"If-None-Match": {`"other", W/` + etag}})
	if rec3.Code != http.StatusNotModified {
		t.Errorf("If-None-Match list with a weak tag: status %d", rec3.Code)
	}
}

// The CSV form answers the same points as a flat table ordered by id,
// finish, store and date, retail first, with meta in headers and the JSON
// form's caching; errors stay JSON.
func TestHistoryAPICSV(t *testing.T) {
	s := historySite(t)
	historyFixture(t, historyRows, nil)
	rec := historyServe(t, s, "/api/v2/history/h-1.csv", historyFields("history", "365"), nil)
	want := "id,finish,store,section,date,price\n" +
		"scry-1,foil,CK,retail,2026-10-06,16.99\n" +
		"scry-1,nonfoil,CK,retail,2026-10-05,8.49\n" +
		"scry-1,nonfoil,CK,retail,2026-10-06,8.49\n" +
		"scry-1,nonfoil,CK,buylist,2026-10-06,5.1\n" +
		"scry-1,nonfoil,TCGLow,retail,2026-10-05,4.89\n" +
		"scry-1,nonfoil,TCGLow,retail,2026-10-06,4.99\n"
	if rec.Code != 200 || rec.Body.String() != want {
		t.Errorf("h-1.csv: %d\n%s\nwant\n%s", rec.Code, rec.Body.String(), want)
	}
	h := rec.Header()
	if h.Get("Content-Type") != "text/csv" || h.Get("X-MTGBAN-Latest") != "2026-10-06" || h.Get("X-MTGBAN-Range") != "365" {
		t.Errorf("headers %v", h)
	}
	if h.Get("X-MTGBAN-Page") != "" || h.Get("X-MTGBAN-Pages") != "" {
		t.Errorf("a card form has page headers: %v", h)
	}
	if cc := h.Get("Cache-Control"); !strings.HasPrefix(cc, "public, max-age=") {
		t.Errorf("Cache-Control %q", cc)
	}
	etag := h.Get("ETag")
	jsonRec, _ := historyGet(t, s, "/api/v2/history/h-1.json", "history", "365", nil)
	if etag == "" || etag == jsonRec.Header().Get("ETag") {
		t.Errorf("CSV ETag %q, JSON's %q", etag, jsonRec.Header().Get("ETag"))
	}
	again := historyServe(t, s, "/api/v2/history/h-1.csv", historyFields("history", "365"), nil)
	if again.Header().Get("ETag") != etag {
		t.Errorf("ETag moved between two reads: %q then %q", etag, again.Header().Get("ETag"))
	}
	notModified := historyServe(t, s, "/api/v2/history/h-1.csv", historyFields("history", "365"), http.Header{"If-None-Match": {etag}})
	if notModified.Code != http.StatusNotModified || notModified.Body.Len() != 0 {
		t.Errorf("If-None-Match: %d, %d bytes", notModified.Code, notModified.Body.Len())
	}
	// A set page carries its page and page count.
	page := historyServe(t, s, "/api/v2/history/hst.csv?page=2", historyFields("history", "3650"), nil)
	if page.Header().Get("X-MTGBAN-Page") != "2" || page.Header().Get("X-MTGBAN-Pages") != "3" || !strings.Contains(page.Body.String(), "\nscry-1,foil,CK,retail,2026-10-06,16.99\n") {
		t.Errorf("hst.csv page 2: %v\n%s", page.Header(), page.Body.String())
	}
	// Nothing found is the header row alone, uncached.
	historyFixture(t, map[int64]map[string]timeseries.ProviderPrices{}, nil)
	empty := historyServe(t, s, "/api/v2/history/h-2.csv", historyFields("history", "365"), nil)
	if empty.Code != 200 || empty.Body.String() != "id,finish,store,section,date,price\n" || empty.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("empty CSV: %d %q %q", empty.Code, empty.Body.String(), empty.Header().Get("Cache-Control"))
	}
	missing := historyServe(t, s, "/api/v2/history/nope.csv", historyFields("history", "365"), nil)
	if missing.Code != 404 || missing.Header().Get("Content-Type") != "application/json" || !strings.Contains(missing.Body.String(), "Not found") {
		t.Errorf("unknown id in CSV: %d %q %s", missing.Code, missing.Header().Get("Content-Type"), missing.Body.String())
	}
}

func TestHistoryAPIIDModesAndRange(t *testing.T) {
	s := historySite(t)
	historyFixture(t, historyRows, nil)
	_, out := historyGet(t, s, "/api/v2/history/h-1.json?id=mtgjson", "history", "365", nil)
	if out.Retail["h-1"]["nonfoil"]["CK"] == nil || out.Retail["h-1_f"]["foil"]["CK"] == nil {
		t.Errorf("id=mtgjson keys: %v", out.Retail)
	}
	rec, out := historyGet(t, s, "/api/v2/history/h-1.json?id=nope", "history", "365", nil)
	if rec.Code != 400 || !strings.Contains(out.Error, `unknown id "nope"`) {
		t.Errorf("bad id mode: %d %q", rec.Code, out.Error)
	}
	_, out = historyGet(t, s, "/api/v2/history/box.json", "history", "365", nil)
	if out.Retail["box"]["sealed"]["TCGLowEV"] == nil {
		t.Errorf("sealed defaults to mtgjson under finish sealed: %v", out.Retail)
	}
	// range clamps to the lookback, defaults to it, and rejects junk.
	_, out = historyGet(t, s, "/api/v2/history/h-1.json?range=900", "history", "365", nil)
	if out.Meta.Range != 365 {
		t.Errorf("range 900 under lookback 365 = %d", out.Meta.Range)
	}
	_, out = historyGet(t, s, "/api/v2/history/h-1.json?range=7", "history", "365", nil)
	if out.Meta.Range != 7 {
		t.Errorf("range 7 = %d", out.Meta.Range)
	}
	_, out = historyGet(t, s, "/api/v2/history/h-1.json", "history", "", nil)
	if out.Meta.Range != 30 {
		t.Errorf("no lookback in the signature = %d, want the 30-day fallback", out.Meta.Range)
	}
	// The site's chart field is not the API's lookback.
	chartOnly := historyFields("history", "")
	chartOnly.Set("SearchChartLoopback", "365")
	if err := json.Unmarshal(historyServe(t, s, "/api/v2/history/h-1.json", chartOnly, nil).Body.Bytes(), &out); err != nil || out.Meta.Range != 30 {
		t.Errorf("SearchChartLoopback alone = %d (%v), want the 30-day fallback", out.Meta.Range, err)
	}
	for _, bad := range []string{"x", "0", "-5"} {
		_, out = historyGet(t, s, "/api/v2/history/h-1.json", "history", bad, nil)
		if out.Meta.Range != 30 {
			t.Errorf("APIlookback %q = %d, want the 30-day fallback", bad, out.Meta.Range)
		}
	}
	for _, bad := range []string{"0", "-3", "x"} {
		rec, out := historyGet(t, s, "/api/v2/history/h-1.json?range="+bad, "history", "365", nil)
		if rec.Code != 400 || !strings.Contains(out.Error, "range") {
			t.Errorf("range=%s: %d %q", bad, rec.Code, out.Error)
		}
	}
}

func TestHistoryAPIBatchAndBudget(t *testing.T) {
	s := historySite(t)
	asked := historyFixture(t, historyRows, nil)
	_, out := historyGet(t, s, "/api/v2/history/h-1,h-2,h-1,unknown-id.json", "history", "365", nil)
	if out.Error != "" || len(out.Retail) != 2 || out.Retail["scry-2"]["nonfoil"]["TCGLow"] == nil {
		t.Errorf("batch: %q %v", out.Error, out.Retail)
	}
	if len(*asked) != 1 || !slices.Equal((*asked)[0], []int64{100, 101, 103}) {
		t.Errorf("batch asked %v", *asked)
	}
	// A batch that resolves no card is a 404, like one unknown id, and reads nothing.
	reads := len(*asked)
	rec, out := historyGet(t, s, "/api/v2/history/a,b.json", "history", "365", nil)
	if rec.Code != 404 || out.Error != "Not found" || len(*asked) != reads {
		t.Errorf("all unknown ids: %d %q, reads %d -> %d", rec.Code, out.Error, reads, len(*asked))
	}
	// Ten repeats of h-1 plus h-2 is two distinct ids, three printings by
	// finish (h-1 nonfoil, h-1 foil, h-2 nonfoil), well under the budget.
	ids := strings.Repeat("h-1,", 10) + "h-2"
	_, out = historyGet(t, s, "/api/v2/history/"+ids+".json", "history", "365", nil)
	if out.Error != "" {
		t.Errorf("two distinct ids (h-1 repeated) over a year: %q", out.Error)
	}
	// Eleven ids, several unknown, resolve to four printings by finish
	// (h-1 nonfoil, h-1 foil reached from both h-1 and h-1_f, h-2 nonfoil,
	// the sealed box): under the ten allowed over a year, and under the
	// 120 allowed over 30 days.
	eleven := "h-1,h-2,h-1_f,box,a,b,c,d,e,f,g"
	rec, out = historyGet(t, s, "/api/v2/history/"+eleven+".json", "history", "365", nil)
	if rec.Code != 200 {
		t.Errorf("eleven ids, four printings, over a year: %d %q", rec.Code, out.Error)
	}
	rec, _ = historyGet(t, s, "/api/v2/history/"+eleven+".json?range=30", "history", "365", nil)
	if rec.Code != 200 {
		t.Errorf("eleven over 30 days: %d", rec.Code)
	}
	// h-1 and h-2 resolve to three printings by finish, one over the
	// allowance of one card-month at 3650 days.
	rec, out = historyGet(t, s, "/api/v2/history/h-1,h-2.json?range=3650", "history", "3650", nil)
	if rec.Code != 400 || !strings.Contains(out.Error, "at most 1 over 3650 days") {
		t.Errorf("three printings over the one allowed at 3650 days: %d %q", rec.Code, out.Error)
	}
	// h-1 and h-1_f resolve to the same two printings (nonfoil and foil);
	// the archive read asks for each id once, not twice.
	_, out = historyGet(t, s, "/api/v2/history/h-1,h-1_f.json", "history", "365", nil)
	if out.Error != "" {
		t.Errorf("h-1 and h-1_f dedupe: %q", out.Error)
	}
	if got := (*asked)[len(*asked)-1]; !slices.Equal(got, []int64{100, 101}) {
		t.Errorf("h-1,h-1_f asked %v, want [100 101] once", got)
	}
	// One id is exempt, a trailing comma included: both finishes at an allowance of one.
	rec, out = historyGet(t, s, "/api/v2/history/h-1,.json", "history", "3650", nil)
	if rec.Code != 200 || out.Retail["scry-1"]["nonfoil"]["CK"] == nil || out.Retail["scry-1"]["foil"]["CK"] == nil {
		t.Errorf("one id at 3650 days: %d %q %v", rec.Code, out.Error, out.Retail)
	}
	// Past three ids a card allowed is refused before anything resolves or reads.
	reads = len(*asked)
	rec, out = historyGet(t, s, "/api/v2/history/h-1,h-2,a,b.json", "history", "3650", nil)
	if rec.Code != 400 || out.Error != "at most 3 ids over 3650 days" || len(*asked) != reads {
		t.Errorf("four ids at 3650 days: %d %q, reads %d -> %d", rec.Code, out.Error, reads, len(*asked))
	}
}

func TestHistoryAPISetPages(t *testing.T) {
	s := historySite(t)
	asked := historyFixture(t, historyRows, nil)
	// Lookback 3650 allows one card a page, so HST's three printings are three pages.
	_, out := historyGet(t, s, "/api/v2/history/hst.json", "history", "3650", nil)
	if out.Meta.Page != 1 || out.Meta.Pages != 3 || out.Retail["scry-1"]["nonfoil"] == nil || len(out.Retail) != 1 {
		t.Errorf("page 1: meta %+v retail %v", out.Meta, out.Retail)
	}
	if len(*asked) != 1 || !slices.Equal((*asked)[0], []int64{100}) {
		t.Errorf("page 1 asked %v", *asked)
	}
	_, out = historyGet(t, s, "/api/v2/history/HST.json?page=2", "history", "3650", nil)
	if out.Meta.Page != 2 || out.Retail["scry-1"]["foil"]["CK"] == nil {
		t.Errorf("page 2: %+v %v", out.Meta, out.Retail)
	}
	rec, out := historyGet(t, s, "/api/v2/history/hst.json?page=4", "history", "3650", nil)
	if rec.Code != 404 || !strings.Contains(out.Error, "page") {
		t.Errorf("page past the end: %d %q", rec.Code, out.Error)
	}
	rec, _ = historyGet(t, s, "/api/v2/history/hst.json?page=0", "history", "3650", nil)
	if rec.Code != 400 {
		t.Errorf("page 0: %d", rec.Code)
	}
	_, out = historyGet(t, s, "/api/v2/history/hst.json", "history", "365", nil)
	if out.Meta.Pages != 1 || len(out.Retail) != 2 {
		t.Errorf("a year allows ten a page: %+v %v", out.Meta, out.Retail)
	}
	_, out = historyGet(t, s, "/api/v2/history/sealed/hst.json", "history", "365", nil)
	if out.Meta.Pages != 1 || out.Retail["box"]["sealed"]["TCGLowEV"] == nil {
		t.Errorf("sealed set: %+v %v", out.Meta, out.Retail)
	}
	rec, _ = historyGet(t, s, "/api/v2/history/sealed/nope.json", "history", "365", nil)
	if rec.Code != 404 {
		t.Errorf("unknown sealed set: %d", rec.Code)
	}
}

func TestHistoryAPIRefusals(t *testing.T) {
	s := historySite(t)
	historyFixture(t, historyRows, nil)
	for _, tc := range []struct {
		target, modes string
		status        int
		want          string
	}{
		{"/api/v2/history/h-1.json", "retail,buylist", 403, "history"},
		{"/api/v2/history/h-1", "history", 404, "Not found"},
		{"/api/v2/history/.json", "history", 404, "Not found"},
		{"/api/v2/history/.csv", "history", 404, "Not found"},
		{"/api/v2/history/,.json", "history", 404, "Not found"},
		{"/api/v2/history/sealed/.json", "history", 404, "Not found"},
		{"/api/v2/history/sealed/h-1,h-2.json", "history", 404, "Not found"},
		{"/api/v2/history/nope.json", "history", 404, "Not found"},
		{"/api/v2/history/a/b/c.json", "history", 404, "Not found"},
	} {
		rec, out := historyGet(t, s, tc.target, tc.modes, "365", nil)
		if rec.Code != tc.status || !strings.Contains(out.Error, tc.want) {
			t.Errorf("%s (%s): %d %q, want %d containing %q", tc.target, tc.modes, rec.Code, out.Error, tc.status, tc.want)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("%s: Cache-Control %q on an error", tc.target, cc)
		}
	}
	// "all" grants history like any mode.
	rec, _ := historyGet(t, s, "/api/v2/history/h-1.json", "all", "365", nil)
	if rec.Code != 200 {
		t.Errorf("APImode all: %d", rec.Code)
	}
}

func TestHistoryAPIEmptyAndUnavailable(t *testing.T) {
	s := historySite(t)
	historyFixture(t, map[int64]map[string]timeseries.ProviderPrices{}, nil)
	rec, out := historyGet(t, s, "/api/v2/history/h-2.json", "history", "365", nil)
	if rec.Code != 200 || out.Error != "" || len(out.Retail) != 0 || out.Meta.Latest != "" {
		t.Errorf("no rows: %d %q %v latest %q", rec.Code, out.Error, out.Retail, out.Meta.Latest)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("empty response Cache-Control %q", cc)
	}
	historyFixture(t, nil, errors.New("boom"))
	rec, out = historyGet(t, s, "/api/v2/history/h-1.json", "history", "365", nil)
	if rec.Code != 503 || out.Error == "" || rec.Header().Get("Retry-After") != "30" {
		t.Errorf("read error: %d %q Retry-After %q", rec.Code, out.Error, rec.Header().Get("Retry-After"))
	}
}

// While the archive is being written the answer is served but not cached.
func TestHistoryAPIDuringASnapshot(t *testing.T) {
	s := historySite(t)
	historyFixture(t, historyRows, nil)
	prev := historyStashing
	t.Cleanup(func() { historyStashing = prev })
	historyStashing = func() bool { return true }
	rec, out := historyGet(t, s, "/api/v2/history/h-1.json", "history", "365", nil)
	if rec.Code != 200 || out.Retail["scry-1"]["nonfoil"]["CK"] == nil {
		t.Fatalf("mid-snapshot: %d %q %v", rec.Code, out.Error, out.Retail)
	}
	if cc, etag := rec.Header().Get("Cache-Control"), rec.Header().Get("ETag"); cc != "no-store" || etag != "" {
		t.Errorf("mid-snapshot: Cache-Control %q ETag %q", cc, etag)
	}
}

// A stash that finishes while the read is in flight is still caught: the
// flag is sampled before the read as well as after.
func TestHistoryAPIStashFinishesDuringTheRead(t *testing.T) {
	s := historySite(t)
	historyFixture(t, historyRows, nil)
	prev := historyStashing
	t.Cleanup(func() { historyStashing = prev })
	calls := 0
	historyStashing = func() bool {
		calls++
		return calls == 1
	}
	rec, out := historyGet(t, s, "/api/v2/history/h-1.json", "history", "365", nil)
	if rec.Code != 200 || out.Retail["scry-1"]["nonfoil"]["CK"] == nil {
		t.Fatalf("stash-during-read: %d %q %v", rec.Code, out.Error, out.Retail)
	}
	if cc, etag := rec.Header().Get("Cache-Control"), rec.Header().Get("ETag"); cc != "no-store" || etag != "" {
		t.Errorf("stash-during-read: Cache-Control %q ETag %q", cc, etag)
	}
	// The old code sampled once, after the read, and would miss this case.
	if calls != 2 {
		t.Errorf("historyStashing called %d times, want 2 (before and after the read)", calls)
	}
}

// A request that finds every read slot taken waits a bounded time, then is
// told to come back.
func TestHistoryAPIBusy(t *testing.T) {
	s := historySite(t)
	asked := historyFixture(t, historyRows, nil)
	prevWait := historySlotWait
	historySlotWait = 5 * time.Millisecond
	for range historyConcurrency {
		historySlots <- struct{}{}
	}
	t.Cleanup(func() {
		for range historyConcurrency {
			<-historySlots
		}
		historySlotWait = prevWait
	})
	rec, out := historyGet(t, s, "/api/v2/history/h-1.json", "history", "365", nil)
	if rec.Code != 503 || out.Error != "price history is busy" || rec.Header().Get("Retry-After") != "5" {
		t.Errorf("busy: %d %q Retry-After %q", rec.Code, out.Error, rec.Header().Get("Retry-After"))
	}
	if len(*asked) != 0 {
		t.Errorf("busy request read %v", *asked)
	}
}

// The history route reaches HistoryAPI, in JSON and CSV, and the rest of
// /api/v2/ still reaches PriceAPIv2. registerRoutes fills the default mux,
// so this mirrors its lines.
func TestHistoryAPIRoutes(t *testing.T) {
	s := historySite(t)
	historyFixture(t, historyRows, nil)
	seedV2Scrapers(t)
	mux := http.NewServeMux()
	mux.Handle("/api/v2/history/", enforceAPISigning(http.HandlerFunc(s.HistoryAPI)))
	mux.Handle("/api/v2/", enforceAPISigning(http.HandlerFunc(s.PriceAPIv2)))
	sig := url.QueryEscape(apisig.Mint([]byte(os.Getenv("BAN_SECRET")), signatureLink(), apisig.Claims{
		API:     "ALL_ACCESS",
		Fields:  url.Values{"APImode": {"all"}, "UserEmail": {"h@example.com"}, "APIlookback": {"365"}},
		Expires: time.Now().Add(time.Hour).Unix(),
	}))
	serve := func(i int, target string) *httptest.ResponseRecorder {
		t.Helper()
		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}
		req := httptest.NewRequest(http.MethodGet, target+sep+"sig="+sig, nil)
		// a fresh address each, so the API rate limit stays out of it
		req.RemoteAddr = fmt.Sprintf("198.51.100.%d:1234", i+1)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	for i, target := range []string{
		"/api/v2/history/h-1,h-2.json",
		"/api/v2/history/h-1.json",
		"/api/v2/history/sealed/hst.json",
	} {
		rec := serve(i, target)
		var out historyOut
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s: %v\n%s", target, err, rec.Body.String())
		}
		// Only HistoryAPI answers with meta.range.
		if rec.Code != 200 || out.Meta.Range != 365 {
			t.Errorf("%s: %d %q range %d, want 200 from HistoryAPI", target, rec.Code, out.Error, out.Meta.Range)
		}
	}
	// Only HistoryAPI answers CSV with the range header.
	for i, target := range []string{"/api/v2/history/h-1,h-2.csv", "/api/v2/history/hst.csv"} {
		rec := serve(5+i, target)
		if rec.Code != 200 || rec.Header().Get("X-MTGBAN-Range") != "365" || !strings.HasPrefix(rec.Body.String(), "id,finish,store,section,date,price\n") {
			t.Errorf("%s: %d range %q\n%s", target, rec.Code, rec.Header().Get("X-MTGBAN-Range"), rec.Body.String())
		}
	}
	rec := serve(9, "/api/v2/retail.json")
	var v2 struct {
		Error string         `json:"error"`
		Meta  map[string]any `json:"meta"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v2); err != nil {
		t.Fatalf("retail.json: %v\n%s", err, rec.Body.String())
	}
	_, latest := v2.Meta["latest"]
	_, hasRange := v2.Meta["range"]
	if v2.Meta["version"] != APIVersionV2 || latest || hasRange {
		t.Errorf("retail.json did not reach PriceAPIv2: %d %q meta %v", rec.Code, v2.Error, v2.Meta)
	}
}

// Dev mode without signatures takes the history package's lookback, so a
// batch fits the budget.
func TestHistoryAPIDevLookback(t *testing.T) {
	s := historySite(t)
	historyFixture(t, historyRows, nil)
	withSigMode(t, true, false)
	rec, out := historyGet(t, s, "/api/v2/history/h-1,h-2,h-1_f,box.json", "history", "", nil)
	if rec.Code != 200 || out.Error != "" || out.Meta.Range != 365 {
		t.Errorf("dev batch of four: %d %q range %d", rec.Code, out.Error, out.Meta.Range)
	}
}

// A card filed as two finish twins reads as one card in both finishes,
// whichever twin is named, the named one first; an unknown id is nil.
func TestHistoryAPIFinishTwins(t *testing.T) {
	s := historySite(t)
	asked := historyFixture(t, historyRows, nil)
	b := historyBackend()
	if got := finishUUIDs(b, "h-4s"); !slices.Equal(got, []string{"h-4s", "h-4"}) {
		t.Errorf("finishUUIDs(h-4s) = %v, want [h-4s h-4]", got)
	}
	if got := finishUUIDs(b, "h-4"); !slices.Equal(got, []string{"h-4", "h-4s"}) {
		t.Errorf("finishUUIDs(h-4) = %v, want [h-4 h-4s]", got)
	}
	if got := finishUUIDs(b, "nope"); got != nil {
		t.Errorf("finishUUIDs(nope) = %v, want nil", got)
	}
	for _, tc := range []struct {
		id    string
		asked []int64
	}{
		{"h-4s", []int64{105, 104}},
		{"h-4", []int64{104, 105}},
	} {
		rec, out := historyGet(t, s, "/api/v2/history/"+tc.id+".json?id=mtgjson", "history", "365", nil)
		if rec.Code != 200 || out.Retail["h-4"]["nonfoil"]["TCGLow"] == nil || out.Retail["h-4s"]["foil"]["TCGLow"] == nil {
			t.Errorf("%s: %d %q %v", tc.id, rec.Code, out.Error, out.Retail)
		}
		if got := (*asked)[len(*asked)-1]; !slices.Equal(got, tc.asked) {
			t.Errorf("%s asked %v, want %v", tc.id, got, tc.asked)
		}
	}
}

// Pacifism 7ED #29 and its foil twin #29★ are separate printings in the
// datastore: each id reaches the other, itself first, once each.
func TestFinishUUIDsReachTheFoilTwin(t *testing.T) {
	skipWithoutDatastore(t)
	b := backend()
	var plain, star string
	for _, uuid := range b.GetUUIDsInSet("7ED") {
		co, err := b.GetUUID(uuid)
		if err != nil || co.Name != "Pacifism" {
			continue
		}
		switch co.Number {
		case "29":
			plain = uuid
		case "29★":
			star = uuid
		}
	}
	if plain == "" || star == "" {
		t.Fatalf("Pacifism 7ED #29 %q, #29★ %q", plain, star)
	}
	for _, tc := range [][2]string{{plain, star}, {star, plain}} {
		got := finishUUIDs(b, tc[0])
		if len(got) == 0 || got[0] != tc[0] || !slices.Contains(got, tc[1]) || len(slices.Compact(slices.Sorted(slices.Values(got)))) != len(got) {
			t.Errorf("finishUUIDs(%s) = %v, want %s first, %s in it, no repeats", tc[0], got, tc[0], tc[1])
		}
	}
}

// A card the id mode has no id for is left out, as v2 prices leave it out.
func TestHistoryAPISkipsCardsTheModeCannotKey(t *testing.T) {
	s := historySite(t)
	historyFixture(t, historyRows, nil)
	b := historyBackend()
	delete(b.UUIDs["h-2"].Identifiers, "scryfallId")
	s.ds.Store(&datastore{backend: b})
	rec, out := historyGet(t, s, "/api/v2/history/h-2.json", "history", "365", nil)
	if rec.Code != 200 || len(out.Retail) != 0 {
		t.Errorf("no scryfall id, default mode: %d %q %v", rec.Code, out.Error, out.Retail)
	}
	_, out = historyGet(t, s, "/api/v2/history/h-2.json?id=mtgjson", "history", "365", nil)
	if out.Retail["h-2"]["nonfoil"]["TCGLow"] == nil {
		t.Errorf("no scryfall id, id=mtgjson: %q %v", out.Error, out.Retail)
	}
}

// A card the variant cache does not know is left out, and a request made of
// nothing else still reads (an empty list) rather than failing.
func TestHistoryAPIUnknownToTheCache(t *testing.T) {
	s := historySite(t)
	asked := historyFixture(t, historyRows, nil)
	prev := historyBanID
	historyBanID = func(co *mtgmatcher.CardObject) int64 {
		if co.UUID == "h-2" {
			return 0
		}
		return prev(co)
	}
	rec, out := historyGet(t, s, "/api/v2/history/h-2.json", "history", "365", nil)
	if rec.Code != 200 || len(out.Retail) != 0 || len(*asked) != 1 || len((*asked)[0]) != 0 {
		t.Errorf("unknown card: %d %v asked %v", rec.Code, out.Retail, *asked)
	}
}
