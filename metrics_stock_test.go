package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/internal/alerts"
	"github.com/mtgban/mtgban-website/observability"
	"github.com/mtgban/mtgban-website/userstate"
)

func stockN(rows []observability.Row, name, scope, value string) int64 {
	for _, r := range rows {
		if r.Name == name && r.Scope == scope && r.Value == value {
			return r.N
		}
	}
	return -1
}

// fullState has every field and map non-zero, under magic.
func fullState() userstate.Stock {
	return userstate.Stock{
		Rows: 10, Synced7d: 4, Synced30d: 6,
		Favorites:       map[int]int64{0: 5, 3: 2, 9: 1, 50: 2},
		Recents:         map[int]int64{0: 4, 6: 6},
		Backpack:        map[int]int64{0: 8, 120: 2},
		BackpackTabs:    map[int]int64{0: 7, 1: 2, 2: 1},
		UploadPresets:   map[int]int64{0: 9, 3: 1},
		ArbitPresets:    map[int]int64{0: 9, 11: 1},
		ArbitPins:       1,
		NewsFilters:     2,
		NavLayout:       3,
		Prefs:           map[string]int64{"theme": 8},
		Sessions:        5,
		UploadShares:    map[string]int64{"magic": 2},
		FavoritesShares: map[string]int64{"magic": 1},
	}
}

// fullAlerts has every map non-zero, under magic.
func fullAlerts() alerts.Stock {
	return alerts.Stock{
		BySide:           map[alerts.GameValue]int64{{Game: "magic", Value: "retail"}: 3},
		ByDelivery:       map[alerts.GameValue]int64{{Game: "magic", Value: "email"}: 3},
		ByStatus:         map[alerts.GameValue]int64{{Game: "magic", Value: "active"}: 3},
		ByCondition:      map[alerts.GameValue]int64{{Game: "magic", Value: "NM"}: 3},
		ByStores:         map[alerts.GameCount]int64{{Game: "magic", N: 0}: 2, {Game: "magic", N: 3}: 1},
		Channels:         map[string]int64{"email": 2},
		ChannelsDisabled: map[string]int64{"bounced": 1},
		Events:           map[alerts.GameValue]int64{{Game: "magic", Value: "delivered"}: 4},
	}
}

func TestStockRows(t *testing.T) {
	state := userstate.Stock{
		Rows: 10, Synced7d: 4, Synced30d: 6,
		Favorites:    map[int]int64{0: 5, 3: 2, 9: 1, 50: 2},
		BackpackTabs: map[int]int64{0: 7, 1: 2, 2: 1},
		Prefs:        map[string]int64{"theme": 8, "made_up_key": 3},
		UploadShares: map[string]int64{"magic": 2, "": 1},
	}
	alert := alerts.Stock{
		BySide:   map[alerts.GameValue]int64{{Game: "magic", Value: "retail"}: 5, {Game: "test-game", Value: "retail"}: 9},
		ByStores: map[alerts.GameCount]int64{{Game: "magic", N: 0}: 3, {Game: "magic", N: 2}: 1, {Game: "magic", N: 4}: 1},
	}
	rows, refused, unknownGames := stockRows(&state, &alert)

	for _, c := range []struct {
		name, scope, value string
		want               int64
	}{
		{"stock.rows", "", "", 10},
		{"stock.synced_7d", "", "", 4},
		{"stock.sessions", "", "", 0}, // written at zero
		{"stock.favorites", "", "0", 5},
		{"stock.favorites", "", "1-9", 3}, // sizes 3 and 9 share a bucket
		{"stock.favorites", "", "50+", 2},
		{"stock.backpack_tabs", "", "1", 2},
		{"stock.backpack_tabs", "", "2", 1},
		{"stock.pref", "", "theme", 8},
		{"stock.pref", "", "made_up_key", -1},
		{"stock.upload_shares", "magic", "", 2},
		{"stock.upload_shares", "", "", -1},
		{"stock.alerts", "magic", "retail", 5},
		{"stock.alerts", "test-game", "retail", -1},
		{"stock.alerts_stores", "magic", "0", 3},
		{"stock.alerts_stores", "magic", "2-4", 2},
		{"stock.fav_shares", "magic", "", -1}, // nothing stored, nothing written
	} {
		if got := stockN(rows, c.name, c.scope, c.value); got != c.want {
			t.Errorf("%s scope %q value %q = %d, want %d", c.name, c.scope, c.value, got, c.want)
		}
	}
	if refused != 1 {
		t.Errorf("refused = %d, want 1 (the made-up key)", refused)
	}
	if unknownGames != 2 {
		t.Errorf("unknownGames = %d, want 2 (the empty game, the test game)", unknownGames)
	}
	for _, r := range rows {
		if r.Instance != observability.SharedInstance || r.Device != "job" || r.Tier != "" || r.Signed || r.Bot {
			t.Fatalf("row %+v is not under the shared instance's dimensions", r)
		}
		if r.Scope == "test-game" || strings.Contains(r.Value, "made_up") {
			t.Fatalf("row %+v carries a word the registry does not know", r)
		}
	}
	cmpKey := func(a, b observability.Row) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Scope, b.Scope), cmp.Compare(a.Value, b.Value))
	}
	if !slices.IsSortedFunc(rows, cmpKey) {
		t.Error("rows are not in key order")
	}
	if len(slices.CompactFunc(slices.Clone(rows), func(a, b observability.Row) bool { return cmpKey(a, b) == 0 })) != len(rows) {
		t.Error("rows repeat a key")
	}
}

// A game no deployment has, or none, never becomes a row.
func TestStockRowsDropUnknownGames(t *testing.T) {
	state := userstate.Stock{
		UploadShares:    map[string]int64{"made-up": 1, "": 1},
		FavoritesShares: map[string]int64{"made-up": 1, "": 1},
	}
	alert := alerts.Stock{
		BySide:      map[alerts.GameValue]int64{{Game: "made-up", Value: "retail"}: 1, {Game: "", Value: "retail"}: 1},
		ByDelivery:  map[alerts.GameValue]int64{{Game: "made-up", Value: "email"}: 1},
		ByStatus:    map[alerts.GameValue]int64{{Game: "", Value: "active"}: 1},
		ByCondition: map[alerts.GameValue]int64{{Game: "made-up", Value: "NM"}: 1},
		ByStores:    map[alerts.GameCount]int64{{Game: "made-up", N: 1}: 1, {Game: "", N: 0}: 1},
		Events:      map[alerts.GameValue]int64{{Game: "", Value: "failed"}: 1},
	}
	rows, refused, unknownGames := stockRows(&state, &alert)
	for _, r := range rows {
		if r.Scope != "" || r.N != 0 {
			t.Errorf("row %+v came from an unknown game", r)
		}
	}
	if refused != 0 || unknownGames != 12 {
		t.Errorf("refused %d, unknownGames %d, want 0 and 12", refused, unknownGames)
	}
}

// Reader text in every string the stores hand over, a key, a game or a value, reaches no row.
func TestStockRowsKeepNoReaderText(t *testing.T) {
	const m = "qzreadermarkerqz"
	state, alert := fullState(), fullAlerts()
	state.Prefs[m] = 1
	state.UploadShares[m] = 1
	state.FavoritesShares[m] = 1
	for _, side := range []map[alerts.GameValue]int64{alert.BySide, alert.ByDelivery, alert.ByStatus, alert.ByCondition, alert.Events} {
		side[alerts.GameValue{Game: m, Value: m}] = 1
		side[alerts.GameValue{Game: "magic", Value: m}] = 1
		side[alerts.GameValue{Game: m, Value: "retail"}] = 1
	}
	alert.ByStores[alerts.GameCount{Game: m, N: 2}] = 1
	alert.Channels[m] = 1
	alert.ChannelsDisabled[m] = 1

	rows, refused, unknownGames := stockRows(&state, &alert)
	if len(rows) == 0 || refused == 0 || unknownGames == 0 {
		t.Fatalf("rows %d, refused %d, unknown games %d: want rows, refusals and unknown games", len(rows), refused, unknownGames)
	}
	for _, r := range rows {
		if got := fmt.Sprintf("%+v", r); strings.Contains(got, m) {
			t.Errorf("reader text reached a row: %s", got)
		}
	}
}

// Nil inputs and nil maps give the always-written names at zero and nothing else.
func TestStockRowsEmpty(t *testing.T) {
	if rows, refused, unknown := stockRows(nil, nil); len(rows) != 0 || refused != 0 || unknown != 0 {
		t.Errorf("nil inputs gave %v, %d, %d", rows, refused, unknown)
	}
	rows, _, _ := stockRows(&userstate.Stock{}, &alerts.Stock{})
	var names []string
	for _, r := range rows {
		if r.N != 0 {
			t.Errorf("row %+v is not zero", r)
		}
		names = append(names, r.Name)
	}
	want := []string{"stock.arbit_pins", "stock.nav_layout", "stock.news_filters", "stock.rows", "stock.sessions", "stock.synced_30d", "stock.synced_7d"}
	if !slices.Equal(names, want) {
		t.Errorf("empty site wrote %v, want %v", names, want)
	}
}

// Every stock name comes out of the mapping, and nothing else does.
func TestEveryStockNameIsProduced(t *testing.T) {
	state, alert := fullState(), fullAlerts()
	rows, refused, unknownGames := stockRows(&state, &alert)
	if refused != 0 || unknownGames != 0 {
		t.Fatalf("the full fixture has %d refused rows and %d unknown games", refused, unknownGames)
	}
	produced := map[string]bool{}
	for _, r := range rows {
		produced[r.Name] = true
	}
	for _, n := range observability.All() {
		if n.Family == observability.FamilyStock && !produced[n.Name] {
			t.Errorf("%s is registered and never written", n.Name)
		}
		delete(produced, n.Name)
	}
	for name := range produced {
		t.Errorf("%s is written and not registered", name)
	}
	var written []string
	for _, r := range rows {
		written = append(written, r.Name)
	}
	if got := slices.Sorted(slices.Values(stockNames())); !slices.Equal(got, slices.Compact(written)) {
		t.Errorf("stockNames %v, written %v", got, slices.Compact(written))
	}
}

// A bucketed name's rows add up to the rows the counts came from.
func TestStockBucketsKeepTheirPopulation(t *testing.T) {
	state, alert := fullState(), fullAlerts()
	rows, _, _ := stockRows(&state, &alert)
	for name, sizes := range map[string]map[int]int64{
		"stock.favorites": state.Favorites, "stock.recents": state.Recents,
		"stock.backpack": state.Backpack, "stock.backpack_tabs": state.BackpackTabs,
		"stock.upload_presets": state.UploadPresets, "stock.arbit_presets": state.ArbitPresets,
	} {
		var want, got int64
		for _, n := range sizes {
			want += n
		}
		for _, r := range rows {
			if r.Name == name {
				got += r.N
			}
		}
		if got != want {
			t.Errorf("%s rows add to %d, want %d", name, got, want)
		}
	}

	// Per game, the stores buckets add to that game's alerts.
	alert = alerts.Stock{ByStores: map[alerts.GameCount]int64{
		{Game: "magic", N: 0}: 4, {Game: "magic", N: 1}: 2, {Game: "magic", N: 3}: 1, {Game: "magic", N: 12}: 5,
		{Game: "lorcana", N: 2}: 3, {Game: "lorcana", N: 40}: 1,
	}}
	rows, _, _ = stockRows(nil, &alert)
	for game, want := range map[string]int64{"magic": 12, "lorcana": 4} {
		var got int64
		for _, r := range rows {
			if r.Name == "stock.alerts_stores" && r.Scope == game {
				got += r.N
			}
		}
		if got != want {
			t.Errorf("stock.alerts_stores rows for %s add to %d, want %d", game, got, want)
		}
	}
}

// The registry's games are the ones a deployment can be.
func TestStockGamesAreTheDeployableGames(t *testing.T) {
	var deployable []string
	for game := range gameMap {
		deployable = append(deployable, string(game))
	}
	slices.Sort(deployable)
	if registered := slices.Sorted(slices.Values(observability.StockGames())); !slices.Equal(registered, deployable) {
		t.Errorf("registry games %v, gameMap %v", registered, deployable)
	}
}

// The synced keys are one list in three places: the script, the tally, the registry.
func TestSyncedPrefKeysAgree(t *testing.T) {
	src, err := os.ReadFile("js/user-state.js")
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)var PREF_KEYS = \[(.*?)\];`).FindSubmatch(src)
	if block == nil {
		t.Fatal("PREF_KEYS not found in js/user-state.js")
	}
	var script []string
	for _, m := range regexp.MustCompile(`'([^']+)'`).FindAllSubmatch(block[1], -1) {
		script = append(script, string(m[1]))
	}
	if !slices.Equal(script, userstate.SyncedPrefKeys) || !slices.Equal(script, observability.StockPrefKeys()) {
		t.Errorf("PREF_KEYS %v\nuserstate %v\nregistry %v", script, userstate.SyncedPrefKeys, observability.StockPrefKeys())
	}
}

func TestUTCDay(t *testing.T) {
	east := time.FixedZone("east", 10*3600)
	if got := utcDay(time.Date(2026, 11, 11, 5, 0, 0, 0, east)); !got.Equal(time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)) || got.Location() != time.UTC {
		t.Errorf("utcDay = %v, want 2026-11-10 UTC", got)
	}
}

// The site's sources always write, and read only the stores it has.
func TestSiteStockSources(t *testing.T) {
	saved := UserStateDB
	t.Cleanup(func() { UserStateDB = saved })
	UserStateDB = &userstate.Client{}
	s := newSite()
	if src := s.stockSources(); src.Write == nil || src.State == nil || src.Alerts != nil {
		t.Errorf("without an alerts store: write %v, state %v, alerts %v", src.Write != nil, src.State != nil, src.Alerts != nil)
	}
	UserStateDB = nil
	if src := s.stockSources(); src.Write == nil || src.State != nil {
		t.Errorf("without userstate: write %v, state %v", src.Write != nil, src.State != nil)
	}
}

func TestCountStoredState(t *testing.T) {
	now := time.Date(2026, 11, 11, 0, 40, 0, 0, time.UTC)
	var wroteDay time.Time
	var wroteInstance string
	var wroteNames []string
	var wrote []observability.Row
	src := stockSources{
		State:  func(context.Context, time.Time) (userstate.Stock, error) { return userstate.Stock{Rows: 2}, nil },
		Alerts: func(context.Context) (alerts.Stock, error) { return alerts.Stock{}, nil },
		Write: func(_ context.Context, day time.Time, instance string, names []string, rows []observability.Row) error {
			wroteDay, wroteInstance, wroteNames, wrote = day, instance, names, rows
			return nil
		},
	}
	result, err := countStoredState(context.Background(), src, now)
	if err != nil {
		t.Fatal(err)
	}
	if !wroteDay.Equal(time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("wrote under %v, want the finished day 2026-11-10", wroteDay)
	}
	if wroteInstance != observability.SharedInstance || !slices.Equal(wroteNames, stockNames()) {
		t.Errorf("wrote instance %q names %v", wroteInstance, wroteNames)
	}
	if stockN(wrote, "stock.rows", "", "") != 2 || result != "7 rows for 2026-11-10" {
		t.Errorf("rows %v, result %q", wrote, result)
	}

	// A source that fails writes nothing.
	wrote = nil
	src.State = func(context.Context, time.Time) (userstate.Stock, error) {
		return userstate.Stock{}, errors.New("down")
	}
	if _, err := countStoredState(context.Background(), src, now); err == nil || wrote != nil {
		t.Errorf("err %v, wrote %v, want an error and no write", err, wrote)
	}
	src.State = func(context.Context, time.Time) (userstate.Stock, error) { return userstate.Stock{Rows: 1}, nil }
	src.Alerts = func(context.Context) (alerts.Stock, error) { return alerts.Stock{}, errors.New("down") }
	if _, err := countStoredState(context.Background(), src, now); err == nil || wrote != nil {
		t.Errorf("err %v, wrote %v, want an error and no write", err, wrote)
	}

	// No alerts store: the state rows are written and the result says so.
	src.Alerts = nil
	result, err = countStoredState(context.Background(), src, now)
	if err != nil || !strings.Contains(result, "alerts not counted") || stockN(wrote, "stock.rows", "", "") != 1 {
		t.Errorf("result %q, err %v", result, err)
	}

	// A refused row or an unknown game is told in the result, after the good rows are written.
	src.State = func(context.Context, time.Time) (userstate.Stock, error) {
		return userstate.Stock{Rows: 1, Prefs: map[string]int64{"made_up_key": 1}, UploadShares: map[string]int64{"": 1}}, nil
	}
	wrote = nil
	result, err = countStoredState(context.Background(), src, now)
	if err != nil || stockN(wrote, "stock.rows", "", "") != 1 {
		t.Errorf("err %v, wrote %v, want the good rows and no error", err, wrote)
	}
	if !strings.Contains(result, "1 refused by the registry") || !strings.Contains(result, "1 under an unknown game") {
		t.Errorf("result %q does not tell the left-out rows", result)
	}

	// A failed write is the job's error.
	src.Write = func(context.Context, time.Time, string, []string, []observability.Row) error {
		return errors.New("full")
	}
	if _, err := countStoredState(context.Background(), src, now); err == nil {
		t.Error("a failed write returned no error")
	}

	// No writer is an error, not a panic.
	src.Write = nil
	if _, err := countStoredState(context.Background(), src, now); err == nil {
		t.Error("a missing writer returned no error")
	}
}
