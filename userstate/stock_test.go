package userstate

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/observability"
)

func TestTallyState(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	var s Stock
	tallyState(&s, State{
		Favorites: json.RawMessage(`[{"id":"a"},{"id":"b","del":1730000000000},{"id":"c","del":false}]`),
		Recents:   json.RawMessage(`[{"q":"bolt"},{"q":"old","del":1}]`),
		Backpack:  json.RawMessage(`[{"id":"x"},{"id":"x","cond":"SP"},{"id":"y","pack":2},{"id":"z","pack":3,"del":5},{"id":""}]`),
		Preferences: json.RawMessage(`{
			"theme": "dark",
			"mtgban_backpack_tabs": "[{\"pack\":1,\"name\":\"Main\"},{\"pack\":4,\"name\":\"Trade\"},{\"pack\":5,\"del\":true}]",
			"mtgban_upload_presets": "[{\"id\":\"p1\",\"name\":\"A\",\"opts\":{}},{\"id\":\"p2\",\"del\":true,\"savedAt\":1}]",
			"mtgban_arbit_presets": "[{\"id\":\"p_1\",\"name\":\"A\",\"group\":\"arbit\",\"q\":\"f=1\"},{\"id\":\"p_2\",\"name\":\"B\",\"group\":\"global\",\"q\":\"\"},{\"id\":\"p_3\",\"name\":\"C\",\"group\":\"elsewhere\",\"q\":\"x\"}]",
			"mtgban_arbit_pins": "{\"arbit:CK\":{\"id\":\"p_1\",\"t\":1}}",
			"mtgban_news_filters": "{\"magic:syp\":{\"q\":\"sort=price\",\"t\":1},\"magic:top\":{\"q\":\"\",\"t\":2}}",
			"mtgban_nav_layout_v1": "{\"sections\":[],\"grid\":[],\"dock\":[]}",
			"not_a_synced_key": "x"
		}`),
	}, now.Add(-24*time.Hour), now)

	// A second reader whose row is mostly unreadable, last synced 40 days ago.
	tallyState(&s, State{
		Favorites:   json.RawMessage(`"not a list"`),
		Recents:     json.RawMessage(`[`),
		Backpack:    json.RawMessage(`[]`),
		Preferences: json.RawMessage(`{"mtgban_upload_presets":"{broken","theme":5,"mtgban_arbit_pins":"[]","mtgban_news_filters":"{\"magic:syp\":{\"q\":\"\"}}"}`),
	}, now.AddDate(0, 0, -40), now)

	if s.Rows != 2 || s.Synced7d != 1 || s.Synced30d != 1 {
		t.Errorf("rows %d, 7d %d, 30d %d, want 2, 1, 1", s.Rows, s.Synced7d, s.Synced30d)
	}
	for name, c := range map[string]struct {
		got  map[int]int64
		size int
	}{
		"favorites": {s.Favorites, 2}, "recents": {s.Recents, 1}, "backpack": {s.Backpack, 3},
		"backpack tabs": {s.BackpackTabs, 3}, "upload presets": {s.UploadPresets, 1}, "arbit presets": {s.ArbitPresets, 2},
	} {
		if c.got[c.size] != 1 || c.got[0] != 1 || len(c.got) != 2 {
			t.Errorf("%s = %v, want one row at %d and one at 0", name, c.got, c.size)
		}
	}
	if s.ArbitPins != 1 || s.NewsFilters != 1 || s.NavLayout != 1 {
		t.Errorf("pins %d, news %d, nav %d, want 1 each", s.ArbitPins, s.NewsFilters, s.NavLayout)
	}
	wantPrefs := map[string]int64{
		"theme": 2, "mtgban_upload_presets": 2, "mtgban_arbit_pins": 2, "mtgban_news_filters": 2,
		"mtgban_backpack_tabs": 1, "mtgban_arbit_presets": 1, "mtgban_nav_layout_v1": 1,
	}
	if !maps.Equal(s.Prefs, wantPrefs) {
		t.Errorf("prefs = %v, want %v", s.Prefs, wantPrefs)
	}
}

// readerMarker stands in for anything a reader typed or stored.
const readerMarker = "qzreadermarkerqz"

// No string a reader controls leaves tallyState: Stock holds counts under fixed keys.
func TestTallyStateKeepsNoReaderText(t *testing.T) {
	m := readerMarker
	pref := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	str := func(v any) json.RawMessage { return json.RawMessage(pref(pref(v))) }
	prefs := map[string]json.RawMessage{
		"theme":                   json.RawMessage(pref(m)),
		"chartDateRange":          json.RawMessage(pref(m)),
		"mtgban_store_factors":    json.RawMessage(pref(map[string]any{m: m})),
		m + "_key":                json.RawMessage(pref(m)),
		"mtgban_backpack_tabs":    str([]map[string]any{{"pack": m, "name": m}, {"pack": 4, "name": m}}),
		"mtgban_upload_presets":   str([]map[string]any{{"id": m, "name": m, "opts": map[string]any{m: m}}}),
		"mtgban_arbit_presets":    str([]map[string]any{{"id": m, "name": m, "group": "arbit", "q": m}, {"id": m, "name": m, "group": m, "q": m}}),
		"mtgban_arbit_pins":       str(map[string]any{m: map[string]any{"id": m, "t": 1}}),
		"mtgban_news_filters":     str(map[string]any{m: map[string]any{"q": m, "t": 1}}),
		"mtgban_nav_layout_v1":    str(map[string]any{"sections": []string{m}, m: m}),
		"mtgban_backpack_sort":    str(m),
		"offline_stores":          str([]string{m}),
		"mtgban_upload_presets_x": json.RawMessage(pref(m)),
	}
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	var s Stock
	tallyState(&s, State{
		Favorites:   json.RawMessage(pref([]map[string]any{{"id": m, "name": m}, {"id": m + "2", "del": m}})),
		Recents:     json.RawMessage(pref([]map[string]any{{"q": m}, {"q": m, "game": m}})),
		Backpack:    json.RawMessage(pref([]map[string]any{{"id": m, "pack": m, "cond": m}, {"id": m, "pack": 2}})),
		Preferences: json.RawMessage(pref(prefs)),
	}, now, now)
	// The fixture is read, not skipped as malformed.
	if s.Rows != 1 || s.UploadPresets[1] != 1 || s.ArbitPresets[1] != 1 || s.ArbitPins != 1 || s.NewsFilters != 1 || s.Prefs["theme"] != 1 {
		t.Fatalf("stock %+v, want the fixture's presets, pins, filters and keys counted", s)
	}
	got := fmt.Sprintf("%+v", s)
	if !strings.Contains(got, "theme") {
		t.Fatalf("the rendering shows no map keys, so it proves nothing: %s", got)
	}
	if strings.Contains(got, m) {
		t.Errorf("reader text reached the stock: %s", got)
	}
}

// Synced on the boundary counts; a moment before it does not.
func TestTallyStateSyncedBoundary(t *testing.T) {
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	var s Stock
	tallyState(&s, State{}, now.AddDate(0, 0, -7), now)
	tallyState(&s, State{}, now.AddDate(0, 0, -7).Add(-time.Second), now)
	if s.Synced7d != 1 || s.Synced30d != 2 {
		t.Errorf("7d %d, 30d %d, want 1 and 2", s.Synced7d, s.Synced30d)
	}
}

// malformedStates are rows a client could write badly or on purpose, each
// with the sizes it must count as.
var malformedStates = []struct {
	name string
	st   State
	want [6]int // favorites, recents, backpack, backpack tabs, upload presets, arbit presets
}{
	{"sections of the wrong type", State{
		Favorites: json.RawMessage(`"a string"`), Recents: json.RawMessage(`{"q":"typed"}`),
		Backpack: json.RawMessage(`5`), Preferences: json.RawMessage(`[1,2]`),
	}, [6]int{}},
	{"preferences a string", State{
		Favorites: json.RawMessage(`[null,3,"x",[],{"id":"a"}]`), Recents: json.RawMessage(`[true,{"q":"x","del":0}]`),
		Backpack: json.RawMessage(`[1,null,"x",{"id":5},{"id":"ok","pack":"7"}]`), Preferences: json.RawMessage(`"secret"`),
	}, [6]int{1, 1, 1, 1, 0, 0}},
	{"inner lists of the wrong shape", State{
		Favorites: json.RawMessage(`[]`), Recents: json.RawMessage(`[]`), Backpack: json.RawMessage(`[]`),
		Preferences: json.RawMessage(`{
			"mtgban_backpack_tabs": "{\"pack\":2}",
			"mtgban_upload_presets": "[1,\"x\",null,{\"id\":\"p\",\"name\":\"n\",\"opts\":null},{\"id\":\"q\",\"name\":\"n\",\"opts\":0},{\"id\":\"s\",\"name\":\"n\",\"opts\":false},{\"id\":\"u\",\"name\":\"n\",\"opts\":\"\"},{\"id\":\"r\",\"name\":\"n\",\"opts\":[]}]",
			"mtgban_arbit_presets": "[{\"id\":\"p\",\"name\":\"n\",\"q\":5,\"group\":\"arbit\"},{\"id\":\"r\",\"name\":\"n\",\"q\":\"\",\"group\":\"global\"}]",
			"mtgban_arbit_pins": "{}",
			"mtgban_news_filters": "[{\"q\":\"x\"}]",
			"mtgban_nav_layout_v1": "[]",
			"a key nobody defined": "typed text"
		}`),
	}, [6]int{0, 0, 0, 0, 1, 1}},
	{"preferences that are not strings", State{
		Favorites: json.RawMessage(`[]`), Recents: json.RawMessage(`[]`), Backpack: json.RawMessage(`[{"id":"c","pack":3}]`),
		Preferences: json.RawMessage(`{"mtgban_backpack_tabs":[{"pack":9}],"mtgban_upload_presets":{"x":1},"mtgban_arbit_pins":null,"mtgban_nav_layout_v1":7}`),
	}, [6]int{0, 0, 1, 1, 0, 0}},
}

func TestTallyStateMalformedRows(t *testing.T) {
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	for _, m := range malformedStates {
		t.Run(m.name, func(t *testing.T) {
			var s Stock
			tallyState(&s, m.st, now, now)
			checkOneRow(t, s, m.want)
		})
	}
}

// checkOneRow checks s counted one row, at the sizes want gives.
func checkOneRow(t *testing.T, s Stock, want [6]int) {
	t.Helper()
	if s.Rows != 1 {
		t.Errorf("rows %d, want 1", s.Rows)
	}
	for i, got := range []map[int]int64{s.Favorites, s.Recents, s.Backpack, s.BackpackTabs, s.UploadPresets, s.ArbitPresets} {
		if len(got) != 1 || got[want[i]] != 1 {
			t.Errorf("size map %d = %v, want one row at %d", i, got, want[i])
		}
	}
	for k := range s.Prefs {
		if !slices.Contains(SyncedPrefKeys, k) {
			t.Errorf("prefs kept %q, which is not a synced key", k)
		}
	}
	if s.ArbitPins != 0 || s.NewsFilters != 0 || s.NavLayout != 0 {
		t.Errorf("pins %d, news %d, nav %d, want 0 each", s.ArbitPins, s.NewsFilters, s.NavLayout)
	}
}

var stockForbidden = regexp.MustCompile(`(?i)\b(email_hash|user_hash|session_id|share_key|share_id|address|patreon_user|refresh_token|client_id|lease|rows|to_jsonb?|row_to_json|jsonb?_agg|jsonb?_build_object|jsonb?_object|array_agg|string_agg|row)\b`)

var (
	selectList  = regexp.MustCompile(`(?is)^\s*SELECT\s+(.*?)\s+FROM\s`)
	fromNames   = regexp.MustCompile(`(?i)\b(?:FROM|JOIN)\s+(\w+)(?:\s+(?:AS\s+)?(\w+))?`)
	bareColumn  = regexp.MustCompile(`^\w+$`)
	placeholder = regexp.MustCompile(`\$\d+`)
)

// No stock query reaches for a column that names a reader or holds their upload.
func TestStockQueriesSelectNoIdentifier(t *testing.T) {
	for key, q := range stockQueries {
		if m := stockForbidden.FindString(q); m != "" {
			t.Errorf("stock query %s selects %s", key, m)
		}
		if strings.Contains(strings.ReplaceAll(q, "count(*)", ""), "*") {
			t.Errorf("stock query %s selects every column", key)
		}
		// Each selected item is count(*) or a bare column, never a table or alias as a row.
		m := selectList.FindStringSubmatch(q)
		if m == nil {
			t.Errorf("stock query %s has no plain select list", key)
			continue
		}
		tables := map[string]bool{}
		for _, f := range fromNames.FindAllStringSubmatch(q, -1) {
			tables[strings.ToLower(f[1])] = true
			tables[strings.ToLower(f[2])] = true
		}
		for _, item := range strings.Split(m[1], ",") {
			item = strings.TrimSpace(item)
			if item == "count(*)" {
				continue
			}
			if !bareColumn.MatchString(item) || tables[strings.ToLower(item)] {
				t.Errorf("stock query %s selects %q, not a bare column", key, item)
			}
		}
	}
}

// stockColumns are the exact columns each stock query may return.
var stockColumns = map[string][]string{
	"state":            {"favorites", "recents", "preferences", "backpack", "updated_at"},
	"sessions":         {"count"},
	"upload_shares":    {"game", "count"},
	"favorites_shares": {"game", "count"},
}

// Each stock query, run, returns only the columns written for it, whatever its text.
func TestStockQueriesReturnOnlyAllowedColumns(t *testing.T) {
	c := testClient(t)
	if !slices.Equal(slices.Sorted(maps.Keys(stockQueries)), slices.Sorted(maps.Keys(stockColumns))) {
		t.Fatalf("stockColumns lists %v, stockQueries %v", slices.Sorted(maps.Keys(stockColumns)), slices.Sorted(maps.Keys(stockQueries)))
	}
	for key, q := range stockQueries {
		args := []any{}
		for range slices.Compact(slices.Sorted(slices.Values(placeholder.FindAllString(q, -1)))) {
			args = append(args, time.Now())
		}
		rows, err := c.db.Query("SELECT * FROM ("+q+") s LIMIT 0", args...)
		if err != nil {
			t.Errorf("stock query %s: %v", key, err)
			continue
		}
		cols, err := rows.Columns()
		_ = rows.Close()
		if err != nil {
			t.Errorf("stock query %s columns: %v", key, err)
			continue
		}
		if !slices.Equal(cols, stockColumns[key]) {
			t.Errorf("stock query %s returns %v, want %v", key, cols, stockColumns[key])
		}
	}
}

// The registry's preference keys are the ones counted here.
func TestSyncedPrefKeysMatchTheRegistry(t *testing.T) {
	if !slices.Equal(SyncedPrefKeys, observability.StockPrefKeys()) {
		t.Errorf("SyncedPrefKeys %v\nStockPrefKeys %v", SyncedPrefKeys, observability.StockPrefKeys())
	}
}

// StockCounts and its helpers reach the database only with SQL from stockQueries.
func TestStockCountsRunsOnlyStockQueries(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "stock.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	queryHelpers := map[string]int{"tallyStates": 3, "countByGame": 1} // helper -> its SQL argument
	dbMethods := map[string]bool{
		"Query": true, "QueryContext": true, "QueryRow": true, "QueryRowContext": true,
		"Exec": true, "ExecContext": true, "Prepare": true, "PrepareContext": true, "Begin": true, "BeginTx": true,
	}
	seen := map[string]bool{}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv == nil {
			continue
		}
		name := fn.Name.Name
		if _, helper := queryHelpers[name]; name != "StockCounts" && !helper {
			continue
		}
		seen[name] = true
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			for _, a := range call.Args {
				if isClientRef(a) {
					t.Errorf("%s hands the client to another function", name)
				}
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch {
			case isIdent(sel.X, "c"):
				at, helper := queryHelpers[sel.Sel.Name]
				if !helper {
					t.Errorf("%s calls c.%s, which is not a stock query helper", name, sel.Sel.Name)
				} else if name != "StockCounts" || len(call.Args) <= at || !isStockQuery(call.Args[at]) {
					t.Errorf("%s calls c.%s without a stockQueries entry", name, sel.Sel.Name)
				}
			case isClientRef(sel.X):
				if !dbMethods[sel.Sel.Name] {
					t.Errorf("%s calls c.db.%s", name, sel.Sel.Name)
				} else if len(call.Args) < 2 || !isStockQuery(call.Args[1]) && !(name != "StockCounts" && isIdent(call.Args[1], "query")) {
					t.Errorf("%s calls c.db.%s with SQL not from stockQueries", name, sel.Sel.Name)
				}
			}
			return true
		})
	}
	if len(seen) != 3 {
		t.Errorf("found %v in stock.go, want StockCounts, tallyStates and countByGame", seen)
	}
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

// isClientRef says e is c or c.db.
func isClientRef(e ast.Expr) bool {
	if isIdent(e, "c") {
		return true
	}
	sel, ok := e.(*ast.SelectorExpr)
	return ok && isIdent(sel.X, "c") && sel.Sel.Name == "db"
}

// isStockQuery says e is stockQueries["<key>"].
func isStockQuery(e ast.Expr) bool {
	ix, ok := e.(*ast.IndexExpr)
	if !ok || !isIdent(ix.X, "stockQueries") {
		return false
	}
	lit, ok := ix.Index.(*ast.BasicLit)
	return ok && lit.Kind == token.STRING
}

// Every query in stock.go is in stockQueries, where the test above sees it.
func TestStockFileKeepsItsSQLInStockQueries(t *testing.T) {
	src, err := os.ReadFile("stock.go")
	if err != nil {
		t.Fatal(err)
	}
	listed := 0
	for _, q := range stockQueries {
		listed += strings.Count(q, "SELECT")
	}
	if total := strings.Count(string(src), "SELECT"); total != listed {
		t.Errorf("stock.go has %d SELECTs, stockQueries %d", total, listed)
	}
}

var sqlWord = regexp.MustCompile(`(?i)\b(select|from|where|join|table|insert|update|delete|returning)\b`)

// No string in stock.go outside stockQueries reads like SQL, whatever its case or call.
func TestStockFileHasNoSQLOutsideStockQueries(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "stock.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var inMap *ast.CompositeLit
	ast.Inspect(f, func(n ast.Node) bool {
		if v, ok := n.(*ast.ValueSpec); ok && len(v.Names) == 1 && v.Names[0].Name == "stockQueries" && len(v.Values) == 1 {
			if lit, ok := v.Values[0].(*ast.CompositeLit); ok {
				inMap = lit
			}
		}
		return true
	})
	if inMap == nil {
		t.Fatal("stock.go declares no stockQueries map literal")
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if n == inMap {
			return false
		}
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			s = lit.Value
		}
		if sqlWord.MatchString(s) {
			t.Errorf("stock.go holds SQL outside stockQueries: %s", lit.Value)
		}
		return true
	})
}

// stockOf tallies the one row of emailHash through the query and scan StockCounts uses.
func stockOf(t *testing.T, c *Client, emailHash string, now time.Time) Stock {
	t.Helper()
	var s Stock
	if err := c.tallyStates(context.Background(), &s, now, stockQueries["state"]+" WHERE email_hash = $1", emailHash); err != nil {
		t.Fatalf("tally: %v", err)
	}
	return s
}

// A malformed row read from the database counts once, empty, and fails nothing.
func TestStockCountsMalformedRows(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	now := time.Now()
	for _, m := range malformedStates {
		t.Run(m.name, func(t *testing.T) {
			h := freshHash(t, c)
			if _, _, err := c.Put(ctx, h, m.st, 0); err != nil {
				t.Fatalf("Put: %v", err)
			}
			s := stockOf(t, c, h, now)
			checkOneRow(t, s, m.want)
			if s.Synced7d != 1 || s.Synced30d != 1 {
				t.Errorf("7d %d, 30d %d, want 1 each", s.Synced7d, s.Synced30d)
			}
		})
	}
	t.Run("a huge list", func(t *testing.T) {
		h := freshHash(t, c)
		fav := "[" + strings.Repeat(`{"id":"a"},`, 19999) + `{"id":"a"}]`
		if _, _, err := c.Put(ctx, h, State{Favorites: json.RawMessage(fav)}, 0); err != nil {
			t.Fatalf("Put: %v", err)
		}
		s := stockOf(t, c, h, now)
		if s.Rows != 1 || s.Favorites[20000] != 1 {
			t.Errorf("rows %d, favorites %v, want one row of 20000", s.Rows, s.Favorites)
		}
	})

	// With every malformed row stored, the whole count still runs and adds up.
	for _, m := range malformedStates {
		h := HashEmail("test-" + t.Name() + "-" + m.name + "@example.com")
		t.Cleanup(func() { _, _ = c.db.Exec(`DELETE FROM user_state WHERE email_hash = $1`, h) })
		if _, err := c.db.Exec(`DELETE FROM user_state WHERE email_hash = $1`, h); err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.Put(ctx, h, m.st, 0); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	s, err := c.StockCounts(ctx, now)
	if err != nil {
		t.Fatalf("StockCounts: %v", err)
	}
	for i, got := range []map[int]int64{s.Favorites, s.Recents, s.Backpack, s.BackpackTabs, s.UploadPresets, s.ArbitPresets} {
		var sum int64
		for _, n := range got {
			sum += n
		}
		if sum != s.Rows {
			t.Errorf("size map %d sums to %d, rows %d", i, sum, s.Rows)
		}
	}
}

func TestStockCountsReadsTheTables(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	now := time.Now()
	game := "test-" + t.Name()
	clean := func() {
		_, _ = c.db.Exec(`DELETE FROM upload_shares WHERE game = $1`, game)
		_, _ = c.db.Exec(`DELETE FROM favorites_shares WHERE game = $1`, game)
		_, _ = c.db.Exec(`DELETE FROM patreon_sessions WHERE session_id = $1`, game)
	}
	clean()
	t.Cleanup(clean)

	before, err := c.StockCounts(ctx, now)
	if err != nil {
		t.Fatalf("StockCounts before: %v", err)
	}
	h := freshHash(t, c)
	if _, _, err := c.Put(ctx, h, State{
		Favorites:   json.RawMessage(`[{"id":"a"},{"id":"b"}]`),
		Preferences: json.RawMessage(`{"theme":"dark"}`),
	}, 0); err != nil {
		t.Fatalf("Put: %v", err)
	}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO upload_shares (share_key, email_hash, rows, game, expires_at) VALUES ($1, $2, '[]', $3, now() + interval '1 hour')`, []any{game + "-live", h, game}},
		{`INSERT INTO upload_shares (share_key, email_hash, rows, game, expires_at) VALUES ($1, $2, '[]', $3, now() - interval '1 hour')`, []any{game + "-expired", h, game}},
		{`INSERT INTO favorites_shares (share_id, email_hash, game) VALUES ($1, $2, $3)`, []any{game + "-live", h, game}},
		{`INSERT INTO favorites_shares (share_id, email_hash, game, revoked_at) VALUES ($1, $2, $3, now())`, []any{game + "-revoked", h, game}},
		{`INSERT INTO patreon_sessions (session_id, email_hash, patreon_user, client_id, refresh_token, expires_at) VALUES ($1, $2, 'u', 'c', 'r', now() + interval '1 hour')`, []any{game, h}},
	} {
		if _, err := c.db.Exec(q.sql, q.args...); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	after, err := c.StockCounts(ctx, now)
	if err != nil {
		t.Fatalf("StockCounts after: %v", err)
	}
	if after.UploadShares[game] != 1 || after.FavoritesShares[game] != 1 {
		t.Errorf("upload shares %d, favorites shares %d, want 1 each", after.UploadShares[game], after.FavoritesShares[game])
	}
	// Expiry is judged by the job's clock: two hours on, the live share has lapsed.
	later, err := c.StockCounts(ctx, now.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("StockCounts later: %v", err)
	}
	if later.UploadShares[game] != 0 {
		t.Errorf("upload shares two hours on %d, want 0", later.UploadShares[game])
	}
	if after.Rows-before.Rows < 1 || after.Favorites[2]-before.Favorites[2] < 1 ||
		after.Prefs["theme"]-before.Prefs["theme"] < 1 || after.Sessions-before.Sessions < 1 {
		t.Errorf("before %+v\nafter %+v\nwant rows, favorites[2], prefs[theme] and sessions each up by 1 or more", before, after)
	}
}
