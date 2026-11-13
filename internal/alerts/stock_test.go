package alerts

import (
	"context"
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
)

var stockForbidden = regexp.MustCompile(`(?i)\b(user_hash|address|discord_user_id|card_id|card_name|card_set|card_number|last_error|error|message_id|rows)\b`)

// stockSensitive is every column of the alert tables naming a reader, a card,
// a price, a threshold, an address, a token or free text, plus the row ids.
var stockSensitive = regexp.MustCompile(`(?i)\b(id|alert_id|card_finish|reference_price|above_kind|above_value|below_kind|below_value|created_price|price|threshold|store|stores|origin|disabled_reason|replaced|tier|email_hash|patreon_user|refresh_token|session_id|share_key|share_id|token)\b`)

// stockWholeRow is any form that selects a whole row.
var stockWholeRow = regexp.MustCompile(`(?i)\b(to_jsonb|to_json|row_to_json|json_agg|jsonb_agg|json_object_agg|jsonb_object_agg|hstore)\s*\(|\*`)

// stockPermitted are the exact forms a query may use a sensitive column in:
// a count, a store count, the events join key and the folded reason.
var stockPermitted = []string{
	"count(*)",
	"cardinality(stores)",
	"ON a.id = e.alert_id",
	"CASE WHEN disabled_reason IN ('bounced', 'complained', 'unsubscribed') THEN disabled_reason ELSE 'other' END",
}

// No stock query reaches for a column that names a reader or holds what they typed.
func TestStockQueriesSelectNoIdentifier(t *testing.T) {
	for key, q := range stockQueries {
		if m := stockForbidden.FindString(q); m != "" {
			t.Errorf("stock query %s selects %s", key, m)
		}
		bare := q
		for _, p := range stockPermitted {
			bare = strings.ReplaceAll(bare, p, "")
		}
		if m := stockSensitive.FindString(bare); m != "" {
			t.Errorf("stock query %s reads %s outside a permitted form", key, m)
		}
		if m := stockWholeRow.FindString(bare); m != "" {
			t.Errorf("stock query %s selects a whole row with %s", key, m)
		}
	}
}

// The guards above refuse the shapes a careless edit would take.
func TestStockGuardsRefuseLeakyQueries(t *testing.T) {
	for _, q := range []string{
		`SELECT *, count(*) FROM alerts GROUP BY 1`,
		`SELECT a.*, count(*) FROM alerts a GROUP BY 1`,
		`SELECT game, above_value, count(*) FROM alerts GROUP BY 1, 2`,
		`SELECT game, threshold, count(*) FROM alert_events GROUP BY 1, 2`,
		`SELECT game, stores, count(*) FROM alerts GROUP BY 1, 2`,
		`SELECT disabled_reason, count(*) FROM alert_channels GROUP BY 1`,
		`SELECT game, json_agg(card_finish) FROM alerts GROUP BY 1`,
		`SELECT row_to_json(a) FROM alerts a`,
	} {
		bare := q
		for _, p := range stockPermitted {
			bare = strings.ReplaceAll(bare, p, "")
		}
		if stockForbidden.MatchString(q) || stockSensitive.MatchString(bare) || stockWholeRow.MatchString(bare) {
			continue
		}
		t.Errorf("guards let through %s", q)
	}
}

// stockColumns is exactly what each stock query returns, as Postgres names it.
var stockColumns = map[string][]string{
	"alerts":   {"game", "side", "delivery", "status", "condition", "cardinality", "count"},
	"channels": {"kind", "?column?", "case", "count"},
	"events":   {"game", "delivered", "count"},
}

// Each stock query returns only the columns written above, checked by the database.
func TestStockQueriesReturnOnlyTheirColumns(t *testing.T) {
	s := testStore(t)
	if len(stockColumns) != len(stockQueries) {
		t.Fatalf("stockColumns lists %d queries, stockQueries holds %d", len(stockColumns), len(stockQueries))
	}
	for key, q := range stockQueries {
		want, ok := stockColumns[key]
		if !ok {
			t.Errorf("stock query %s has no column list", key)
			continue
		}
		rows, err := s.db.Query(`SELECT * FROM (` + q + `) s LIMIT 0`)
		if err != nil {
			t.Fatalf("stock query %s: %v", key, err)
		}
		got, err := rows.Columns()
		_ = rows.Close()
		if err != nil {
			t.Fatalf("stock query %s columns: %v", key, err)
		}
		if !slices.Equal(got, want) {
			t.Errorf("stock query %s returns %v, want %v", key, got, want)
		}
	}
}

func TestAddKnownAndTallyChannelsSkipUnlistedWords(t *testing.T) {
	m := map[GameValue]int64{}
	addKnown(m, "magic", "retail", stockSides, 2)
	addKnown(m, "magic", "wholesale", stockSides, 5)
	addKnown(m, "magic", "", stockSides, 7)
	if want := (map[GameValue]int64{{"magic", "retail"}: 2}); !maps.Equal(m, want) {
		t.Errorf("addKnown = %v, want %v", m, want)
	}

	st := Stock{Channels: map[string]int64{}, ChannelsDisabled: map[string]int64{}}
	for _, c := range []struct {
		kind, reason string
		disabled     bool
	}{
		{"email", "", false},
		{"email", ReasonBounced, true},
		{"discord", "other", true},
		{"pager", "other", true},
		{"email", "typed by hand", true},
		{"email", ReasonComplained, false},
	} {
		tallyChannels(&st, c.kind, c.disabled, c.reason, 1)
	}
	if want := (map[string]int64{"email": 4, "discord": 1}); !maps.Equal(st.Channels, want) {
		t.Errorf("channels = %v, want %v", st.Channels, want)
	}
	if want := (map[string]int64{ReasonBounced: 1, "other": 2}); !maps.Equal(st.ChannelsDisabled, want) {
		t.Errorf("disabled = %v, want %v", st.ChannelsDisabled, want)
	}
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

var stockSQLWord = regexp.MustCompile(`(?i)\b(select|from|where|join|table|insert|update|delete|returning)\b`)

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
		if stockSQLWord.MatchString(s) {
			t.Errorf("stock.go holds SQL outside stockQueries: %s", lit.Value)
		}
		return true
	})
}

// stockCalls are the database calls a stock helper may make.
var stockCalls = []string{"Query", "QueryContext", "QueryRow", "QueryRowContext", "Exec", "ExecContext", "Prepare", "PrepareContext"}

// StockCounts reaches only functions of stock.go, and every query it runs is
// an entry of stockQueries, so no SQL elsewhere in the package can feed it.
func TestStockCountsTakesItsSQLOnlyFromStockQueries(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "stock.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok {
			declared[fn.Name.Name] = true
		}
	}
	dbCalls := 0
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		// A method on the store must be one stock.go declares, or a call on its db.
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == "s" && !declared[sel.Sel.Name] {
			t.Errorf("stock.go calls s.%s, which it does not declare", sel.Sel.Name)
		}
		inner, ok := sel.X.(*ast.SelectorExpr)
		if !ok || inner.Sel.Name != "db" {
			return true
		}
		dbCalls++
		if !slices.Contains(stockCalls, sel.Sel.Name) {
			t.Errorf("stock.go calls db.%s", sel.Sel.Name)
			return true
		}
		q := call.Args[0]
		if strings.HasSuffix(sel.Sel.Name, "Context") {
			q = call.Args[1]
		}
		var from string
		if idx, ok := q.(*ast.IndexExpr); ok {
			if id, ok := idx.X.(*ast.Ident); ok {
				from = id.Name
			}
		}
		if from != "stockQueries" {
			t.Errorf("stock.go runs db.%s on SQL not taken from stockQueries", sel.Sel.Name)
		}
		return true
	})
	if dbCalls != len(stockQueries) {
		t.Errorf("stock.go makes %d database calls, stockQueries holds %d queries", dbCalls, len(stockQueries))
	}
}

func TestStockCountsReadsTheAlertTables(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	game := "test-" + t.Name()
	now := time.Now()

	var ids []int64
	for _, row := range []struct {
		side   Side
		stores []string
	}{
		{SideRetail, []string{}},
		{SideBuylist, []string{"CK"}},
		{SideBuylist, []string{"CK", "SCG", "TCG"}},
	} {
		a := sample(h)
		a.Game, a.Side, a.Stores = game, row.side, row.stores
		created, err := s.Create(ctx, a)
		if err != nil {
			t.Fatalf("Create %+v: %v", row, err)
		}
		ids = append(ids, created.ID)
	}
	if ok, err := s.SetStatus(ctx, ids[1], h, StatusPaused); err != nil || !ok {
		t.Fatalf("SetStatus: ok=%v err=%v", ok, err)
	}

	before, err := s.StockCounts(ctx)
	if err != nil {
		t.Fatalf("StockCounts before: %v", err)
	}
	must(t, s.UpsertChannel(ctx, Channel{UserHash: h, Kind: ChannelEmail, Address: h + "@example.com", Source: SourceUser}))
	must(t, s.DisableChannel(ctx, h, ChannelEmail, SourceUser, "opted out", now))

	for _, delivered := range []bool{true, false} {
		must(t, s.AddEvent(ctx, Event{AlertID: ids[0], FiredAt: now, Threshold: "below", Store: "CK", Price: 9, Delivered: delivered}))
	}

	after, err := s.StockCounts(ctx)
	if err != nil {
		t.Fatalf("StockCounts after: %v", err)
	}
	for _, c := range []struct {
		name string
		got  int64
		want int64
	}{
		{"side retail", after.BySide[GameValue{game, "retail"}], 1},
		{"side buylist", after.BySide[GameValue{game, "buylist"}], 2},
		{"delivery discord", after.ByDelivery[GameValue{game, "discord"}], 3},
		{"status paused", after.ByStatus[GameValue{game, "paused"}], 1},
		{"status active", after.ByStatus[GameValue{game, "active"}], 2},
		{"condition NM", after.ByCondition[GameValue{game, "NM"}], 3},
		{"stores 0", after.ByStores[GameCount{game, 0}], 1},
		{"stores 1", after.ByStores[GameCount{game, 1}], 1},
		{"stores 3", after.ByStores[GameCount{game, 3}], 1},
		{"events delivered", after.Events[GameValue{game, "delivered"}], 1},
		{"events failed", after.Events[GameValue{game, "failed"}], 1},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
	if d := after.Channels["email"] - before.Channels["email"]; d < 1 {
		t.Errorf("email channels up by %d, want 1 or more", d)
	}
	if d := after.ChannelsDisabled["other"] - before.ChannelsDisabled["other"]; d < 1 {
		t.Errorf("disabled channels under other up by %d, want 1 or more", d)
	}
	for k := range after.ChannelsDisabled {
		if !slices.Contains([]string{ReasonBounced, ReasonComplained, ReasonUnsubscribed, "other"}, k) {
			t.Errorf("disabled channels keyed by %q", k)
		}
	}
}
