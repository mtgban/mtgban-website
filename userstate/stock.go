package userstate

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Stock is what the userstate tables hold, as counts and nothing else.
type Stock struct {
	Rows, Synced7d, Synced30d   int64
	Favorites, Recents          map[int]int64 // live entries -> rows
	Backpack, BackpackTabs      map[int]int64
	UploadPresets, ArbitPresets map[int]int64
	ArbitPins, NewsFilters      int64
	NavLayout                   int64
	Prefs                       map[string]int64 // synced key -> rows holding it
	Sessions                    int64
	// Keyed by the stored game; the caller drops games it does not know.
	UploadShares, FavoritesShares map[string]int64 // game -> live links
}

// SyncedPrefKeys are the PREF_KEYS of js/user-state.js, in its order.
var SyncedPrefKeys = []string{
	"mtgban_fav_sort", "mtgban_fav_sort_dir", "theme", "chartDateRange", "mtgban_nav_layout_v1",
	"chartReleasesLongRange", "chartCheckpointTypes", "offline_mode", "offline_stores", "offline_editions",
	"offline_img_editions", "mtgban_search_layout", "mtgban_popular_collapsed", "mtgban_store_factors",
	"mtgban_upload_presets", "mtgban_arbit_filters", "mtgban_arbit_presets", "mtgban_arbit_pins",
	"mtgban_backpack_tabs", "mtgban_backpack_sort", "mtgban_news_filters", "mtgban_upload_sort",
}

// stockQueries is every query StockCounts runs; none reads a column naming a reader.
var stockQueries = map[string]string{
	"state":            `SELECT favorites, recents, preferences, backpack, updated_at FROM user_state`,
	"sessions":         `SELECT count(*) FROM patreon_sessions WHERE expires_at > $1`,
	"upload_shares":    `SELECT game, count(*) FROM upload_shares WHERE expires_at > $1 GROUP BY game`,
	"favorites_shares": `SELECT game, count(*) FROM favorites_shares WHERE revoked_at IS NULL GROUP BY game`,
}

// StockCounts counts what the tables hold, one pass each, judged at now.
func (c *Client) StockCounts(ctx context.Context, now time.Time) (Stock, error) {
	var s Stock
	if err := c.tallyStates(ctx, &s, now, stockQueries["state"]); err != nil {
		return Stock{}, fmt.Errorf("userstate: stock state: %w", err)
	}
	if err := c.db.QueryRowContext(ctx, stockQueries["sessions"], now).Scan(&s.Sessions); err != nil {
		return Stock{}, fmt.Errorf("userstate: stock sessions: %w", err)
	}
	var err error
	if s.UploadShares, err = c.countByGame(ctx, stockQueries["upload_shares"], now); err != nil {
		return Stock{}, fmt.Errorf("userstate: stock upload shares: %w", err)
	}
	if s.FavoritesShares, err = c.countByGame(ctx, stockQueries["favorites_shares"]); err != nil {
		return Stock{}, fmt.Errorf("userstate: stock favorites shares: %w", err)
	}
	return s, nil
}

// tallyStates streams the state rows query returns through tallyState.
func (c *Client) tallyStates(ctx context.Context, s *Stock, now time.Time, query string, args ...any) error {
	rows, err := c.db.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var fav, rec, pref, pack []byte
		var updatedAt time.Time
		if err := rows.Scan(&fav, &rec, &pref, &pack, &updatedAt); err != nil {
			return err
		}
		tallyState(s, State{Favorites: fav, Recents: rec, Preferences: pref, Backpack: pack}, updatedAt, now)
	}
	return rows.Err()
}

// countByGame reads a game and count per row of query.
func (c *Client) countByGame(ctx context.Context, query string, args ...any) (map[string]int64, error) {
	rows, err := c.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var game string
		var n int64
		if err := rows.Scan(&game, &n); err != nil {
			return nil, err
		}
		out[game] = n
	}
	return out, rows.Err()
}

// tallyState adds one row to s; what does not parse counts as empty.
func tallyState(s *Stock, st State, updatedAt, now time.Time) {
	s.Rows++
	if !updatedAt.Before(now.AddDate(0, 0, -7)) {
		s.Synced7d++
	}
	if !updatedAt.Before(now.AddDate(0, 0, -30)) {
		s.Synced30d++
	}

	var prefs map[string]json.RawMessage
	if json.Unmarshal(st.Preferences, &prefs) != nil {
		prefs = nil
	}
	for _, k := range SyncedPrefKeys {
		if _, ok := prefs[k]; ok {
			bump(&s.Prefs, k)
		}
	}

	bump(&s.Favorites, countLive(objects(st.Favorites)))
	bump(&s.Recents, countLive(objects(st.Recents)))

	// Live backpack entries, as js/backpack.js read and live keep them.
	packs := map[int]bool{}
	entries := 0
	for _, e := range objects(st.Backpack) {
		if nonEmpty(e, "id") && isLive(e["del"]) {
			entries++
			packs[backpackPack(e["pack"])] = true
		}
	}
	for _, t := range objects(prefString(prefs, backpackTabsKey)) {
		if isLive(t["del"]) {
			packs[backpackPack(t["pack"])] = true
		}
	}
	bump(&s.Backpack, entries)
	bump(&s.BackpackTabs, len(packs))

	// Upload presets as js/upload-presets.js readAll keeps them; opts must be truthy.
	n := 0
	for _, p := range objects(prefString(prefs, "mtgban_upload_presets")) {
		if nonEmpty(p, "id") && nonEmpty(p, "name") && !isLive(p["opts"]) && isLive(p["del"]) {
			n++
		}
	}
	bump(&s.UploadPresets, n)

	// Arbit presets as js/arbit-presets.js readAll keeps them.
	n = 0
	for _, p := range objects(prefString(prefs, "mtgban_arbit_presets")) {
		_, isQ := p["q"].(string)
		group := str(p, "group")
		if nonEmpty(p, "id") && nonEmpty(p, "name") && isQ && (group == "arbit" || group == "global") && isLive(p["del"]) {
			n++
		}
	}
	bump(&s.ArbitPresets, n)

	if pins := object(prefString(prefs, "mtgban_arbit_pins")); len(pins) > 0 {
		s.ArbitPins++
	}
	for _, f := range object(prefString(prefs, "mtgban_news_filters")) {
		if e, ok := f.(map[string]any); ok && nonEmpty(e, "q") {
			s.NewsFilters++
			break
		}
	}
	if object(prefString(prefs, "mtgban_nav_layout_v1")) != nil {
		s.NavLayout++
	}
}

// bump adds one row at key k, making the map on first use.
func bump[K comparable](m *map[K]int64, k K) {
	if *m == nil {
		*m = map[K]int64{}
	}
	(*m)[k]++
}

// objects is the elements of a JSON list that are objects; anything else has none.
func objects(raw []byte) []map[string]any {
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) != nil {
		return nil
	}
	out := make([]map[string]any, 0, len(list))
	for _, e := range list {
		var o map[string]any
		if json.Unmarshal(e, &o) == nil && o != nil {
			out = append(out, o)
		}
	}
	return out
}

// object is raw decoded as a JSON object, nil when it is not one.
func object(raw []byte) map[string]any {
	var o map[string]any
	if json.Unmarshal(raw, &o) != nil {
		return nil
	}
	return o
}

// prefString is the text a preference holds as a JSON string, nil when it holds none.
func prefString(prefs map[string]json.RawMessage, key string) []byte {
	var v string
	if json.Unmarshal(prefs[key], &v) != nil {
		return nil
	}
	return []byte(v)
}

// countLive counts the entries whose del is unset.
func countLive(list []map[string]any) int {
	n := 0
	for _, e := range list {
		if isLive(e["del"]) {
			n++
		}
	}
	return n
}

// str is the string o holds at key, empty when it holds none.
func str(o map[string]any, key string) string {
	if v, ok := o[key].(string); ok {
		return v
	}
	return ""
}

// nonEmpty says o holds a non-empty string at key.
func nonEmpty(o map[string]any, key string) bool {
	return str(o, key) != ""
}
