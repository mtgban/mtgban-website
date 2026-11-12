package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/mtgban/mtgban-website/internal/alerts"
	"github.com/mtgban/mtgban-website/observability"
	"github.com/mtgban/mtgban-website/userstate"
)

// stockSources is where the stock job reads and writes; a nil State or Alerts is skipped, a nil Write is an error.
type stockSources struct {
	State  func(ctx context.Context, now time.Time) (userstate.Stock, error)
	Alerts func(ctx context.Context) (alerts.Stock, error)
	Write  func(ctx context.Context, day time.Time, instance string, names []string, rows []observability.Row) error
}

// stockSources reads the userstate and alerts stores and writes the shared stock rows.
func (s *site) stockSources() stockSources {
	src := stockSources{Write: ObservabilityDB.ReplaceDayRows}
	if UserStateDB != nil {
		src.State = UserStateDB.StockCounts
	}
	if store := s.alerts.Store(); store != nil {
		src.Alerts = store.StockCounts
	}
	return src
}

// stockKey is one stock row's key before the registry checks it.
type stockKey struct{ name, scope, value string }

// stockTally sums counts by key, dropping games no deployment has.
type stockTally struct {
	n            map[stockKey]int64
	unknownGames int
}

// add sums n at key; a zero count adds nothing.
func (t *stockTally) add(name, scope, value string, n int64) {
	if n != 0 {
		t.n[stockKey{name, scope, value}] += n
	}
}

// always writes name with no value, even at zero.
func (t *stockTally) always(name string, n int64) {
	t.n[stockKey{name: name}] += n
}

// game sums n under game when a deployment can be that game.
func (t *stockTally) game(name, game, value string, n int64) {
	if n == 0 {
		return
	}
	if !slices.Contains(observability.StockGames(), game) {
		t.unknownGames++
		return
	}
	t.add(name, game, value, n)
}

// bucketOf labels size under name's edges.
func bucketOf(name string, size int) string {
	label, _ := observability.BucketFor(name, int64(size))
	return label
}

// stockRows maps the counts to stock rows, leaving out and counting what the registry refuses and games no deployment has.
func stockRows(state *userstate.Stock, alert *alerts.Stock) (rows []observability.Row, refused, unknownGames int) {
	t := stockTally{n: map[stockKey]int64{}}
	if state != nil {
		for name, n := range map[string]int64{
			"stock.rows": state.Rows, "stock.synced_7d": state.Synced7d, "stock.synced_30d": state.Synced30d,
			"stock.arbit_pins": state.ArbitPins, "stock.news_filters": state.NewsFilters,
			"stock.nav_layout": state.NavLayout, "stock.sessions": state.Sessions,
		} {
			t.always(name, n)
		}
		for name, sizes := range map[string]map[int]int64{
			"stock.favorites": state.Favorites, "stock.recents": state.Recents,
			"stock.backpack": state.Backpack, "stock.backpack_tabs": state.BackpackTabs,
			"stock.upload_presets": state.UploadPresets, "stock.arbit_presets": state.ArbitPresets,
		} {
			for size, n := range sizes {
				t.add(name, "", bucketOf(name, size), n)
			}
		}
		for key, n := range state.Prefs {
			t.add("stock.pref", "", key, n)
		}
		for game, n := range state.UploadShares {
			t.game("stock.upload_shares", game, "", n)
		}
		for game, n := range state.FavoritesShares {
			t.game("stock.fav_shares", game, "", n)
		}
	}
	if alert != nil {
		for name, m := range map[string]map[alerts.GameValue]int64{
			"stock.alerts": alert.BySide, "stock.alerts_delivery": alert.ByDelivery,
			"stock.alerts_status": alert.ByStatus, "stock.alerts_condition": alert.ByCondition,
			"stock.alert_events": alert.Events,
		} {
			for k, n := range m {
				t.game(name, k.Game, k.Value, n)
			}
		}
		for k, n := range alert.ByStores {
			t.game("stock.alerts_stores", k.Game, bucketOf("stock.alerts_stores", k.N), n)
		}
		for kind, n := range alert.Channels {
			t.add("stock.channels", "", kind, n)
		}
		for reason, n := range alert.ChannelsDisabled {
			t.add("stock.channels_disabled", "", reason, n)
		}
	}

	for k, n := range t.n {
		name, ok := observability.Lookup(k.name)
		if !ok || name.Family != observability.FamilyStock {
			refused++
			continue
		}
		// Nothing is folded: a value the registry would rewrite is refused.
		if scope, value, ok := name.Check(k.scope, k.value, observability.Validators{}); !ok || scope != k.scope || value != k.value {
			refused++
			continue
		}
		rows = append(rows, observability.Row{
			Dims:  observability.Dims{Instance: observability.SharedInstance, Device: "job"},
			Scope: k.scope, Name: k.name, Value: k.value, N: n,
		})
	}
	slices.SortFunc(rows, func(a, b observability.Row) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Scope, b.Scope), cmp.Compare(a.Value, b.Value))
	})
	return rows, refused, t.unknownGames
}

// stockNames is every registered stock name, the set a day's replace clears.
func stockNames() []string {
	var out []string
	for _, n := range observability.All() {
		if n.Family == observability.FamilyStock {
			out = append(out, n.Name)
		}
	}
	return out
}

// countStoredState counts the stored state and replaces the finished day's stock rows; a nil Write is an error.
func countStoredState(ctx context.Context, src stockSources, now time.Time) (string, error) {
	if src.Write == nil {
		return "", errors.New("stock: no writer")
	}
	var state *userstate.Stock
	if src.State != nil {
		s, err := src.State(ctx, now)
		if err != nil {
			return "", err
		}
		state = &s
	}
	var alert *alerts.Stock
	if src.Alerts != nil {
		a, err := src.Alerts(ctx)
		if err != nil {
			return "", err
		}
		alert = &a
	}
	rows, refused, unknownGames := stockRows(state, alert)
	day := utcDay(now).AddDate(0, 0, -1)
	if err := src.Write(ctx, day, observability.SharedInstance, stockNames(), rows); err != nil {
		return "", err
	}
	result := fmt.Sprintf("%d rows for %s", len(rows), day.Format("2006-01-02"))
	if src.Alerts == nil {
		result += ", alerts not counted"
	}
	if refused > 0 {
		result += fmt.Sprintf(", %d refused by the registry", refused)
	}
	if unknownGames > 0 {
		result += fmt.Sprintf(", %d under an unknown game", unknownGames)
	}
	return result, nil
}
