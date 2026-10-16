package main

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/mtgban/mtgban-website/internal/alerts"
)

// adminAlertsLimit caps the rows the Alerts tab lists.
const adminAlertsLimit = 100

// alertsAdminStore is what the Alerts tab reads from the alerts store.
type alertsAdminStore interface {
	AdminTotals(ctx context.Context, game string) (alerts.AdminTotals, error)
	ListRecent(ctx context.Context, game string, limit int) ([]alerts.Alert, error)
}

// AlertAdminRow is one alert as the tab lists it: the owner by a prefix of
// the hash, enough to group one user's rows and not the hash itself.
type AlertAdminRow struct {
	Owner string
	alerts.Alert
}

// AlertsAdminDashboard is the admin's view of this game's alerts table:
// the counts, and the newest rows. Failed says a query did not answer.
type AlertsAdminDashboard struct {
	Game    string
	Totals  alerts.AdminTotals
	Active  int
	Paused  int
	Parked  int
	Buylist int
	Retail  int
	Discord int
	Email   int
	Rows    []AlertAdminRow
	Dropped int // alerts past the row cap
	Failed  bool
	Loaded  time.Time
}

type alertsAdminCacheEntry struct {
	dash    *AlertsAdminDashboard
	fetched time.Time
}

var alertsAdminCache = struct {
	mu     sync.Mutex
	byGame map[string]alertsAdminCacheEntry
}{byGame: map[string]alertsAdminCacheEntry{}}

// loadAlertsDashboard serves the game's dashboard from the cache within
// usageCacheTTL, fetching it otherwise; a failed fetch is not kept.
func loadAlertsDashboard(ctx context.Context, store alertsAdminStore, game string) *AlertsAdminDashboard {
	alertsAdminCache.mu.Lock()
	defer alertsAdminCache.mu.Unlock()

	entry, found := alertsAdminCache.byGame[game]
	if !found || time.Since(entry.fetched) >= usageCacheTTL {
		dash := fetchAlertsDashboard(ctx, store, game)
		entry = alertsAdminCacheEntry{dash: dash, fetched: time.Now()}
		if !dash.Failed {
			alertsAdminCache.byGame[game] = entry
		}
	}
	return entry.dash
}

func fetchAlertsDashboard(ctx context.Context, store alertsAdminStore, game string) *AlertsAdminDashboard {
	dash := &AlertsAdminDashboard{Game: game, Loaded: time.Now()}
	totals, err := store.AdminTotals(ctx, game)
	if err != nil {
		log.Println("admin alerts: totals:", err)
		dash.Failed = true
	}
	dash.Totals = totals
	dash.Active = totals.ByStatus[alerts.StatusActive]
	dash.Paused = totals.ByStatus[alerts.StatusPaused]
	dash.Parked = totals.ByStatus[alerts.StatusOverAllowance]
	dash.Buylist = totals.BySide[alerts.SideBuylist]
	dash.Retail = totals.BySide[alerts.SideRetail]
	dash.Discord = totals.ByDelivery[alerts.DeliveryDiscord]
	dash.Email = totals.ByDelivery[alerts.DeliveryEmail]

	rows, err := store.ListRecent(ctx, game, adminAlertsLimit)
	if err != nil {
		log.Println("admin alerts: rows:", err)
		dash.Failed = true
	}
	dash.Rows = make([]AlertAdminRow, 0, len(rows))
	for _, a := range rows {
		dash.Rows = append(dash.Rows, AlertAdminRow{Owner: ownerPrefix(a.UserHash), Alert: a})
	}
	if d := totals.Alerts - len(rows); d > 0 {
		dash.Dropped = d
	}
	return dash
}

// ownerPrefix is the first 8 characters of a user hash.
func ownerPrefix(userHash string) string {
	if len(userHash) > 8 {
		return userHash[:8]
	}
	return userHash
}
