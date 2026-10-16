package main

import (
	"context"
	"errors"
	"html/template"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/internal/alerts"
)

// fakeAlertsAdminStore answers the two admin queries from fixed values.
type fakeAlertsAdminStore struct {
	totals alerts.AdminTotals
	rows   []alerts.Alert
	err    error
	calls  int
}

func (f *fakeAlertsAdminStore) AdminTotals(context.Context, string) (alerts.AdminTotals, error) {
	f.calls++
	return f.totals, f.err
}

func (f *fakeAlertsAdminStore) ListRecent(context.Context, string, int) ([]alerts.Alert, error) {
	return f.rows, f.err
}

// The dashboard groups the totals into the counts the tab prints, names
// each owner by a prefix of the hash, and says how many rows the cap hid.
func TestAlertsDashboardCountsAndPrefixesOwners(t *testing.T) {
	t.Cleanup(func() { alertsAdminCache.byGame = map[string]alertsAdminCacheEntry{} })
	store := &fakeAlertsAdminStore{
		totals: alerts.AdminTotals{
			Alerts: 150, Users: 4,
			ByStatus:   map[alerts.Status]int{alerts.StatusActive: 120, alerts.StatusPaused: 20, alerts.StatusOverAllowance: 10},
			BySide:     map[alerts.Side]int{alerts.SideBuylist: 100, alerts.SideRetail: 50},
			ByDelivery: map[alerts.DeliveryChannel]int{alerts.DeliveryDiscord: 140, alerts.DeliveryEmail: 10},
		},
		rows: []alerts.Alert{{ID: 7, UserHash: "0123456789abcdef", CardID: "card-1"}, {ID: 6, UserHash: "abc", CardID: "card-2"}},
	}
	dash := loadAlertsDashboard(context.Background(), store, "magic-test")

	if dash.Game != "magic-test" || dash.Failed {
		t.Fatalf("dashboard = %+v", dash)
	}
	if dash.Active != 120 || dash.Paused != 20 || dash.Parked != 10 || dash.Buylist != 100 || dash.Retail != 50 || dash.Discord != 140 || dash.Email != 10 {
		t.Errorf("counts = %+v", dash)
	}
	if dash.Dropped != 148 {
		t.Errorf("Dropped = %d, want 148 (150 alerts, 2 rows)", dash.Dropped)
	}
	if len(dash.Rows) != 2 || dash.Rows[0].Owner != "01234567" || dash.Rows[1].Owner != "abc" || dash.Rows[0].ID != 7 {
		t.Errorf("rows = %+v", dash.Rows)
	}
}

// A good load is served from the cache within the TTL; a failed one is not
// kept, so the next view asks again.
func TestAlertsDashboardCachesGoodLoadsOnly(t *testing.T) {
	t.Cleanup(func() { alertsAdminCache.byGame = map[string]alertsAdminCacheEntry{} })
	ctx := context.Background()

	failing := &fakeAlertsAdminStore{err: errors.New("down")}
	dash := loadAlertsDashboard(ctx, failing, "cache-test")
	if !dash.Failed {
		t.Fatal("a failing store did not mark the dashboard Failed")
	}
	working := &fakeAlertsAdminStore{totals: alerts.AdminTotals{Alerts: 1, Users: 1}}
	dash = loadAlertsDashboard(ctx, working, "cache-test")
	if dash.Failed || dash.Totals.Alerts != 1 {
		t.Fatalf("after a failure the next load was not fresh: %+v", dash)
	}
	loadAlertsDashboard(ctx, working, "cache-test")
	if working.calls != 1 {
		t.Errorf("store asked %d times within the TTL, want 1", working.calls)
	}
	if dash.Loaded.IsZero() || time.Since(dash.Loaded) > time.Minute {
		t.Errorf("Loaded = %v", dash.Loaded)
	}
}

// The partial renders the counts and rows, the not-configured message with
// no dashboard, and the failure notice when a query did not answer.
func TestAdminAlertsPartialRenders(t *testing.T) {
	tmpl, err := template.New("").Funcs(funcMap).ParseFiles("templates/partials/admin-alerts.html")
	if err != nil {
		t.Fatal(err)
	}
	render := func(vars PageVars) string {
		var out strings.Builder
		if err := tmpl.ExecuteTemplate(&out, "admin-alerts", vars); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}

	out := render(PageVars{})
	if !strings.Contains(out, "Alerts are not configured on this site") {
		t.Errorf("nil dashboard:\n%s", out)
	}

	fired := time.Date(2026, 10, 15, 12, 30, 0, 0, time.UTC)
	dash := &AlertsAdminDashboard{
		Game: "magic", Totals: alerts.AdminTotals{Alerts: 3, Users: 2}, Active: 2, Paused: 1, Buylist: 3, Discord: 3,
		Rows: []AlertAdminRow{{Owner: "01234567", Alert: alerts.Alert{
			ID: 7, CardID: "card-1", Side: alerts.SideBuylist, Condition: "NM", Stores: []string{"CK", "SCG"},
			ReferencePrice: 10, Above: alerts.Threshold{Kind: alerts.KindPct, Value: 10}, Delivery: alerts.DeliveryDiscord,
			Status: alerts.StatusActive, LastFiredAt: &fired, LastError: "no DM channel",
			Card:      alerts.Card{Name: "Bolt", Set: "LEA", Number: "161", Finish: "nonfoil"},
			CreatedAt: time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC),
		}}},
		Dropped: 2,
	}
	out = render(PageVars{AdminVars: AdminVars{AlertStats: dash}})
	for _, want := range []string{"3 alerts from 2 users", "active 2", "paused 1", "01234567", "Bolt", "LEA #161 nonfoil", "+10%", "2 stores", "2026-10-15 12:30", "no DM channel", "Showing 1 of 3"} {
		if !strings.Contains(out, want) {
			t.Errorf("dashboard lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "0123456789abcdef") {
		t.Error("the full owner hash was rendered")
	}

	dash.Failed = true
	out = render(PageVars{AdminVars: AdminVars{AlertStats: dash}})
	if !strings.Contains(out, "The alerts query failed") {
		t.Errorf("failed dashboard lacks the notice:\n%s", out)
	}
}
