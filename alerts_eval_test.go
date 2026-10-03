package main

import (
	"context"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/internal/access"
	"github.com/mtgban/mtgban-website/internal/alerts"
	"github.com/mtgban/mtgban-website/userstate"
)

func TestAlertsReadyFrom(t *testing.T) {
	for _, c := range []struct {
		uuids, sellers, vendors int
		want                    bool
	}{
		{0, 1, 1, false},
		{1, 0, 0, false},
		{1, 1, 0, true},
		{1, 0, 1, true},
	} {
		got := alertsReadyFrom(c.uuids, c.sellers, c.vendors)
		if got != c.want {
			t.Errorf("alertsReadyFrom(%d, %d, %d) = %v, want %v", c.uuids, c.sellers, c.vendors, got, c.want)
		}
	}
}

// Every closure the package calls is built by the root; a dropped one
// would nil-deref inside the tracked run or a request.
func TestAlertDepsAreWired(t *testing.T) {
	withSigMode(t, false, false)
	t.Setenv("RESEND_API_KEY", "re_test")
	s := newSite()
	d := s.alertEvalDeps()
	if d.PerRun == nil {
		t.Fatal("PerRun is nil")
	}
	d = d.PerRun(d)
	for name, missing := range map[string]bool{
		"Deliverers": len(d.Deliverers) == 0, "ChannelFor": d.ChannelFor == nil, "Channels": d.Channels == nil,
		"Ready": d.Ready == nil, "Values": d.Values == nil,
		"Allowance": d.Allowance == nil, "Prices": d.Prices == nil, "Resolve": d.Resolve == nil,
		"StoreLabel": d.StoreLabel == nil, "Log": d.Log == nil, "Report": d.Report == nil,
	} {
		if missing {
			t.Errorf("eval deps: %s is nil", name)
		}
	}
	var kinds []alerts.ChannelKind
	for _, dl := range d.Deliverers {
		kinds = append(kinds, dl.Kind())
	}
	if !slices.Equal(kinds, []alerts.ChannelKind{alerts.ChannelDiscord, alerts.ChannelEmail}) {
		t.Errorf("eval deps: deliverers %v, want discord and email", kinds)
	}
	if d.Game != string(Config().Game) {
		t.Errorf("eval deps: Game = %q, want %q", d.Game, Config().Game)
	}
	// The fresh site's empty backend: not ready, and no card resolves.
	if d.Ready() {
		t.Error("ready on an empty datastore")
	}
	_, _, found := d.Resolve("no-such-card")
	if found {
		t.Error("resolved a card on an empty datastore")
	}

	a := s.alertAPIDeps()
	for name, missing := range map[string]bool{
		"Identity": a.Identity == nil, "Allowance": a.Allowance == nil, "Prices": a.Prices == nil,
		"Resolve": a.Resolve == nil, "StoreLabel": a.StoreLabel == nil, "Game": a.Game == nil,
		"Channels": a.Channels == nil, "Mint": a.Mint == nil, "SendConfirm": a.SendConfirm == nil,
	} {
		if missing {
			t.Errorf("api deps: %s is nil", name)
		}
	}
	if a.ConfirmTTL != 24*time.Hour {
		t.Errorf("api deps: ConfirmTTL = %v", a.ConfirmTTL)
	}
	if a.Game != nil && a.Game() != string(Config().Game) {
		t.Errorf("api deps: Game() = %q, want %q", a.Game(), Config().Game)
	}
	// The service builds the limiter, and only once a store is attached.
	if a.Limiter != nil {
		t.Error("api deps carry a limiter before any store")
	}
}

// Production without RESEND_API_KEY has no mailer: no confirm sends and
// no mail deliveries pass as delivered; dev still logs.
func TestAlertMailWithoutAKey(t *testing.T) {
	withSigMode(t, false, false)
	t.Setenv("RESEND_API_KEY", "")
	s := newSite()
	if s.alertAPIDeps().SendConfirm != nil || s.alertMailer() != nil {
		t.Fatal("production without a key wired a mailer")
	}
	if err := s.sendAlertConfirm(context.Background(), "a@b.c", "https://x/confirm"); err == nil {
		t.Fatal("confirm sent without a mailer")
	}
	// The evaluator gets no mail deliverer either, so no run logs a mail
	// it could never send; email is hidden and parked instead.
	d := s.alertEvalDeps()
	d = d.PerRun(d)
	if len(d.Deliverers) != 1 || d.Deliverers[0].Kind() != alerts.ChannelDiscord {
		t.Fatalf("production without a key wired %d deliverers", len(d.Deliverers))
	}
	withSigMode(t, true, false)
	if s.alertAPIDeps().SendConfirm == nil || s.alertMailer() == nil {
		t.Fatal("dev without a key must log mail")
	}
	d = s.alertEvalDeps()
	if d = d.PerRun(d); len(d.Deliverers) != 2 {
		t.Fatalf("dev without a key wired %d deliverers, want both", len(d.Deliverers))
	}
}

// TestAlertEvalValuesCarryGrantOverrides pins PerRun's Values to the grant
// overrides path, not just the tier: a regression back to
// valuesForTierIn(ACL(), tier) must fail this test.
func TestAlertEvalValuesCarryGrantOverrides(t *testing.T) {
	savedAccess := Access
	t.Cleanup(func() { Access = savedAccess })

	files := map[string]string{
		"acl":    `{"Legacy": {"Search": {}}}`,
		"grants": `[{"email": "granted@example.com", "tier": "Legacy", "overrides": {"Alerts": {"AlertsMax": "5"}}}]`,
	}
	Access = access.New(access.Hooks{
		Open: func(_ context.Context, path string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(files[path])), nil
		},
	})
	err := Access.Load(context.Background(), access.Sources{TablePath: "acl", GrantsPath: "grants"})
	if err != nil {
		t.Fatal(err)
	}

	s := newSite()
	d := s.alertEvalDeps()
	d = d.PerRun(d)

	grantedHash := userstate.HashEmail("granted@example.com")
	got := alertAllowance(d.Values(grantedHash, "Legacy"))
	if got != 5 {
		t.Errorf("granted allowance = %d, want 5", got)
	}

	unknownHash := userstate.HashEmail("unknown@example.com")
	got = alertAllowance(d.Values(unknownHash, "Legacy"))
	if got != 0 {
		t.Errorf("unknown allowance = %d, want 0", got)
	}
}

func TestAlertSideOfKind(t *testing.T) {
	for kind, want := range map[string]alerts.Side{"retail": alerts.SideRetail, "buylist": alerts.SideBuylist, "sealed": ""} {
		got, ok := alertSideOfKind(kind)
		if got != want || ok != (want != "") {
			t.Errorf("alertSideOfKind(%q) = %q, %v", kind, got, ok)
		}
	}
}

// A reload pokes the sides its kinds price, and nothing for other kinds.
func TestPokeAlertsQueuesTheReloadedSides(t *testing.T) {
	s := newSite()
	s.pokeAlerts("retail")
	got := s.alerts.Pending()
	if got != nil {
		t.Fatalf("a site with no store queued %v", got)
	}
	s.alerts.SetStore(&alerts.Store{})
	s.pokeAlerts("sealed")
	got = s.alerts.Pending()
	if got != nil {
		t.Fatalf("an unpriced kind queued %v", got)
	}
	s.pokeAlerts("retail", "buylist")
	got = s.alerts.Pending()
	if !slices.Equal(got, []alerts.Side{alerts.SideBuylist, alerts.SideRetail}) {
		t.Fatalf("Pending = %v", got)
	}
}
