package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// These are go-mtgban's workflow names; its workflows_test.go pins the other side.
func TestNewBantoolWorkflow(t *testing.T) {
	tests := []struct {
		game  mtgmatcher.Game
		store string
		want  bantoolWorkflow
	}{
		{"magic", "cardkingdom", bantoolWorkflow{
			EventType: "magic-cardkingdom",
			File:      "bantool-magic-cardkingdom.yml",
			RunName:   "magic / cardkingdom",
		}},
		{"lorcana", "tcg_index", bantoolWorkflow{
			EventType: "lorcana-tcg_index",
			File:      "bantool-lorcana-tcg_index.yml",
			RunName:   "lorcana / tcg_index",
		}},
	}
	for _, tt := range tests {
		got := newBantoolWorkflow(tt.game, tt.store)
		if got != tt.want {
			t.Errorf("newBantoolWorkflow(%q, %q) = %+v, want %+v", tt.game, tt.store, got, tt.want)
		}
	}
}

// Pins the stale badge, the section header's count and the banner's own
// "Stale (N):" text - not the row's logs link, which renders regardless.
func TestAdminDashboardShowsStaleBadgeAndBanner(t *testing.T) {
	withSigMode(t, true, false)

	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	prevIdx := scraperIndexPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
		scraperIndexPtr.Store(prevIdx)
	})

	threeDaysAgo := time.Now().Add(-72 * time.Hour)
	sellers := []mtgban.Seller{inventoryOf("CK", 5, threeDaysAgo)}
	var noVendors []mtgban.Vendor
	sellersPtr.Store(&sellers)
	vendorsPtr.Store(&noVendors)
	scraperIndexPtr.Store(buildScraperIndex(map[string]map[string][]string{
		"cardkingdom": {"retail": {"CK"}},
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Host = "mtgban.com"
	rec := httptest.NewRecorder()
	testSite.Admin(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()

	if !strings.Contains(body, "stale 3d") {
		t.Error("dashboard row is missing the stale 3d badge")
	}
	if !strings.Contains(body, `<span class="admin-stale-count">1 stale</span>`) {
		t.Error("the Retail Scrapers section header does not count the stale row")
	}
	if !strings.Contains(body, "Stale (1):") {
		t.Error("the page-top banner is missing or miscounts the stale store")
	}
}
