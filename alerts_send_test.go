package main

import (
	"testing"
)

func TestAlertSiteURL(t *testing.T) {
	withConfigCopy(t)
	savedDev := DevMode
	t.Cleanup(func() { DevMode = savedDev })
	Config().Game = DefaultGame
	Config().SiteURL = "https://lorcana.mtgban.com/"
	got := alertSiteURL()
	if got != "https://lorcana.mtgban.com" {
		t.Fatalf("trailing slash kept: %q", got)
	}
	Config().SiteURL, DevMode, Config().Port = "", true, "8080"
	got = alertSiteURL()
	if got != "http://localhost:8080" {
		t.Fatalf("dev fallback = %q", got)
	}
	DevMode = false
	got = alertSiteURL()
	if got != DefaultExternalURL {
		t.Fatalf("prod fallback = %q", got)
	}
	Config().Game = "lorcana"
	got = alertSiteURL()
	if got != "" {
		t.Fatalf("non-Magic prod fallback = %q, want empty", got)
	}
	Config().SiteURL = "https://lorcana.mtgban.com"
	got = alertSiteURL()
	if got != "https://lorcana.mtgban.com" {
		t.Fatalf("non-Magic configured = %q", got)
	}
}
