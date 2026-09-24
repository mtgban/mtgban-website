package manabox

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestParseDeckURL(t *testing.T) {
	id, err := ParseDeckURL("https://manabox.app/decks/AaC6XaAWcOq3CRiJ-rVEDg")
	if err != nil {
		t.Fatal(err)
	}
	if id != "AaC6XaAWcOq3CRiJ-rVEDg" {
		t.Fatalf("got %q", id)
	}
	if _, err := ParseDeckURL("https://moxfield.com/decks/x"); err == nil {
		t.Fatal("expected error for non-manabox host")
	}
}

func TestLoadLive(t *testing.T) {
	if os.Getenv("MANABOX_LIVE") == "" {
		t.Skip("MANABOX_LIVE not set; skipping live ManaBox test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	items, name, err := Load(ctx, "https://manabox.app/decks/AaC6XaAWcOq3CRiJ-rVEDg", 0)
	if err != nil {
		t.Fatal(err)
	}
	if name == "" || len(items) == 0 {
		t.Fatalf("name=%q items=%d", name, len(items))
	}
	t.Logf("deck %q with %d cards", name, len(items))
}
