package archidekt

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestParseDeckURL(t *testing.T) {
	good := map[string]string{
		"https://archidekt.com/decks/27936929/breena":        "27936929",
		"https://www.archidekt.com/decks/27936929":           "27936929",
		"https://archidekt.com/decks/27936929/breena?tab=x/": "27936929",
	}
	for link, want := range good {
		id, err := ParseDeckURL(link)
		if err != nil || id != want {
			t.Errorf("ParseDeckURL(%q) = %q, %v, want %q", link, id, err, want)
		}
	}

	bad := []string{
		"https://moxfield.com/decks/27936929",
		"https://archidekt.com/decks/",
		"https://archidekt.com/decks/..",
		"https://archidekt.com/decks/%2e%2e/x",
		"https://archidekt.com/decks/-1",
		"https://archidekt.com/folders/27936929",
	}
	for _, link := range bad {
		_, err := ParseDeckURL(link)
		if err == nil {
			t.Errorf("ParseDeckURL(%q) succeeded, want an error", link)
		}
	}
}

func TestDeckItems(t *testing.T) {
	const payload = `{
		"name": "Test",
		"categories": [
			{"name": "Maybeboard", "includedInDeck": false},
			{"name": "Sideboard", "includedInDeck": false},
			{"name": "Ramp", "includedInDeck": true}
		],
		"cards": [
			{"quantity": 1, "modifier": "Normal", "categories": ["Ramp"], "card": {"uid": "a"}},
			{"quantity": 2, "modifier": "Foil", "categories": [], "card": {"uid": "b"}},
			{"quantity": 1, "modifier": "Etched", "categories": ["Ramp", "Maybeboard"], "card": {"uid": "c"}},
			{"quantity": 1, "modifier": "Normal", "categories": ["Maybeboard", "Ramp"], "card": {"uid": "d"}},
			{"quantity": 1, "modifier": "Normal", "card": {"uid": ""}},
			{"quantity": 0, "modifier": "Normal", "card": {"uid": "e"}},
			{"quantity": 1, "modifier": "Normal", "categories": ["Sideboard"], "card": {"uid": "f"}}
		]
	}`
	var deck deckPayload
	err := json.Unmarshal([]byte(payload), &deck)
	if err != nil {
		t.Fatal(err)
	}

	items := deckItems(&deck, 0)
	if len(items) != 4 {
		t.Fatalf("got %d items, want 4: %+v", len(items), items)
	}
	if items[0].ScryfallID != "a" || items[0].IsFoil || items[0].IsEtched {
		t.Errorf("item 0 = %+v", items[0])
	}
	if items[1].ScryfallID != "b" || !items[1].IsFoil || items[1].Quantity != 2 {
		t.Errorf("item 1 = %+v", items[1])
	}
	if items[2].ScryfallID != "c" || !items[2].IsEtched {
		t.Errorf("item 2 = %+v", items[2])
	}
	if items[3].ScryfallID != "f" {
		t.Errorf("item 3 = %+v, want the Sideboard card", items[3])
	}

	if got := deckItems(&deck, 2); len(got) != 2 {
		t.Errorf("maxRows 2 kept %d items", len(got))
	}
}

func TestLoadLive(t *testing.T) {
	if os.Getenv("ARCHIDEKT_LIVE") == "" {
		t.Skip("ARCHIDEKT_LIVE not set; skipping live Archidekt test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	items, name, err := Load(ctx, "https://archidekt.com/decks/27936929/breena", 0)
	if err != nil {
		t.Fatal(err)
	}
	if name == "" || len(items) == 0 {
		t.Fatalf("name=%q items=%d", name, len(items))
	}
	t.Logf("deck %q with %d cards", name, len(items))
}
