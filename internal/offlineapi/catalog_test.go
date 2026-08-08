package offlineapi

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

func TestImageKey(t *testing.T) {
	tests := []struct {
		name       string
		imagesFull string
		setCode    string
		sealed     bool
		want       string
	}{
		{
			name:       "single scryfall url",
			imagesFull: "https://cards.scryfall.io/normal/front/a/b/abc123-def.jpg",
			setCode:    "NEO",
			sealed:     false,
			want:       "abc123-def",
		},
		{
			name:       "sealed tcgplayer url",
			imagesFull: "https://product-images.tcgplayer.com/12345.jpg",
			setCode:    "NEO",
			sealed:     true,
			want:       "p-NEO-12345",
		},
		{
			name:       "empty url",
			imagesFull: "",
			setCode:    "NEO",
			sealed:     false,
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := imageKey(tt.imagesFull, tt.setCode, tt.sealed)
			if got != tt.want {
				t.Errorf("imageKey(%q, %q, %v) = %q, want %q", tt.imagesFull, tt.setCode, tt.sealed, got, tt.want)
			}
		})
	}
}

func TestNewCatalogCardIncludesImageKey(t *testing.T) {
	co := &mtgmatcher.CardObject{
		Card: mtgmatcher.Card{
			Name:    "Lightning Bolt",
			Number:  "1",
			Rarity:  "common",
			SetCode: "LEA",
			Images:  map[string]string{"full": "https://cards.scryfall.io/normal/front/a/b/abcd1234.jpg"},
		},
	}

	card := newCatalogCard(co, nil)
	if card.Image != "abcd1234" {
		t.Errorf("Image = %q, want %q", card.Image, "abcd1234")
	}
}

func TestNewCatalogCardSealed(t *testing.T) {
	co := &mtgmatcher.CardObject{
		Card: mtgmatcher.Card{
			Name:    "Modern Horizons 3 Collector Booster",
			SetCode: "MH3",
			Images:  map[string]string{"full": "https://product-images.tcgplayer.com/541185.jpg"},
		},
		Sealed: true,
	}

	card := newCatalogCard(co, nil)
	if !card.Sealed {
		t.Error("Sealed = false, want true")
	}
	if card.Image != "p-MH3-541185" {
		t.Errorf("Image = %q, want %q", card.Image, "p-MH3-541185")
	}
}

func TestNewCatalogCardOmitsImageKeyWhenMissing(t *testing.T) {
	co := &mtgmatcher.CardObject{
		Card: mtgmatcher.Card{
			Name:    "No Image Card",
			SetCode: "LEA",
		},
	}

	card := newCatalogCard(co, nil)
	if card.Image != "" {
		t.Errorf("Image = %q, want empty", card.Image)
	}
}
