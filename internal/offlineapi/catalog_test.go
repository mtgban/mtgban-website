package offlineapi

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

func cardFor(uuid, setCode, imagesFull string, sealed bool) *mtgmatcher.CardObject {
	co := &mtgmatcher.CardObject{
		Card:   mtgmatcher.Card{UUID: uuid, SetCode: setCode},
		Sealed: sealed,
	}
	if imagesFull != "" {
		co.Images = map[string]string{"full": imagesFull}
	}
	return co
}

func TestImageKey(t *testing.T) {
	tests := []struct {
		name  string
		co    *mtgmatcher.CardObject
		magic bool
		want  string
	}{
		{
			name:  "magic single keys on the scryfall id in its url",
			co:    cardFor("mtgjson-uuid", "NEO", "https://cards.scryfall.io/normal/front/a/b/abc123-def.jpg", false),
			magic: true,
			want:  "abc123-def",
		},
		{
			name:  "magic sealed keys on set code and tcgplayer id",
			co:    cardFor("mtgjson-uuid", "NEO", "https://product-images.tcgplayer.com/12345.jpg", true),
			magic: true,
			want:  "p-NEO-12345",
		},
		{
			name:  "no image means no key",
			co:    cardFor("mtgjson-uuid", "NEO", "", false),
			magic: true,
			want:  "",
		},
		// The datastore games key on the card's own uuid: their image urls are
		// their CDN's filenames and name nothing anything else knows.
		{
			name: "datastore single keys on its uuid, not its url",
			co:   cardFor("1854", "TFC", "https://cdn.example.invalid/cards/elsa-1854.jpg", false),
			want: "1854",
		},
		{
			name: "datastore finish resolves to the printing that holds the image",
			co:   cardFor("1854_f", "TFC", "https://cdn.example.invalid/cards/elsa-1854.jpg", false),
			want: "1854",
		},
		// Riftbound files no bare printing at all, only finishes, so this is
		// the only shape its cards ever take.
		{
			name: "datastore dashed finish resolves the same way",
			co:   cardFor("ogn-066-298_foil", "OGN", "https://cdn.example.invalid/a.png", false),
			want: "ogn-066-298",
		},
		{
			name: "datastore sealed keeps the p- prefix and its own uuid",
			co:   cardFor("1-600001", "TFC", "https://cdn.example.invalid/sealed/box.jpg", true),
			want: "p-1-600001",
		},
		{
			name: "datastore card with no image has no key either",
			co:   cardFor("1854_f", "TFC", "", false),
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := imageKey(tt.co, tt.magic)
			if got != tt.want {
				t.Errorf("imageKey(%+v, magic=%v) = %q, want %q", tt.co.Card.UUID, tt.magic, got, tt.want)
			}
		})
	}
}

// A uuid with no finish suffix is a printing already, and one that opens with
// an underscore is not a suffix to strip but a name that happens to start with
// one; trimming either would ask the bundle for a key that is not in it.
func TestBasePrintingIDLeavesNonSuffixesAlone(t *testing.T) {
	for _, id := range []string{"1854", "ogn-066-298", "_leading", ""} {
		if got := basePrintingID(id); got != id {
			t.Errorf("basePrintingID(%q) = %q, want it unchanged", id, got)
		}
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

	card := newCatalogCard(co, nil, true)
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

	card := newCatalogCard(co, nil, true)
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

	card := newCatalogCard(co, nil, true)
	if card.Image != "" {
		t.Errorf("Image = %q, want empty", card.Image)
	}
}
