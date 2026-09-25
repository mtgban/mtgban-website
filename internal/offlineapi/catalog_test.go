package offlineapi

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// cardFor builds a card object. id is the identifier the mirror files the
// image under - scryfallId for a Magic single, tcgplayerProductId for Magic
// sealed - which is deliberately not the same thing as whatever the image url
// happens to be named.
func cardFor(uuid, setCode, imagesFull, id string, sealed bool) *mtgmatcher.CardObject {
	co := &mtgmatcher.CardObject{
		Card:   mtgmatcher.Card{UUID: uuid, SetCode: setCode},
		Sealed: sealed,
	}
	if imagesFull != "" {
		co.Images = map[string]string{"full": imagesFull}
	}
	if id != "" {
		field := "scryfallId"
		if sealed {
			field = "tcgplayerProductId"
		}
		co.Identifiers = map[string]string{field: id}
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
			name:  "magic single keys on its scryfall id",
			co:    cardFor("mtgjson-uuid", "NEO", "https://cards.scryfall.io/grid/front/a/b/abc123-def.webp", "abc123-def", false),
			magic: true,
			want:  "abc123-def",
		},
		// 436 printings, the Italian Legends reprints among them, carry an
		// image url named for a different Scryfall entry than the one their
		// scryfallId names. The mirror files them under the identifier, so
		// reading the url instead asked for a key it never stored and those
		// cards silently had no image at all.
		{
			name:  "magic single follows the identifier when the url disagrees",
			co:    cardFor("mtgjson-uuid", "LEGITA", "https://cards.scryfall.io/grid/front/e/3/e3958d77-aaaa-bbbb-cccc-dddddddddddd.webp", "5c970830-1111-2222-3333-444444444444", false),
			magic: true,
			want:  "5c970830-1111-2222-3333-444444444444",
		},
		{
			name:  "magic sealed keys on set code and tcgplayer id",
			co:    cardFor("mtgjson-uuid", "NEO", "https://product-images.tcgplayer.com/12345.jpg", "12345", true),
			magic: true,
			want:  "p-NEO-12345",
		},
		{
			name:  "no image means no key",
			co:    cardFor("mtgjson-uuid", "NEO", "", "abc123-def", false),
			magic: true,
			want:  "",
		},
		// The mirror skips a card it has no scryfall id for, so a key built
		// from anything else would name an object that was never stored.
		{
			name:  "magic single with no scryfall id has no key",
			co:    cardFor("mtgjson-uuid", "NEO", "https://cards.scryfall.io/grid/front/a/b/abc.webp", "", false),
			magic: true,
			want:  "",
		},
		// The datastore games key on the product: their image urls are their
		// CDN's filenames and name nothing anything else knows.
		{
			name: "datastore single keys on its product, not its uuid or url",
			co:   datastoreCard("dtd011_502592_rainbowfoil", "502592", "https://cdn.example.invalid/cards/502592.jpg"),
			want: "502592",
		},
		{
			name: "datastore single naming no product and no finishes keys on its uuid",
			co:   datastoreCard("unl-t01", "", "https://cdn.example.invalid/a.png"),
			want: "unl-t01",
		},
		{
			name: "datastore sealed keeps the p- prefix and its own uuid",
			co:   cardFor("1-600001", "TFC", "https://cdn.example.invalid/sealed/box.jpg", "", true),
			want: "p-1-600001",
		},
		{
			name: "datastore card with no image has no key either",
			co:   datastoreCard("dtd011_502592_rainbowfoil", "502592", ""),
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

// datastoreCard builds a datastore game's single the way the loaders do: its
// TCGplayer product id, where it names one, among its identifiers.
func datastoreCard(uuid, product, imagesFull string) *mtgmatcher.CardObject {
	co := cardFor(uuid, "DTD", imagesFull, "", false)
	if product != "" {
		co.Identifiers = map[string]string{"tcgplayerProductId": product}
	}
	return co
}

// Collector number DTD011 is two Flesh and Blood products, 502592 sold in
// Normal and Rainbow Foil and 502740 in Cold Foil, and AGB008 is two products
// of one finish each. Cutting the uuid at its last underscore gave 502592's
// finishes "dtd011" and "dtd011_502592", and both AGB008 products "agb008".
func TestDatastoreImageKeyFollowsTheProduct(t *testing.T) {
	for _, tt := range []struct{ uuid, product string }{
		{"dtd011_502592", "502592"},
		{"dtd011_502592_rainbowfoil", "502592"},
		{"dtd011_502740_coldfoil", "502740"},
		{"agb008_633694", "633694"},
		{"agb008_633695", "633695"},
	} {
		co := datastoreCard(tt.uuid, tt.product, "https://cdn.example.invalid/x.jpg")
		if got := imageKey(co, false); got != tt.product {
			t.Errorf("imageKey(%s) = %q, want its product %q", tt.uuid, got, tt.product)
		}
	}
}

// Riftbound's tokens name no product, and unl-t01 is sold in two finishes
// sharing one image. Keyed on their uuids they would be filed twice, so they
// share the key of the printing they are finishes of.
func TestDatastoreImageKeyFoldsAPrintingThatNamesNoProduct(t *testing.T) {
	foilUUIDs := map[string]string{"nonfoil": "unl-t01", "foil": "unl-t01_foil"}
	for _, uuid := range []string{"unl-t01", "unl-t01_foil"} {
		co := datastoreCard(uuid, "", "https://cdn.example.invalid/a.png")
		co.FoilUUIDs = foilUUIDs
		if got := imageKey(co, false); got != "unl-t01_foil" {
			t.Errorf("imageKey(%s) = %q, want the printing's %q", uuid, got, "unl-t01_foil")
		}
	}
}

func TestNewCatalogCardIncludesImageKey(t *testing.T) {
	co := &mtgmatcher.CardObject{
		Card: mtgmatcher.Card{
			Name:        "Lightning Bolt",
			Number:      "1",
			Rarity:      "common",
			SetCode:     "LEA",
			Images:      map[string]string{"full": "https://cards.scryfall.io/grid/front/a/b/abcd1234.webp"},
			Identifiers: map[string]string{"scryfallId": "abcd1234"},
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
			Name:        "Modern Horizons 3 Collector Booster",
			SetCode:     "MH3",
			Images:      map[string]string{"full": "https://product-images.tcgplayer.com/541185.jpg"},
			Identifiers: map[string]string{"tcgplayerProductId": "541185"},
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
