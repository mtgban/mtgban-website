package timeseries

import "testing"

// Sub-type names are per-game and open-ended, so the split is "Normal" against
// however many alternates a product carries, and the rows arrive in whatever
// order the warm-up scan reads them.
func TestTCGPrintings(t *testing.T) {
	type row struct {
		banID   int64
		subType string
	}
	cases := []struct {
		name      string
		rows      []row
		want      tcgPrintings
		canonical int64
	}{
		{
			name:      "normal and holofoil",
			rows:      []row{{10, "Holofoil"}, {20, "Normal"}},
			want:      tcgPrintings{normal: 20, alt: 10, altCount: 1},
			canonical: 20,
		},
		{
			name:      "foil only product has no normal",
			rows:      []row{{30, "Cold Foil"}},
			want:      tcgPrintings{alt: 30, altCount: 1},
			canonical: 30,
		},
		{
			name:      "two foil sub-types are both counted",
			rows:      []row{{50, "Holofoil"}, {40, "Cold Foil"}, {60, "Normal"}},
			want:      tcgPrintings{normal: 60, alt: 40, altCount: 2},
			canonical: 60,
		},
		{
			name:      "editions are alternates too, and there can be many",
			rows:      []row{{70, "1st Edition"}, {80, "Unlimited"}, {90, "Limited"}},
			want:      tcgPrintings{alt: 70, altCount: 3},
			canonical: 70,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var p tcgPrintings
			for _, r := range tc.rows {
				p = p.observe(r.banID, r.subType)
			}
			if p != tc.want {
				t.Errorf("printings = %+v, want %+v", p, tc.want)
			}
			if got := p.canonical(); got != tc.canonical {
				t.Errorf("canonical() = %d, want %d", got, tc.canonical)
			}
		})
	}
}

// The write path must never fall back to another printing: a base price landing
// on an alternate (or the reverse) silently overwrites it, and a product with
// several alternates can't be resolved from a foil bool at all.
func TestCachedTCGBanIDForFinish(t *testing.T) {
	var c Client
	c.variants.tcgPrintingsByProduct.Store(100, tcgPrintings{normal: 1, alt: 2, altCount: 1})
	c.variants.tcgPrintingsByProduct.Store(200, tcgPrintings{alt: 3, altCount: 1})
	c.variants.tcgPrintingsByProduct.Store(300, tcgPrintings{normal: 4})
	c.variants.tcgPrintingsByProduct.Store(400, tcgPrintings{normal: 5, alt: 6, altCount: 2})

	cases := []struct {
		name      string
		productID int
		foil      bool
		want      int64
		wantMatch TCGPrintingMatch
	}{
		{"base card takes Normal", 100, false, 1, TCGPrintingResolved},
		{"foil card takes the only alternate", 100, true, 2, TCGPrintingResolved},
		{"alternate-only product has no base printing", 200, false, 0, TCGPrintingUnknown},
		{"alternate-only product resolves its alternate", 200, true, 3, TCGPrintingResolved},
		{"base-only product has no alternate", 300, true, 0, TCGPrintingUnknown},
		{"two alternates can't be told apart", 400, true, 0, TCGPrintingAmbiguous},
		{"two alternates still resolve the base", 400, false, 5, TCGPrintingResolved},
		{"product not in the cache", 999, true, 0, TCGPrintingUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, match := c.CachedTCGBanIDForFinish(tc.productID, tc.foil)
			if got != tc.want || match != tc.wantMatch {
				t.Errorf("CachedTCGBanIDForFinish(%d, %t) = (%d, %v), want (%d, %v)",
					tc.productID, tc.foil, got, match, tc.want, tc.wantMatch)
			}
		})
	}
}

// The read path charts a bare product id, so it must keep answering with the
// canonical printing even where the write path refuses to guess.
func TestCachedTCGBanID(t *testing.T) {
	var c Client
	c.variants.tcgPrintingsByProduct.Store(100, tcgPrintings{normal: 1, alt: 2, altCount: 2})
	c.variants.tcgPrintingsByProduct.Store(200, tcgPrintings{alt: 3, altCount: 1})

	if got, ok := c.CachedTCGBanID(100); got != 1 || !ok {
		t.Errorf("CachedTCGBanID(100) = (%d, %t), want (1, true)", got, ok)
	}
	if got, ok := c.CachedTCGBanID(200); got != 3 || !ok {
		t.Errorf("CachedTCGBanID(200) = (%d, %t), want (3, true)", got, ok)
	}
	if got, ok := c.CachedTCGBanID(999); got != 0 || ok {
		t.Errorf("CachedTCGBanID(999) = (%d, %t), want (0, false)", got, ok)
	}
}

func TestMagicVariantNormalized(t *testing.T) {
	cases := []struct {
		name string
		in   MagicVariant
		want MagicVariant
	}{
		{
			name: "strips mtgmatcher suffix and normalizes english",
			in:   MagicVariant{MtgjsonUUID: "abcdef01-2345-6789-abcd-ef0123456789_f", Language: "English"},
			want: MagicVariant{MtgjsonUUID: "abcdef01-2345-6789-abcd-ef0123456789", Language: ""},
		},
		{
			name: "keeps a clean uuid and a real language",
			in:   MagicVariant{MtgjsonUUID: "abcdef01-2345-6789-abcd-ef0123456789", IsFoil: true, Language: "Japanese"},
			want: MagicVariant{MtgjsonUUID: "abcdef01-2345-6789-abcd-ef0123456789", IsFoil: true, Language: "Japanese"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in.normalized()
			if got != tc.want {
				t.Errorf("normalized() = %+v, want %+v", got, tc.want)
			}
		})
	}
}
