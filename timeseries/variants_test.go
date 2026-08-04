package timeseries

import "testing"

// Sub-type names are per-game, so the split is "Normal" vs everything else, and
// the rows arrive in whatever order the warm-up scan reads them.
func TestTCGFinishes(t *testing.T) {
	type row struct {
		banID   int64
		subType string
	}
	cases := []struct {
		name          string
		rows          []row
		normal        int64
		foil          int64
		canonicalWant int64
	}{
		{
			name:          "normal and holofoil",
			rows:          []row{{10, "Holofoil"}, {20, "Normal"}},
			normal:        20,
			foil:          10,
			canonicalWant: 20,
		},
		{
			name:          "foil only product keeps no normal",
			rows:          []row{{30, "Cold Foil"}},
			foil:          30,
			canonicalWant: 30,
		},
		{
			name:          "two foil sub-types pick the smallest ban_id",
			rows:          []row{{50, "Holofoil"}, {40, "Cold Foil"}, {60, "Normal"}},
			normal:        60,
			foil:          40,
			canonicalWant: 60,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var f tcgFinishes
			for _, r := range tc.rows {
				f = f.observe(r.banID, r.subType)
			}
			if f.normal != tc.normal || f.foil != tc.foil {
				t.Errorf("finishes = %+v, want normal=%d foil=%d", f, tc.normal, tc.foil)
			}
			if got := f.canonical(); got != tc.canonicalWant {
				t.Errorf("canonical() = %d, want %d", got, tc.canonicalWant)
			}
		})
	}
}

// The write path must never fall back to the other finish: a non-foil price
// landing on the foil variant (or the reverse) silently overwrites it.
func TestCachedTCGBanIDForFinish(t *testing.T) {
	var c Client
	c.variants.tcgNormalByProduct.Store(100, int64(1))
	c.variants.tcgFoilByProduct.Store(100, int64(2))
	c.variants.tcgFoilByProduct.Store(200, int64(3))

	cases := []struct {
		productID int
		foil      bool
		want      int64
		wantOK    bool
	}{
		{productID: 100, foil: false, want: 1, wantOK: true},
		{productID: 100, foil: true, want: 2, wantOK: true},
		{productID: 200, foil: true, want: 3, wantOK: true},
		{productID: 200, foil: false},
		{productID: 999, foil: true},
	}
	for _, tc := range cases {
		got, ok := c.CachedTCGBanIDForFinish(tc.productID, tc.foil)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("CachedTCGBanIDForFinish(%d, %t) = (%d, %t), want (%d, %t)",
				tc.productID, tc.foil, got, ok, tc.want, tc.wantOK)
		}
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
