package timeseries

import (
	"strings"
	"testing"
)

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

func TestBuildWarmVariantQuery(t *testing.T) {
	cases := []struct {
		name      string
		scope     VariantScope
		wantWhere string
		wantArgs  []any
	}{
		{
			name:      "no scope reads the whole table",
			scope:     VariantScope{},
			wantWhere: "",
		},
		{
			name:      "magic only",
			scope:     VariantScope{Magic: true},
			wantWhere: "WHERE mtgjson_uuid IS NOT NULL",
		},
		{
			name:      "one category",
			scope:     VariantScope{TCGCategoryIDs: []int{71}},
			wantWhere: "WHERE tcgp_category_id IN ($1)",
			wantArgs:  []any{71},
		},
		{
			name:      "magic plus the categories it ingests",
			scope:     VariantScope{Magic: true, TCGCategoryIDs: []int{71, 89}},
			wantWhere: "WHERE mtgjson_uuid IS NOT NULL OR tcgp_category_id IN ($1,$2)",
			wantArgs:  []any{71, 89},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			query, args := buildWarmVariantQuery(tc.scope)
			if !strings.HasPrefix(query, "SELECT ban_id") {
				t.Fatalf("query does not select the variant columns: %s", query)
			}
			_, where, found := strings.Cut(query, "WHERE ")
			switch {
			case tc.wantWhere == "" && found:
				t.Errorf("unscoped warm got a WHERE clause: %s", query)
			case tc.wantWhere != "":
				if !found {
					t.Fatalf("scoped warm got no WHERE clause: %s", query)
				}
				if got := "WHERE " + strings.TrimSpace(where); got != tc.wantWhere {
					t.Errorf("where = %q, want %q", got, tc.wantWhere)
				}
			}
			if len(args) != len(tc.wantArgs) {
				t.Fatalf("args = %v, want %v", args, tc.wantArgs)
			}
			for i := range args {
				if args[i] != tc.wantArgs[i] {
					t.Errorf("args[%d] = %v, want %v", i, args[i], tc.wantArgs[i])
				}
			}
		})
	}
}

// A derived id is the variant's own numbers laid side by side, so it can be
// read off by eye and computed anywhere without asking the table.
func TestTCGBanIDLayout(t *testing.T) {
	got, ok := TCGBanID(TCGVariant{CategoryID: 71, ProductID: 492703, SubType: "Cold Foil"})
	if !ok {
		t.Fatal("TCGBanID refused a Lorcana cold foil")
	}
	if want := int64(71)<<40 | int64(492703)<<8 | 4; got != want {
		t.Errorf("TCGBanID = %d, want %d", got, want)
	}
}

// Every derived id has to sit above the identity sequence the existing rows
// were numbered from, or a new row could take an old row's id, and under 2^53
// so the browser reads the same number the server wrote.
func TestTCGBanIDRange(t *testing.T) {
	const identityCeiling = 1 << 32 // the sequence stood at ~2M when ids were first derived
	lo, _ := TCGBanID(TCGVariant{CategoryID: 1, ProductID: 1, SubType: ""})
	hi, _ := TCGBanID(TCGVariant{CategoryID: tcgBanIDMaxCategory, ProductID: tcgBanIDMaxProduct, SubType: "Unlimited Edition Rainbow Foil"})
	if lo <= identityCeiling {
		t.Errorf("lowest derived id %d is inside the identity range", lo)
	}
	if hi >= 1<<53 {
		t.Errorf("highest derived id %d is past 2^53", hi)
	}
}

// Two variants never share an id, since the id is the unique key.
func TestTCGBanIDDistinct(t *testing.T) {
	seen := map[int64]TCGVariant{}
	for _, cat := range []int{1, 2, 71, tcgBanIDMaxCategory} {
		for _, prod := range []int{1, 2, 492703, tcgBanIDMaxProduct} {
			for subType := range tcgSubTypeCodes {
				v := TCGVariant{CategoryID: cat, ProductID: prod, SubType: subType}
				id, ok := TCGBanID(v)
				if !ok {
					t.Fatalf("TCGBanID refused %+v", v)
				}
				if prev, dup := seen[id]; dup {
					t.Fatalf("%+v and %+v share id %d", prev, v, id)
				}
				seen[id] = v
			}
		}
	}
}

// Anything the layout cannot hold falls back to the sequence, rather than
// wrapping into another variant's id.
func TestTCGBanIDRefuses(t *testing.T) {
	for _, v := range []TCGVariant{
		{CategoryID: 71, ProductID: 1, SubType: "Etched Galaxy Foil"},
		{CategoryID: 0, ProductID: 1, SubType: "Normal"},
		{CategoryID: tcgBanIDMaxCategory + 1, ProductID: 1, SubType: "Normal"},
		{CategoryID: 71, ProductID: 0, SubType: "Normal"},
		{CategoryID: 71, ProductID: tcgBanIDMaxProduct + 1, SubType: "Normal"},
	} {
		if id, ok := TCGBanID(v); ok {
			t.Errorf("TCGBanID(%+v) = %d, want a refusal", v, id)
		}
	}
}

// The codes are baked into every id filed with them, so a code that changed
// or a name that left would re-key a printing.
func TestTCGSubTypeCodesStayPut(t *testing.T) {
	codes := map[int64]string{}
	for name, code := range tcgSubTypeCodes {
		if code >= 1<<tcgBanIDProductShift {
			t.Errorf("%q has code %d, past the sub-type field", name, code)
		}
		if prev, dup := codes[code]; dup {
			t.Errorf("%q and %q share code %d", prev, name, code)
		}
		codes[code] = name
	}
	if tcgSubTypeCodes["Normal"] != 1 || tcgSubTypeCodes["Cold Foil"] != 4 ||
		tcgSubTypeCodes["Unlimited Edition Rainbow Foil"] != 16 {
		t.Error("a sub-type code was renumbered")
	}
}
