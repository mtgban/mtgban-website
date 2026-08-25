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
