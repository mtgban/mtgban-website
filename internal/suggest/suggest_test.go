package suggest

import (
	"slices"
	"testing"
)

func TestRelaxedSearches(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		clean   string
		filters []string
		want    []AltSearch
	}{
		{
			name:  "no filters yields nothing",
			raw:   "lightning bolt",
			clean: "lightning bolt",
		},
		{
			name:    "single filter only offers the bare name",
			raw:     "lightning bolt s:lea",
			clean:   "lightning bolt",
			filters: []string{"s:lea"},
			want:    []AltSearch{{"lightning bolt", "lightning bolt"}},
		},
		{
			name:    "two filters offer bare name plus per-filter removal",
			raw:     "lightning bolt s:lea f:foil",
			clean:   "lightning bolt",
			filters: []string{"s:lea", "f:foil"},
			want: []AltSearch{
				{"lightning bolt", "lightning bolt"},
				{"without s:lea", "lightning bolt f:foil"},
				{"without f:foil", "lightning bolt s:lea"},
			},
		},
		{
			name:    "empty card name still relaxes individual filters",
			raw:     "s:lea r:mythic",
			clean:   "",
			filters: []string{"s:lea", "r:mythic"},
			want: []AltSearch{
				{"without s:lea", "r:mythic"},
				{"without r:mythic", "s:lea"},
			},
		},
	}
	for _, tc := range cases {
		got := relaxedSearches(tc.raw, tc.clean, tc.filters)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: relaxedSearches = %#v, want %#v", tc.name, got, tc.want)
		}
	}
}

// A comma inside a quoted value is part of the value, and only one outside
// the quotes separates two of them.
func TestSplitList(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want []string
	}{
		{`a,b`, []string{`a`, `b`}},
		{`"A B"`, []string{`"A B"`}},
		{`"A, B"`, []string{`"A, B"`}},
		{`"A, B","C"`, []string{`"A, B"`, `"C"`}},
		{`"A","B, C",d`, []string{`"A"`, `"B, C"`, `d`}},
		{`"A, B`, []string{`"A, B`}},
		{``, []string{``}},
	} {
		got := SplitList(tt.in)
		if !slices.Equal(got, tt.want) {
			t.Errorf("SplitList(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// A field is replaced where it stands as a term of its own, never inside a
// longer one it starts or ends.
func TestReplaceField(t *testing.T) {
	for _, tt := range []struct{ query, field, value, want string }{
		{"s:atw s:at", "s:at", "s:ath", "s:atw s:ath"},
		{"s:atw s:at", "s:atw", "s:atq", "s:atq s:at"},
		{"bolt -s:lea s:lea", "s:lea", "", "bolt -s:lea "},
		{"bolt s:atw&", "s:atw", "s:atq", "bolt s:atq&"},
		{"bolt s:lea", "s:m10", "", "bolt s:lea"},
	} {
		got := replaceField(tt.query, tt.field, tt.value)
		if got != tt.want {
			t.Errorf("replaceField(%q, %q, %q) = %q, want %q", tt.query, tt.field, tt.value, got, tt.want)
		}
	}
	got := rewrites("s:atw s:at", []string{"s:atw", "s:at"}, [][][]string{{{"atq"}}, {{"ath"}}})
	if !slices.Equal(got, []string{"s:atq s:ath"}) {
		t.Errorf("rewrites = %q, want [s:atq s:ath]", got)
	}
}
