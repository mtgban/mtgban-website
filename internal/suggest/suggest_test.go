package suggest

import (
	"reflect"
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
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: relaxedSearches = %#v, want %#v", tc.name, got, tc.want)
		}
	}
}
