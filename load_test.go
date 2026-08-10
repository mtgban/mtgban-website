package main

import (
	"testing"
)

func TestLoadSummary(t *testing.T) {
	tests := []struct {
		name   string
		loaded int
		failed []string
		want   string
	}{
		{
			name:   "all loaded",
			loaded: 3,
			want:   "Server loaded 3/3 scrapers",
		},
		{
			name:   "unloaded scrapers still count towards the total",
			loaded: 1,
			failed: []string{"a/retail/A: no such object"},
			want: "Server loaded 1/2 scrapers\n" +
				"not loaded (1): a/retail/A: no such object",
		},
		{
			name:   "listed in a stable order whatever order they finished in",
			loaded: 0,
			failed: []string{"c/retail/C: timeout", "a/retail/A: timeout"},
			want: "Server loaded 0/2 scrapers\n" +
				"not loaded (2): a/retail/A: timeout; c/retail/C: timeout",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := loadSummary(test.loaded, test.failed)
			if got != test.want {
				t.Errorf("got:\n%s\nwant:\n%s", got, test.want)
			}
		})
	}
}
