package main

import "testing"

func TestCollapseIndex(t *testing.T) {
	tests := []struct {
		name                        string
		entries                     []SearchEntry
		lowShort, marketShort       string
		lowSolo, marketSolo, merged string
		wantOK                      bool
		wantName, wantURL           string
		wantPrice, wantSecondary    float64
	}{
		{
			name:          "both present, low before market",
			entries:       []SearchEntry{{Shorthand: "TCGLow", Price: 1, URL: "tcg-low"}, {Shorthand: "TCGMarket", Price: 2, URL: "tcg-market"}},
			lowShort:      "TCGLow",
			marketShort:   "TCGMarket",
			merged:        "TCG (Low / Market)",
			wantOK:        true,
			wantName:      "TCG (Low / Market)",
			wantURL:       "tcg-low",
			wantPrice:     1,
			wantSecondary: 2,
		},
		{
			name:          "both present, market before low (order independent)",
			entries:       []SearchEntry{{Shorthand: "TCGMarket", Price: 2, URL: "tcg-market"}, {Shorthand: "TCGLow", Price: 1, URL: "tcg-low"}},
			lowShort:      "TCGLow",
			marketShort:   "TCGMarket",
			merged:        "TCG (Low / Market)",
			wantOK:        true,
			wantName:      "TCG (Low / Market)",
			wantURL:       "tcg-low",
			wantPrice:     1,
			wantSecondary: 2,
		},
		{
			name:        "low only keeps its scraper name (empty solo)",
			entries:     []SearchEntry{{Shorthand: "TCGLow", Price: 1, URL: "tcg-low", ScraperName: "TCG Low"}},
			lowShort:    "TCGLow",
			marketShort: "TCGMarket",
			merged:      "TCG (Low / Market)",
			wantOK:      true,
			wantName:    "TCG Low",
			wantURL:     "tcg-low",
			wantPrice:   1,
		},
		{
			name:        "MKM low only renamed to solo label",
			entries:     []SearchEntry{{Shorthand: "MKMLow", Price: 1, URL: "cm-low", ScraperName: "raw"}},
			lowShort:    "MKMLow",
			marketShort: "MKMTrend",
			lowSolo:     "Cardmarket Low",
			marketSolo:  "Cardmarket Trend",
			merged:      "CM (Low / Trend)",
			wantOK:      true,
			wantName:    "Cardmarket Low",
			wantURL:     "cm-low",
			wantPrice:   1,
		},
		{
			name:        "MKM trend only renamed to solo label",
			entries:     []SearchEntry{{Shorthand: "MKMTrend", Price: 2, URL: "cm-trend", ScraperName: "raw"}},
			lowShort:    "MKMLow",
			marketShort: "MKMTrend",
			lowSolo:     "Cardmarket Low",
			marketSolo:  "Cardmarket Trend",
			merged:      "CM (Low / Trend)",
			wantOK:      true,
			wantName:    "Cardmarket Trend",
			wantURL:     "cm-trend",
			wantPrice:   2,
		},
		{
			name:        "duplicate market, no low: first wins and the rest dedupe",
			entries:     []SearchEntry{{Shorthand: "TCGMarket", Price: 2, URL: "m1", ScraperName: "TCG Market"}, {Shorthand: "TCGMarket", Price: 3, URL: "m2", ScraperName: "TCG Market"}},
			lowShort:    "TCGLow",
			marketShort: "TCGMarket",
			merged:      "TCG (Low / Market)",
			wantOK:      true,
			wantName:    "TCG Market",
			wantURL:     "m1",
			wantPrice:   2,
		},
		{
			// The exact shape that caused the cardmarket mislabel: a cardmarket
			// row plus two TCGMarket entries and no TCGLow. Collapsing the TCG
			// pair must yield the tcgplayer row, never the cardmarket one.
			name:        "regression: TCG pair never adopts the cardmarket row",
			entries:     []SearchEntry{{Shorthand: "MKMLow", Price: 328, URL: "cardmarket"}, {Shorthand: "TCGMarket", Price: 866, URL: "tcgplayer", ScraperName: "TCG Market"}, {Shorthand: "TCGMarket", Price: 866, URL: "tcgplayer"}},
			lowShort:    "TCGLow",
			marketShort: "TCGMarket",
			merged:      "TCG (Low / Market)",
			wantOK:      true,
			wantName:    "TCG Market",
			wantURL:     "tcgplayer",
			wantPrice:   866,
		},
		{
			// Same data, collapsing the MKM pair: the cardmarket row keeps its
			// own URL and label.
			name:        "regression: cardmarket row stays cardmarket",
			entries:     []SearchEntry{{Shorthand: "MKMLow", Price: 328, URL: "cardmarket"}, {Shorthand: "TCGMarket", Price: 866, URL: "tcgplayer", ScraperName: "TCG Market"}, {Shorthand: "TCGMarket", Price: 866, URL: "tcgplayer"}},
			lowShort:    "MKMLow",
			marketShort: "MKMTrend",
			lowSolo:     "Cardmarket Low",
			marketSolo:  "Cardmarket Trend",
			merged:      "CM (Low / Trend)",
			wantOK:      true,
			wantName:    "Cardmarket Low",
			wantURL:     "cardmarket",
			wantPrice:   328,
		},
		{
			name:        "neither present",
			entries:     []SearchEntry{{Shorthand: "CK", Price: 5}},
			lowShort:    "TCGLow",
			marketShort: "TCGMarket",
			merged:      "TCG (Low / Market)",
			wantOK:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := collapseIndex(tt.entries, tt.lowShort, tt.marketShort, tt.lowSolo, tt.marketSolo, tt.merged)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if got.ScraperName != tt.wantName {
				t.Errorf("ScraperName = %q, want %q", got.ScraperName, tt.wantName)
			}
			if got.URL != tt.wantURL {
				t.Errorf("URL = %q, want %q", got.URL, tt.wantURL)
			}
			if got.Price != tt.wantPrice {
				t.Errorf("Price = %v, want %v", got.Price, tt.wantPrice)
			}
			if got.Secondary != tt.wantSecondary {
				t.Errorf("Secondary = %v, want %v", got.Secondary, tt.wantSecondary)
			}
		})
	}
}

func TestCollapseSealedEV(t *testing.T) {
	evShorts := []string{"EV"}

	tests := []struct {
		name     string
		entries  []SearchEntry
		wantLen  int
		wantSeen bool
		check    func(t *testing.T, rows []SearchEntry)
	}{
		{
			name: "base then sim folds into one row",
			entries: []SearchEntry{
				{Shorthand: "EV", ScraperName: "EV alpha", Price: 10},
				{Shorthand: "EV", ScraperName: "EV alpha Sim", Price: 11, ExtraValues: map[string]float64{"iqr": 1.5}},
			},
			wantLen:  1,
			wantSeen: true,
			check: func(t *testing.T, rows []SearchEntry) {
				if rows[0].Price != 10 || rows[0].Secondary != 11 {
					t.Errorf("Price/Secondary = %v/%v, want 10/11", rows[0].Price, rows[0].Secondary)
				}
				if rows[0].ExtraValues["iqr"] != 1.5 {
					t.Errorf("ExtraValues[iqr] = %v, want 1.5", rows[0].ExtraValues["iqr"])
				}
			},
		},
		{
			name: "sim then base (order independent within a product)",
			entries: []SearchEntry{
				{Shorthand: "EV", ScraperName: "EV alpha Sim", Price: 11},
				{Shorthand: "EV", ScraperName: "EV alpha", Price: 10},
			},
			wantLen:  1,
			wantSeen: true,
			check: func(t *testing.T, rows []SearchEntry) {
				if rows[0].Price != 10 || rows[0].Secondary != 11 {
					t.Errorf("Price/Secondary = %v/%v, want 10/11", rows[0].Price, rows[0].Secondary)
				}
			},
		},
		{
			name: "distinct products stay separate",
			entries: []SearchEntry{
				{Shorthand: "EV", ScraperName: "EV alpha", Price: 10},
				{Shorthand: "EV", ScraperName: "EV beta", Price: 20},
				{Shorthand: "EV", ScraperName: "EV alpha Sim", Price: 11},
			},
			wantLen:  2,
			wantSeen: true,
			check: func(t *testing.T, rows []SearchEntry) {
				if rows[0].Price != 10 || rows[0].Secondary != 11 {
					t.Errorf("alpha Price/Secondary = %v/%v, want 10/11", rows[0].Price, rows[0].Secondary)
				}
				if rows[1].Price != 20 {
					t.Errorf("beta Price = %v, want 20", rows[1].Price)
				}
			},
		},
		{
			name:     "EV present but name without a product id is skipped",
			entries:  []SearchEntry{{Shorthand: "EV", ScraperName: "EV", Price: 10}},
			wantLen:  0,
			wantSeen: true,
			check:    func(t *testing.T, rows []SearchEntry) {},
		},
		{
			name:     "non-EV shorthands are ignored",
			entries:  []SearchEntry{{Shorthand: "TCGLow", ScraperName: "TCG Low", Price: 5}},
			wantLen:  0,
			wantSeen: false,
			check:    func(t *testing.T, rows []SearchEntry) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows, seen := collapseSealedEV(tt.entries, evShorts)
			if seen != tt.wantSeen {
				t.Errorf("seen = %v, want %v", seen, tt.wantSeen)
			}
			if len(rows) != tt.wantLen {
				t.Fatalf("rows = %d, want %d", len(rows), tt.wantLen)
			}
			tt.check(t, rows)
		})
	}
}

func TestPassthroughIndex(t *testing.T) {
	entries := []SearchEntry{
		{Shorthand: "TCGLow"},
		{Shorthand: "TCGMarket"},
		{Shorthand: "MKMLow"},
		{Shorthand: "MKMTrend"},
		{Shorthand: "EV", ScraperName: "EV alpha"},
		{Shorthand: "CK"},
		{Shorthand: "CT0"},
	}

	consumed := []string{"TCGLow", "TCGMarket", "MKMLow", "MKMTrend", "EV"}
	got := passthroughIndex(entries, consumed)

	want := []string{"CK", "CT0"}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Shorthand != want[i] {
			t.Errorf("entry %d = %q, want %q", i, got[i].Shorthand, want[i])
		}
	}
}
