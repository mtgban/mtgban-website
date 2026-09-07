package main

import (
	"strings"
	"testing"
)

// CardConduit and Deckbox both name a card by an identifier only Magic cards
// carry, so the two exports are only worth offering where the site serves
// them. The exports that address a card by anything else stay.
func TestMagicOnlyExportsFollowTheGame(t *testing.T) {
	// The page names Deckbox in its help text too, as a file format it reads,
	// so the buttons are counted by the call each one makes rather than by
	// the destination's name.
	for _, page := range []struct {
		kind    string
		entries []UploadEntry
		submit  string
	}{
		{"form", nil, "submitForm"},
		{"results", []UploadEntry{{CardID: "", Quantity: 1, HasQuantity: true}}, "submitExport"},
	} {
		for _, magicOnly := range []bool{true, false} {
			out := renderUpload(t, PageVars{
				CanBuylist:       true,
				MagicOnlyExports: magicOnly,
				UploadEntries:    page.entries,
			})

			want := 0
			if magicOnly {
				want = 1
			}
			for _, field := range []string{"estimate", "deckbox"} {
				button := page.submit + "('" + field + "'"
				count := strings.Count(out, button)
				if count != want {
					t.Errorf("%s page, MagicOnlyExports=%v: %s appears %d times, want %d",
						page.kind, magicOnly, button, count, want)
				}
			}

			for _, field := range []string{"download", "tcgplayer_csv"} {
				button := page.submit + "('" + field + "'"
				if !strings.Contains(out, button) {
					t.Errorf("%s page, MagicOnlyExports=%v: %s went missing too",
						page.kind, magicOnly, button)
				}
			}
		}
	}
}
