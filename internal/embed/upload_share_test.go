package embed

import (
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/matcher"
)

func TestUploadSharePreview(t *testing.T) {
	b := matcher.NewBackend()
	for _, c := range []struct {
		uuid, name, set string
		sealed          bool
	}{
		{"a", "Sheoldred, the Apocalypse", "DMU", false},
		{"a_f", "Sheoldred, the Apocalypse", "DMU", false},
		{"b", "Ragavan, Nimble Pilferer", "MH2", false},
		{"c", "The One Ring", "LTR", false},
		{"d", "Orcish Bowmasters", "LTR", false},
		{"e", "Modern Horizons 3 Play Booster Box", "MH3", true},
	} {
		co := &matcher.CardObject{Sealed: c.sealed}
		co.UUID = c.uuid
		co.Name = c.name
		co.SetCode = c.set
		co.Images = map[string]string{"full": "https://img/" + c.uuid}
		b.UUIDs[c.uuid] = co
	}
	expires := time.Date(2026, 11, 18, 23, 0, 0, 0, time.UTC)

	got := UploadShare(b, []string{"unknown", "a", "a_f", "b", "c", "d", "e"}, []string{"9", "4", "1", "", "x", "2", "3"}, true, expires)
	want := SharePreview{
		Title:       "Shared buylist",
		Description: "9 cards and 3 sealed products. Link expires Nov 18.",
		ImageURL:    "https://img/a",
	}
	if got != want {
		t.Errorf("UploadShare =\n %+v\nwant\n %+v", got, want)
	}

	got = UploadShare(b, []string{"c"}, nil, false, expires)
	want = SharePreview{
		Title:       "Shared retail list",
		Description: "1 card. Link expires Nov 18.",
		ImageURL:    "https://img/c",
	}
	if got != want {
		t.Errorf("UploadShare =\n %+v\nwant\n %+v", got, want)
	}

	if got := UploadShare(b, []string{"unknown"}, nil, false, expires); got != (SharePreview{}) {
		t.Errorf("UploadShare with nothing placed = %+v, want empty", got)
	}
}
