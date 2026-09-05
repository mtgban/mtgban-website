package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// resolveCardLink follows an internal card link the way a click would, and
// returns the query it lands on.
func resolveCardLink(t *testing.T, link string) string {
	t.Helper()
	if !strings.HasPrefix(link, "/card/") {
		parsed, err := url.Parse(link)
		if err != nil {
			t.Fatalf("parsing %q: %v", link, err)
		}
		return parsed.Query().Get("q")
	}

	rec := httptest.NewRecorder()
	CardRedirect(rec, httptest.NewRequest(http.MethodGet, link, nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("%s answered %d, want a redirect", link, rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing the redirect of %q: %v", link, err)
	}
	return loc.Query().Get("q")
}

// The link on a page has to find the printing it was made for. This is what
// the query form was quietly failing at: a number carrying a language or
// variant suffix - 59ita, 349alt, 1110jpn - went out as cn:, which reads the
// number without it, and the link came back empty.
func TestCardLinkResolvesToItsPrinting(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	uuids := mtgmatcher.GetUUIDs()
	step := len(uuids) / 300
	if step < 1 {
		step = 1
	}

	var checked, missed int
	for i := 0; i < len(uuids); i += step {
		co, err := mtgmatcher.GetUUID(uuids[i])
		if err != nil || co.Sealed {
			continue
		}
		checked++

		card := uuid2card(uuids[i], true, false, false)
		query := resolveCardLink(t, card.SearchURL)
		keys, err := searchAndFilter(parseSearchOptionsNG(query, nil, nil, nil))
		if err != nil {
			t.Errorf("%s #%s: %v", co.SetCode, co.Number, err)
			continue
		}

		var found bool
		for _, key := range keys {
			if key == uuids[i] {
				found = true
				break
			}
		}
		if !found {
			missed++
			if missed < 6 {
				t.Errorf("the link for %s %s #%s asks %q and does not find it (%d results)",
					co.Name, co.SetCode, co.Number, query, len(keys))
			}
		}
	}

	if checked == 0 {
		t.Fatal("no cards were checked")
	}
	if missed != 0 {
		t.Errorf("%d of %d links miss the card they point at", missed, checked)
	}
}

// The shape itself, and the finish that pins which printing of the number.
func TestCardLinkTakesTheScryfallShape(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	ids, err := mtgmatcher.SearchEquals("Another Round")
	if err != nil || len(ids) == 0 {
		t.Skip("this datastore has no Another Round")
	}

	var sawFoil, sawPlain bool
	for _, id := range ids {
		co, err := mtgmatcher.GetUUID(id)
		if err != nil || co.SetCode != "OTJ" {
			continue
		}
		want := "/card/OTJ/" + co.Number + "/nonfoil"
		if co.Foil {
			want = "/card/OTJ/" + co.Number + "/foil"
			sawFoil = true
		} else {
			sawPlain = true
		}
		if got := uuid2card(id, true, false, false).SearchURL; got != want {
			t.Errorf("linked as %q, want %q", got, want)
		}
	}
	if !sawFoil || !sawPlain {
		t.Skip("both finishes are needed to tell the two links apart")
	}
}

// A shape that cannot name the card keeps the query it always had: a sealed
// product goes to the sealed page, and a number made only of zeros is one the
// number filter reads as nothing - 22 cards, the World Championship ad cards
// among them, which neither form reaches today.
func TestCardLinkKeepsTheQueryWhereThePathCannotName(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	var sealed, zeroed string
	for _, uuid := range mtgmatcher.GetUUIDs() {
		co, err := mtgmatcher.GetUUID(uuid)
		if err != nil {
			continue
		}
		if co.Sealed {
			if sealed == "" {
				sealed = uuid
			}
			continue
		}
		if zeroed == "" && co.Number != "" && strings.Trim(co.Number, "0") == "" {
			zeroed = uuid
		}
		if sealed != "" && zeroed != "" {
			break
		}
	}

	if sealed != "" {
		link := uuid2card(sealed, true, false, false).SearchURL
		if !strings.HasPrefix(link, "/sealed?q=") {
			t.Errorf("a sealed product links to %q, want the sealed page", link)
		}
	}
	if zeroed != "" {
		co, _ := mtgmatcher.GetUUID(zeroed)
		link := uuid2card(zeroed, true, false, false).SearchURL
		if strings.HasPrefix(link, "/card/") {
			t.Errorf("%s #%s links to %q, which the number filter reads as no number at all",
				co.SetCode, co.Number, link)
		}
		// The link it keeps is the one it had, which does not find it either:
		// cn: reads a number of zeros as no number just as cns: does, so these
		// have never been reachable. Kept rather than swapped so this change
		// leaves them exactly as it found them.
		keys, err := searchAndFilter(parseSearchOptionsNG(resolveCardLink(t, link), nil, nil, nil))
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range keys {
			if key == zeroed {
				t.Logf("%s #%s is reachable after all - the guard in cardPath can go",
					co.SetCode, co.Number)
			}
		}
	}
}

// The finish in the path is the game's own name for it. Magic sets Finish to
// the same word a case on the two flags would produce, so the two agree there
// and the link is unchanged; a game that prices print runs rather than
// foilings has no flag that says which run, and only Finish does.
func TestCardPathNamesTheFinishTheGameUses(t *testing.T) {
	for _, tt := range []struct {
		name string
		co   mtgmatcher.CardObject
		want string
	}{
		{
			name: "a print run no flag can name",
			co: mtgmatcher.CardObject{
				Card:    mtgmatcher.Card{SetCode: "LOB", Number: "1", Finish: "1stedition"},
				Edition: "Legend of Blue Eyes",
			},
			want: "/card/LOB/1/1stedition",
		},
		{
			name: "a foil the game names its own way",
			co: mtgmatcher.CardObject{
				Card: mtgmatcher.Card{SetCode: "TFC", Number: "2", Finish: "coldfoil"},
				Foil: true,
			},
			want: "/card/TFC/2/coldfoil",
		},
		{
			name: "magic, where the two agree",
			co: mtgmatcher.CardObject{
				Card: mtgmatcher.Card{SetCode: "OTJ", Number: "3", Finish: "foil"},
				Foil: true,
			},
			want: "/card/OTJ/3/foil",
		},
		{
			name: "a datastore that names no finish falls back to the flags",
			co: mtgmatcher.CardObject{
				Card:   mtgmatcher.Card{SetCode: "XYZ", Number: "4"},
				Etched: true,
			},
			want: "/card/XYZ/4/etched",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := cardPath(&tt.co); got != tt.want {
				t.Errorf("linked as %q, want %q", got, tt.want)
			}
		})
	}
}

// A number that carries a separator cannot be a path segment, and escaping it
// does not help: net/http decodes %2F before a handler sees the path, so Flesh
// and Blood's WTR040//WTR001 arrives as three segments and reads as WTR040.
// Those keep the query link, which does name them.
func TestCardPathDeclinesANumberItCannotSpell(t *testing.T) {
	for _, tt := range []struct {
		name string
		co   mtgmatcher.CardObject
		want string
	}{
		{
			name: "a number split across two cards",
			co: mtgmatcher.CardObject{
				Card: mtgmatcher.Card{SetCode: "WTR", Number: "WTR040//WTR001", Finish: "1steditionnormal"},
			},
			want: "",
		},
		{
			name: "a number of zeros, which the filter reads as none",
			co: mtgmatcher.CardObject{
				Card: mtgmatcher.Card{SetCode: "WC99", Number: "0", Finish: "nonfoil"},
			},
			want: "",
		},
		{
			name: "a sealed product, which belongs to another page",
			co: mtgmatcher.CardObject{
				Card:   mtgmatcher.Card{SetCode: "OTJ", Number: "1"},
				Sealed: true,
			},
			want: "",
		},
		{
			name: "and an ordinary one",
			co: mtgmatcher.CardObject{
				Card: mtgmatcher.Card{SetCode: "OTJ", Number: "1", Finish: "nonfoil"},
			},
			want: "/card/OTJ/1/nonfoil",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := cardPath(&tt.co); got != tt.want {
				t.Errorf("linked as %q, want %q", got, tt.want)
			}
		})
	}
}
