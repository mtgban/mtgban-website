package alerts

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/bwmarrin/discordgo"
)

func shorthandLabel(s string) string { return s }

func TestAlertEmbedNamesEveryStoreWithALink(t *testing.T) {
	a := Alert{
		CardID: "card-1", Side: SideBuylist, Condition: "NM", ReferencePrice: 10,
		Above: Threshold{Kind: KindAbs, Value: 12},
		Card:  Card{Name: "Lightning Bolt", Set: "LEA", Number: "161", Finish: "nonfoil"},
	}
	d := Decision{FireAbove: true, AboveHits: []Quote{{Store: "CK", Price: 12.5}, {Store: "SCG", Price: 13}}}
	e := dmEmbed(a, d, "https://mtgban.com", shorthandLabel)
	if !strings.Contains(e.Title, "Lightning Bolt") {
		t.Fatalf("title = %q", e.Title)
	}
	body := e.Description
	for _, want := range []string{"above $12.00", "$12.50", "$13.00", "https://mtgban.com/go/b/CK/card-1", "https://mtgban.com/go/b/SCG/card-1", "reference $10.00"} {
		if !strings.Contains(body, want) {
			t.Errorf("description lacks %q:\n%s", want, body)
		}
	}
	retail := a
	retail.Side = SideRetail
	e = dmEmbed(retail, d, "https://x", shorthandLabel)
	if !strings.Contains(e.Description, "/go/r/CK/card-1") {
		t.Fatalf("retail link wrong: %s", e.Description)
	}
}

func TestAlertEmbedPctThresholdBelowAndCreatedPrice(t *testing.T) {
	createdPrice := 9.0
	a := Alert{
		CardID: "card-1", Side: SideBuylist, Condition: "NM", ReferencePrice: 10,
		Above:        Threshold{Kind: KindPct, Value: 20},
		Below:        Threshold{Kind: KindAbs, Value: 8},
		Card:         Card{Name: "Lightning Bolt", Set: "LEA", Number: "161", Finish: "nonfoil"},
		CreatedPrice: &createdPrice,
	}
	d := Decision{
		FireAbove: true, AboveHits: []Quote{{Store: "CK", Price: 12.5}},
		FireBelow: true, BelowHits: []Quote{{Store: "SCG", Price: 7.5}},
	}
	e := dmEmbed(a, d, "https://mtgban.com", shorthandLabel)
	for _, want := range []string{
		"above $12.00 (20% of reference)",
		"below $8.00",
		"$7.50",
		"$9.00 when the alert was set",
	} {
		if !strings.Contains(e.Description, want) {
			t.Errorf("description lacks %q:\n%s", want, e.Description)
		}
	}
}

func TestAlertEmbedLimitsStoreLines(t *testing.T) {
	hits := make([]Quote, 40)
	for i := range hits {
		hits[i] = Quote{Store: fmt.Sprintf("S%02d", i), Price: 10}
	}
	a := Alert{
		CardID: "card-1", Side: SideRetail, Condition: "NM", ReferencePrice: 10,
		Above: Threshold{Kind: KindAbs, Value: 12},
		Card:  Card{Name: "Lightning Bolt", Set: "LEA", Number: "161", Finish: "nonfoil"},
	}
	d := Decision{FireAbove: true, AboveHits: hits}
	e := dmEmbed(a, d, "https://mtgban.com", shorthandLabel)
	got := strings.Count(e.Description, "[Buy](")
	if got != embedMaxLines {
		t.Fatalf("store lines = %d, want %d", got, embedMaxLines)
	}
	if !strings.Contains(e.Description, "and 25 more stores") {
		t.Fatalf("missing overflow line:\n%s", e.Description)
	}
}

func TestAlertEmbedTruncatesLongDescription(t *testing.T) {
	longLabel := strings.Repeat("X", 500)
	hits := make([]Quote, embedMaxLines)
	for i := range hits {
		hits[i] = Quote{Store: longLabel, Price: 10}
	}
	a := Alert{
		CardID: "card-1", Side: SideRetail, Condition: "NM", ReferencePrice: 10,
		Above: Threshold{Kind: KindAbs, Value: 12},
		Card:  Card{Name: "Lightning Bolt", Set: "LEA", Number: "161", Finish: "nonfoil"},
	}
	d := Decision{FireAbove: true, AboveHits: hits}
	e := dmEmbed(a, d, "https://mtgban.com", shorthandLabel)
	n := utf8.RuneCountInString(e.Description)
	if n > embedMaxDescription {
		t.Fatalf("description = %d runes, want <= %d", n, embedMaxDescription)
	}
	if !strings.HasSuffix(e.Description, "[Manage alerts](https://mtgban.com/alerts)") {
		t.Fatalf("description does not end with the manage link:\n%s", e.Description)
	}
}

func TestAlertTruncateCutsAtLineBreak(t *testing.T) {
	s := strings.Repeat("a", 50) + "\n" + strings.Repeat("b", 100)
	got := truncateEmbedDescription(s, "[M](x)", 120)
	if got != strings.Repeat("a", 50)+"\n[M](x)" {
		t.Fatalf("cut mid-line: %q", got)
	}
	// No break within the window: a hard cut.
	s = strings.Repeat("a", 10) + "\n" + strings.Repeat("b", 500)
	got = truncateEmbedDescription(s, "", 300)
	if utf8.RuneCountInString(got) != 300 || !strings.Contains(got, "\n") {
		t.Fatalf("hard cut = %d runes", utf8.RuneCountInString(got))
	}
}

func TestAlertEmbedEscapesMarkdown(t *testing.T) {
	a := Alert{
		CardID: "card-1", Side: SideRetail, Condition: "NM", ReferencePrice: 10,
		Above: Threshold{Kind: KindAbs, Value: 12},
		Card:  Card{Name: "_____", Set: "U*H", Number: "[1]", Finish: "nonfoil"},
	}
	d := Decision{FireAbove: true, AboveHits: []Quote{{Store: "CK", Price: 13}}}
	e := dmEmbed(a, d, "https://x", shorthandLabel)
	if !strings.HasPrefix(e.Description, `\_\_\_\_\_ U\*H #\[1\], `) {
		t.Fatalf("card line not escaped:\n%s", e.Description)
	}
	got := escapeMarkdown("a\\b`c~d|e(f)")
	if got != "a\\\\b\\`c\\~d\\|e\\(f\\)" {
		t.Fatalf("escapeMarkdown = %q", got)
	}
}

func TestAlertEmbedOmitsLinksWithoutOrigin(t *testing.T) {
	a := Alert{
		CardID: "card-1", Side: SideBuylist, Condition: "NM", ReferencePrice: 10,
		Above: Threshold{Kind: KindAbs, Value: 12},
		Card:  Card{Name: "Lightning Bolt", Set: "LEA", Number: "161", Finish: "nonfoil"},
	}
	d := Decision{FireAbove: true, AboveHits: []Quote{{Store: "CK", Price: 12.5}}}
	e := dmEmbed(a, d, "", shorthandLabel)
	if strings.Contains(e.Description, "](") || strings.Contains(e.Description, "Manage alerts") || e.URL != "" {
		t.Fatalf("links left in:\n%s\nurl=%q", e.Description, e.URL)
	}
	if !strings.Contains(e.Description, "CK: $12.50\n") {
		t.Fatalf("store line = \n%s", e.Description)
	}
}

func TestParkedEmbedListsCardsAndLinks(t *testing.T) {
	var parked []Moved
	for i := range 17 {
		parked = append(parked, Moved{
			ID: int64(i), Card: Card{Name: "Card_" + strconv.Itoa(i), Set: "LEA", Number: "1", Finish: "foil"},
			Side: SideRetail, Condition: "NM", Origin: "https://mtgban.com",
		})
	}
	e := parkedEmbed(parked, "Your tier no longer includes price alerts.")
	if e.Title != "Price alerts parked" || e.URL != "https://mtgban.com/alerts" {
		t.Fatalf("title=%q url=%q", e.Title, e.URL)
	}
	if strings.Count(e.Description, " LEA #1, foil, NM retail\n") != embedMaxLines || !strings.Contains(e.Description, "and 2 more\n") {
		t.Fatalf("card lines:\n%s", e.Description)
	}
	if !strings.Contains(e.Description, `Card\_0 LEA #1, foil`) || !strings.HasPrefix(e.Description, "Your tier no longer includes price alerts.\n\n") {
		t.Fatalf("escaping or reason:\n%s", e.Description)
	}
	parked[0].Origin = ""
	e = parkedEmbed(parked, "x")
	if e.URL != "" || strings.Contains(e.Description, "Manage alerts") {
		t.Fatalf("links left in without an origin:\n%s", e.Description)
	}
}

func TestIsDMPermanent(t *testing.T) {
	status := func(code int) *discordgo.RESTError {
		return &discordgo.RESTError{Response: &http.Response{StatusCode: code}}
	}
	coded := func(code, errCode int) *discordgo.RESTError {
		return &discordgo.RESTError{
			Response: &http.Response{StatusCode: code},
			Message:  &discordgo.APIErrorMessage{Code: errCode},
		}
	}
	permanent := map[string]error{
		"50007":                  coded(403, discordgo.ErrCodeCannotSendMessagesToThisUser),
		"50007 without response": &discordgo.RESTError{Message: &discordgo.APIErrorMessage{Code: discordgo.ErrCodeCannotSendMessagesToThisUser}},
		"10013":                  coded(404, discordgo.ErrCodeUnknownUser),
		"wrapped 10013":          fmt.Errorf("send: %w", coded(404, discordgo.ErrCodeUnknownUser)),
	}
	for name, err := range permanent {
		if !isDMPermanent(err) {
			t.Errorf("%s not permanent", name)
		}
	}
	transient := map[string]error{
		"404 without code": status(404),
		"401":              status(401),
		"403 without code": status(403),
		"429":              status(429),
		"500":              status(500),
		"plain":            errors.New("dial tcp"),
		"no response":      &discordgo.RESTError{},
	}
	for name, err := range transient {
		if isDMPermanent(err) {
			t.Errorf("%s treated as permanent", name)
		}
	}
}
