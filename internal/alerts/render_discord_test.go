package alerts

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
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
	e := renderDiscord(Firing{Alert: a, Decision: d, Origin: "https://mtgban.com"}, shorthandLabel)
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
	e = renderDiscord(Firing{Alert: retail, Decision: d, Origin: "https://x"}, shorthandLabel)
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
	e := renderDiscord(Firing{Alert: a, Decision: d, Origin: "https://mtgban.com"}, shorthandLabel)
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
	e := renderDiscord(Firing{Alert: a, Decision: d, Origin: "https://mtgban.com"}, shorthandLabel)
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
	e := renderDiscord(Firing{Alert: a, Decision: d, Origin: "https://mtgban.com"}, shorthandLabel)
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
	e := renderDiscord(Firing{Alert: a, Decision: d, Origin: "https://x"}, shorthandLabel)
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
	e := renderDiscord(Firing{Alert: a, Decision: d, Origin: ""}, shorthandLabel)
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

func discordDigest(ids ...int64) Digest {
	var dg Digest
	for _, id := range ids {
		a := activeAlert()
		a.ID = id
		d := Decision{FireAbove: true, AboveHits: []Quote{{Store: "CK", Price: 13}}}
		dg.Firings = append(dg.Firings, Firing{Alert: a.Alert, Decision: d, Origin: a.Origin, Contact: a.Contact})
	}
	return dg
}

func TestDiscordDelivererSendsOneDMPerFiring(t *testing.T) {
	sender := &fakeSender{}
	del := NewDiscordDeliverer(sender, 0)
	if del.Kind() != ChannelDiscord {
		t.Fatalf("kind = %s", del.Kind())
	}
	got := del.Deliver(context.Background(), discordDigest(7, 8), Channel{Kind: ChannelDiscord, Address: "d9"}, shorthandLabel)
	if len(got) != 2 || got[0] != (Delivery{AlertID: 7}) || got[1] != (Delivery{AlertID: 8}) {
		t.Fatalf("deliveries = %+v", got)
	}
	// Sent to the channel's address, not the contact's legacy id.
	if len(sender.sent) != 2 || sender.sent[0] != "d9" || sender.sent[1] != "d9" {
		t.Fatalf("sent = %v", sender.sent)
	}
	e := sender.embeds[0]
	if e.URL != "https://lorcana.mtgban.com/alerts" || !strings.Contains(e.Description, "https://lorcana.mtgban.com/go/b/CK/card-1") {
		t.Fatalf("links: url=%q\n%s", e.URL, e.Description)
	}

	refused := errors.New("dial tcp")
	sender = &fakeSender{err: refused}
	got = NewDiscordDeliverer(sender, 0).Deliver(context.Background(), discordDigest(7, 8), Channel{Address: "d9"}, shorthandLabel)
	if len(got) != 2 || got[0].Err != refused || got[1].Err != refused || len(sender.sent) != 2 {
		t.Fatalf("deliveries = %+v, sent %v", got, sender.sent)
	}
}

func TestDiscordDelivererPacesBetweenSends(t *testing.T) {
	const pace = 200 * time.Millisecond
	sender := &fakeSender{}
	del := NewDiscordDeliverer(sender, pace)
	start := time.Now()
	del.Deliver(context.Background(), discordDigest(7), Channel{Address: "d9"}, shorthandLabel)
	if time.Since(start) >= pace {
		t.Fatalf("first DM waited %s", time.Since(start))
	}
	// The notice after it waits, as every later DM of the run does.
	start = time.Now()
	err := del.(notifier).notify("d9", &discordgo.MessageEmbed{Title: "x"})
	if err != nil || time.Since(start) < pace || len(sender.sent) != 2 {
		t.Fatalf("second DM after %s, err %v, sent %v", time.Since(start), err, sender.sent)
	}
}
