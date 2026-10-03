package alerts

import (
	"fmt"
	htmltemplate "html/template"
	"math"
	"net/url"
	"path/filepath"
	"strings"
	texttemplate "text/template"
)

// MailTemplates are the parsed subject-free email bodies RenderMail fills.
type MailTemplates struct {
	HTML *htmltemplate.Template
	Text *texttemplate.Template
}

// LoadMailTemplates parses alert_digest.html and alert_digest.txt from dir;
// unlike the page templates, these are not in the site's template cache.
func LoadMailTemplates(dir string) (MailTemplates, error) {
	html, err := htmltemplate.ParseFiles(filepath.Join(dir, "alert_digest.html"))
	if err != nil {
		return MailTemplates{}, err
	}
	text, err := texttemplate.ParseFiles(filepath.Join(dir, "alert_digest.txt"))
	if err != nil {
		return MailTemplates{}, err
	}
	return MailTemplates{HTML: html, Text: text}, nil
}

// mailRow is one firing's threshold crossing, as a template sees it.
type mailRow struct {
	Card, Set, Number, Finish, Condition, Side string
	Store, Change, Threshold                   string
	Link, Image                                string
}

// mailView is what both templates render.
type mailView struct {
	Headline       string
	Rows           []mailRow
	AlertsURL      string
	Others         []string
	UnsubscribeURL string
}

// RenderMail builds the subject, plain text and HTML for one user's digest.
// label names a store from its shorthand; image gives a card's thumbnail URL.
func RenderMail(tpl MailTemplates, d Digest, label func(string) string, image func(cardID string) string) (subject, text, html string, err error) {
	view := buildMailView(d, label, image)
	subject = mailSubject(d)

	var textBuf, htmlBuf strings.Builder
	if err = tpl.Text.Execute(&textBuf, view); err != nil {
		return "", "", "", err
	}
	if err = tpl.HTML.Execute(&htmlBuf, view); err != nil {
		return "", "", "", err
	}
	return subject, textBuf.String(), htmlBuf.String(), nil
}

// mailSubject is "Price alert: <card>" for a single firing, else a count.
func mailSubject(d Digest) string {
	if len(d.Firings) == 1 {
		return "Price alert: " + d.Firings[0].Alert.Card.Name
	}
	return fmt.Sprintf("%d price alerts fired", len(d.Firings))
}

// buildMailView turns a Digest into the view the templates range over.
func buildMailView(d Digest, label func(string) string, image func(string) string) mailView {
	view := mailView{
		Others:         othersLines(d.Others),
		UnsubscribeURL: d.UnsubscribeURL,
	}
	if len(d.Firings) > 0 {
		view.AlertsURL = d.Firings[0].Origin + "/alerts"
	}
	if len(d.Firings) == 1 {
		view.Headline = mailHeadlineOne(d.Firings[0], label)
	} else {
		view.Headline = fmt.Sprintf("%d of your price alerts fired", len(d.Firings))
	}
	for _, f := range d.Firings {
		img := image(f.Alert.CardID)
		for _, row := range firingRows(f, label) {
			row.Image = img
			view.Rows = append(view.Rows, row)
		}
	}
	return view
}

// mailHeadlineOne names the store, side, card and threshold a single
// firing's best hit reached.
func mailHeadlineOne(f Firing, label func(string) string) string {
	a, dec := f.Alert, f.Decision
	store, t, above := "", a.Above, true
	switch {
	case dec.FireAbove && len(dec.AboveHits) > 0:
		store, t, above = dec.AboveHits[0].Store, a.Above, true
	case dec.FireBelow && len(dec.BelowHits) > 0:
		store, t, above = dec.BelowHits[0].Store, a.Below, false
	}
	return fmt.Sprintf("%s's %s price for %s reached your threshold of %s", label(store), a.Side, a.Card.Name, thresholdLabel(t, a.ReferencePrice, above))
}

// firingRows is one row per side of f that fired, best hit only.
func firingRows(f Firing, label func(string) string) []mailRow {
	a, dec := f.Alert, f.Decision
	kind := "r"
	if a.Side == SideBuylist {
		kind = "b"
	}
	row := func(hits []Quote, t Threshold, above bool) (mailRow, bool) {
		if len(hits) == 0 {
			return mailRow{}, false
		}
		hit := hits[0]
		return mailRow{
			Card: a.Card.Name, Set: a.Card.Set, Number: a.Card.Number, Finish: a.Card.Finish,
			Condition: a.Condition, Side: string(a.Side),
			Store:     label(hit.Store),
			Change:    changeText(a.ReferencePrice, hit.Price),
			Threshold: thresholdLabel(t, a.ReferencePrice, above),
			Link:      f.Origin + "/go/" + kind + "/" + url.PathEscape(hit.Store) + "/" + url.PathEscape(a.CardID),
		}, true
	}
	var rows []mailRow
	if dec.FireAbove {
		if r, ok := row(dec.AboveHits, a.Above, true); ok {
			rows = append(rows, r)
		}
	}
	if dec.FireBelow {
		if r, ok := row(dec.BelowHits, a.Below, false); ok {
			rows = append(rows, r)
		}
	}
	return rows
}

// changeText is "$<reference> to $<hit> (<signed whole percent>%)".
func changeText(reference, hit float64) string {
	pct := 0.0
	if reference != 0 {
		pct = (hit - reference) / reference * 100
	}
	return fmt.Sprintf("%s to %s (%+d%%)", money(reference), money(hit), int(math.Round(pct)))
}

// othersLines renders the user's other alerts as plain, unescaped lines.
func othersLines(others []Alert) []string {
	if len(others) == 0 {
		return nil
	}
	out := make([]string, 0, len(others))
	for _, a := range others {
		out = append(out, fmt.Sprintf("%s %s #%s, %s, %s %s", a.Card.Name, a.Card.Set, a.Card.Number, a.Card.Finish, a.Condition, a.Side))
	}
	return out
}
