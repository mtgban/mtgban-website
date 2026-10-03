package alerts

import (
	"context"
	"fmt"
	"strings"

	"github.com/mtgban/mtgban-website/mailer"
)

// ParkNotice is one parking event as the user is told of it: the alerts
// parked and why, each reason its own paragraph.
type ParkNotice struct {
	Parked []Moved
	Reason string
}

// ParkNotifier tells a user by mail that their alerts were parked; the
// mail deliverer is one, and the site wraps it to point links at the right
// host.
type ParkNotifier interface {
	NotifyPark(ctx context.Context, ch Channel, n ParkNotice) error
}

// noticeMaxLines caps the alerts a notice lists before "and N more".
const noticeMaxLines = 10

// parkView is what both notice templates render.
type parkView struct {
	Reasons        []string
	Lines          []string
	More           int
	AlertsURL      string
	UnsubscribeURL string
}

// buildParkView lists the parked alerts in plain text, without the
// Discord markdown escapes the embed needs.
func buildParkView(n ParkNotice, unsubscribeURL string) parkView {
	view := parkView{UnsubscribeURL: unsubscribeURL}
	for _, r := range strings.Split(n.Reason, "\n\n") {
		if r = strings.TrimSpace(r); r != "" {
			view.Reasons = append(view.Reasons, r)
		}
	}
	shown := n.Parked
	if len(shown) > noticeMaxLines {
		shown = shown[:noticeMaxLines]
	}
	for _, m := range shown {
		view.Lines = append(view.Lines, fmt.Sprintf("%s %s #%s, %s, %s %s", m.Card.Name, m.Card.Set, m.Card.Number, m.Card.Finish, m.Condition, m.Side))
	}
	view.More = len(n.Parked) - len(shown)
	if len(n.Parked) > 0 && n.Parked[0].Origin != "" {
		view.AlertsURL = n.Parked[0].Origin + "/alerts"
	}
	return view
}

// RenderParkMail builds the subject, plain text and HTML of a park notice.
func RenderParkMail(tpl MailTemplates, n ParkNotice, unsubscribeURL string) (subject, text, html string, err error) {
	view := buildParkView(n, unsubscribeURL)
	subject = "Your price alerts are paused"
	var textBuf, htmlBuf strings.Builder
	if err = tpl.ParkedText.Execute(&textBuf, view); err != nil {
		return "", "", "", err
	}
	if err = tpl.ParkedHTML.Execute(&htmlBuf, view); err != nil {
		return "", "", "", err
	}
	return subject, textBuf.String(), htmlBuf.String(), nil
}

// NotifyPark mails one park notice. It is not a digest: the daily ceiling
// does not count it, since a user whose alerts just stopped has to hear so.
func (m *MailDeliverer) NotifyPark(ctx context.Context, ch Channel, n ParkNotice) error {
	if m.Mailer == nil || m.Templates.ParkedHTML == nil || m.Templates.ParkedText == nil {
		return errMailNotConfigured
	}
	unsubscribeURL := ""
	if m.Unsubscribe != nil {
		unsubscribeURL = m.Unsubscribe(ch.UserHash)
	}
	subject, text, html, err := RenderParkMail(m.Templates, n, unsubscribeURL)
	if err != nil {
		return err
	}
	_, err = m.Mailer.Send(ctx, mailer.Message{
		To:      ch.Address,
		Subject: subject,
		Text:    text,
		HTML:    html,
		Headers: unsubscribeHeaders(unsubscribeURL),
	})
	return err
}

// unsubscribeHeaders is the one-click unsubscribe pair for a link, and
// nothing for no link.
func unsubscribeHeaders(unsubscribeURL string) map[string]string {
	headers := map[string]string{}
	if unsubscribeURL != "" {
		headers["List-Unsubscribe"] = "<" + unsubscribeURL + ">"
		headers["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"
	}
	return headers
}
