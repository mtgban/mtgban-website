package alerts

import (
	"context"
	"errors"
	"time"

	"github.com/mtgban/mtgban-website/mailer"
)

// errMailNotConfigured is a MailDeliverer missing a field it needs to send,
// so Deliver fails a firing closed instead of panicking the run.
var errMailNotConfigured = errors.New("alerts: mail delivery not configured")

// MailDeliverer sends one mail per digest through Mailer, holding a firing
// back with ErrDailyLimit once Sent reaches Ceiling in the last 24 hours.
type MailDeliverer struct {
	Mailer      mailer.Mailer
	Templates   MailTemplates
	Image       func(cardID string) string
	Unsubscribe func(userHash string) string // signed URL
	Sent        func(ctx context.Context, userHash string, since time.Time) (int, error)
	Ceiling     int // 20
	Now         func() time.Time
}

// Kind implements Deliverer.
func (m *MailDeliverer) Kind() ChannelKind { return ChannelEmail }

// Deliver renders one mail for the whole digest and sends it once, sharing
// the outcome across every firing. A missing field, a Sent error or a
// render error all fail closed, holding every firing back for a retry; the
// daily ceiling does too, with ErrDailyLimit so the evaluator keeps the
// alert active instead of parking it.
func (m *MailDeliverer) Deliver(ctx context.Context, d Digest, ch Channel, label func(string) string) []Delivery {
	if m.Mailer == nil || m.Templates.HTML == nil || m.Templates.Text == nil {
		return mailResults(d, errMailNotConfigured)
	}
	if m.Ceiling > 0 {
		count := 0
		if m.Sent != nil {
			var err error
			count, err = m.Sent(ctx, d.UserHash, m.now().Add(-24*time.Hour))
			if err != nil {
				return mailResults(d, err)
			}
		}
		if count >= m.Ceiling {
			return mailResults(d, ErrDailyLimit)
		}
	}
	image := m.Image
	if image == nil {
		image = func(string) string { return "" }
	}
	headers := map[string]string{}
	if m.Unsubscribe != nil {
		d.UnsubscribeURL = m.Unsubscribe(d.UserHash)
		headers = unsubscribeHeaders(d.UnsubscribeURL)
	}
	subject, text, html, err := RenderMail(m.Templates, d, label, image)
	if err != nil {
		return mailResults(d, err)
	}
	id, err := m.Mailer.Send(ctx, mailer.Message{
		To:      ch.Address,
		Subject: subject,
		Text:    text,
		HTML:    html,
		Headers: headers,
	})
	if err != nil {
		return mailResults(d, err)
	}
	out := make([]Delivery, 0, len(d.Firings))
	for _, f := range d.Firings {
		out = append(out, Delivery{AlertID: f.Alert.ID, MessageID: id})
	}
	return out
}

// now reads the clock, defaulting to time.Now.
func (m *MailDeliverer) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// mailResults is the same error on every firing: nothing was sent.
func mailResults(d Digest, err error) []Delivery {
	out := make([]Delivery, 0, len(d.Firings))
	for _, f := range d.Firings {
		out = append(out, Delivery{AlertID: f.Alert.ID, Err: err})
	}
	return out
}
