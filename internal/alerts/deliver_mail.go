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

// MailDeliverer sends one mail per digest through Mailer, and park notices
// besides. Each mail is reserved in the user's ledger before it is sent,
// and Reserve refuses once the user had Ceiling mails in the last 24 hours,
// holding the mail back with ErrDailyLimit; Release undoes a reservation
// whose send the provider refused. A nil Reserve sends without a ceiling.
type MailDeliverer struct {
	Mailer      mailer.Mailer
	Templates   MailTemplates
	Image       func(cardID string) string
	Unsubscribe func(userHash string) string // signed URL
	Reserve     func(ctx context.Context, userHash string, at time.Time, ceiling int) (int64, bool, error)
	Release     func(ctx context.Context, id int64) error
	Ceiling     int // 20
	Now         func() time.Time
}

// Kind implements Deliverer.
func (m *MailDeliverer) Kind() ChannelKind { return ChannelEmail }

// Deliver renders one mail for the whole digest and sends it once, sharing
// the outcome across every firing. A missing field, a Reserve error or a
// render error all fail closed, holding every firing back for a retry; the
// daily ceiling does too, with ErrDailyLimit so the evaluator keeps the
// alert active instead of parking it.
func (m *MailDeliverer) Deliver(ctx context.Context, d Digest, ch Channel, label func(string) string) []Delivery {
	if m.Mailer == nil || m.Templates.HTML == nil || m.Templates.Text == nil {
		return mailResults(d, errMailNotConfigured)
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
	id, err := m.sendCounted(ctx, d.UserHash, mailer.Message{
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

// sendCounted sends msg under the daily ceiling: reserved first, so two
// sends at the last slot cannot both pass, and released only when the
// provider refused it; a send that may have gone out stays counted.
func (m *MailDeliverer) sendCounted(ctx context.Context, userHash string, msg mailer.Message) (string, error) {
	var reserved int64
	if m.Reserve != nil {
		id, ok, err := m.Reserve(ctx, userHash, m.now(), m.Ceiling)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", ErrDailyLimit
		}
		reserved = id
	}
	id, err := m.Mailer.Send(ctx, msg)
	if mailer.Refused(err) && m.Reserve != nil && m.Release != nil {
		// A mail that did not go out does not count, even once ctx is gone.
		releaseErr := m.Release(context.WithoutCancel(ctx), reserved)
		if releaseErr != nil {
			err = errors.Join(err, releaseErr)
		}
	}
	return id, err
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
