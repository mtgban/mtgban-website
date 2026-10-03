package main

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"

	"github.com/mtgban/mtgban-website/internal/alerts"
	"github.com/mtgban/mtgban-website/mailer"
)

const (
	alertConfirmSubject = "Confirm your MTGBAN alert email"
	alertConfirmTTL     = 24 * time.Hour
	// alertMailCeiling is the most alert mails one user gets in 24 hours.
	alertMailCeiling = 20

	alertsConfirmedText      = "Your email address is confirmed."
	alertsConfirmFailedText  = "This confirmation link is not valid or has expired."
	alertsUnsubscribeAskText = "Stop all price alert mail to this account?"
	alertsUnsubscribedText   = "You will no longer receive alert mail."
	alertsUnsubFailedText    = "This unsubscribe link is not valid."
	alertsUnavailableText    = "Alerts are not available right now."
	alertsLinkErrorText      = "Something went wrong, try the link again later."
)

// AlertsNoticeVars is the one line the confirm and unsubscribe pages show.
type AlertsNoticeVars struct {
	Heading string
	Text    string
	// Token, when set, shows the Unsubscribe button that posts it back.
	Token string
}

// alertTokenSecret keys the mailed tokens, as BAN_SECRET keys signatures.
func alertTokenSecret() []byte {
	return []byte(os.Getenv("BAN_SECRET"))
}

// verifyAlertToken checks a mailed token of one kind; no secret, no token.
func verifyAlertToken(secret []byte, raw string, kind alerts.TokenKind, now time.Time) (alerts.Token, error) {
	if len(secret) == 0 {
		return alerts.Token{}, alerts.ErrBadToken
	}
	t, err := alerts.VerifyToken(secret, raw, now)
	if err != nil {
		return alerts.Token{}, err
	}
	if t.Kind != kind || t.UserHash == "" {
		return alerts.Token{}, alerts.ErrBadToken
	}
	return t, nil
}

// alertUnsubscribeURL is a user's never-expiring one-click unsubscribe link.
func alertUnsubscribeURL(origin, userHash string) string {
	token := alerts.MintToken(alertTokenSecret(), alerts.Token{Kind: alerts.TokenUnsubscribe, UserHash: userHash})
	return origin + "/alerts/unsubscribe?token=" + url.QueryEscape(token)
}

// alertMailConfigured is whether alert mail can go anywhere: dev logs it,
// production needs RESEND_API_KEY.
func alertMailConfigured() bool {
	return DevMode || os.Getenv("RESEND_API_KEY") != ""
}

// alertMailer is Resend when RESEND_API_KEY is set; without it dev logs and
// production has none (nil). Dev logs unless -alerts-send asks for real mail.
func (s *site) alertMailer() mailer.Mailer {
	if DevMode && !s.alertsSend {
		return &mailer.Log{Out: os.Stdout}
	}
	resend, err := mailer.ResendFromEnv(Config().Mail.From)
	if err != nil {
		log.Println("alerts: mail:", err)
		// A broken From must fail each send, not pass as delivered through the log.
		if !DevMode {
			return failingMailer{err: err}
		}
	}
	if resend != nil {
		return resend
	}
	if DevMode {
		return &mailer.Log{Out: os.Stdout}
	}
	return nil
}

// failingMailer refuses every message with the configuration error.
type failingMailer struct{ err error }

func (f failingMailer) Send(context.Context, mailer.Message) (string, error) {
	return "", f.err
}

// loadAlertMail reads the digest templates and the webhook secret once,
// and checks mail.from; either failing is fatal outside dev.
func (s *site) loadAlertMail() {
	tpl, err := alerts.LoadMailTemplates("templates/mail")
	if err != nil {
		if !DevMode {
			log.Fatalln("alerts: mail templates:", err)
		}
		log.Println("alerts: mail templates:", err)
	}
	_, err = mail.ParseAddress(Config().Mail.From)
	if err != nil {
		if !DevMode {
			log.Fatalln("alerts: mail.from:", err)
		}
		log.Println("alerts: mail.from:", err, "- alert mail is logged, not sent")
	}
	s.mailTemplates = tpl
	s.mailEventsSecret = decodeMailEventsSecret(os.Getenv("RESEND_WEBHOOK_SECRET"))
	if !alertMailConfigured() {
		log.Println("alerts: RESEND_API_KEY not set, alert email is unavailable")
	}
}

// decodeMailEventsSecret is the webhook key, nil (refusing every event) when unusable.
func decodeMailEventsSecret(raw string) []byte {
	if raw == "" {
		log.Println("alerts: RESEND_WEBHOOK_SECRET not set, mail events are refused")
		return nil
	}
	secret, err := alerts.DecodeSvixSecret(raw)
	if err != nil {
		log.Println("alerts: RESEND_WEBHOOK_SECRET unusable, mail events are refused:", err)
		return nil
	}
	return secret
}

// alertConfirmMail is the confirmation mail's text and HTML bodies.
func alertConfirmMail(link string) (text, html string) {
	hours := int(alertConfirmTTL.Hours())
	text = fmt.Sprintf("Open this link within %d hours to confirm this address for your MTGBAN price alerts:\n\n%s\n\n"+
		"If you did not ask for this, ignore this mail.\n", hours, link)
	escaped := template.HTMLEscapeString(link)
	html = fmt.Sprintf(`<p>Open this link within %d hours to confirm this address for your MTGBAN price alerts:</p>`+
		`<p><a href="%s">%s</a></p><p>If you did not ask for this, ignore this mail.</p>`, hours, escaped, escaped)
	return text, html
}

// sendAlertConfirm mails a confirmation link to an address the user entered.
func (s *site) sendAlertConfirm(ctx context.Context, to, link string) error {
	m := s.alertMailer()
	if m == nil {
		return errors.New("alerts: mail not configured")
	}
	text, html := alertConfirmMail(link)
	_, err := m.Send(ctx, mailer.Message{To: to, Subject: alertConfirmSubject, Text: text, HTML: html})
	return err
}

// alertCardImage is a card's thumbnail, else its full image.
func alertCardImage(b *mtgmatcher.Backend, cardID string) string {
	co, err := b.GetUUID(cardID)
	if err != nil {
		return ""
	}
	if co.Images["thumbnail"] != "" {
		return co.Images["thumbnail"]
	}
	return co.Images["full"]
}

// alertMailDeliverer sends digests through the site's mailer and templates.
func (s *site) alertMailDeliverer(b *mtgmatcher.Backend) alerts.Deliverer {
	return originMailDeliverer{mail: alerts.MailDeliverer{
		Mailer:    s.alertMailer(),
		Templates: s.mailTemplates,
		Image:     func(cardID string) string { return alertCardImage(b, cardID) },
		Sent:      s.alerts.Store().MailsSentSince,
		Ceiling:   alertMailCeiling,
	}}
}

// originMailDeliverer points each digest's unsubscribe link at the site
// its alerts were saved on, which MailDeliverer alone cannot see.
type originMailDeliverer struct {
	mail alerts.MailDeliverer
}

func (m originMailDeliverer) Kind() alerts.ChannelKind { return alerts.ChannelEmail }

func (m originMailDeliverer) Deliver(ctx context.Context, d alerts.Digest, ch alerts.Channel, label func(string) string) []alerts.Delivery {
	origin := externalURL(nil)
	if len(d.Firings) > 0 && d.Firings[0].Origin != "" {
		origin = d.Firings[0].Origin
	}
	// A firing saved without an origin links to the fallback, not a relative path.
	d.Firings = slices.Clone(d.Firings)
	for i := range d.Firings {
		if d.Firings[i].Origin == "" {
			d.Firings[i].Origin = origin
		}
	}
	md := m.mail
	md.Unsubscribe = func(userHash string) string { return alertUnsubscribeURL(origin, userHash) }
	return md.Deliver(ctx, d, ch, label)
}

// alertChannelStore is what the mail link pages need from the store.
type alertChannelStore interface {
	Channels(ctx context.Context, userHash string) ([]alerts.Channel, error)
	SetChannelVerified(ctx context.Context, userHash string, kind alerts.ChannelKind, source alerts.ChannelSource, address string, at time.Time) (bool, error)
	DisableChannel(ctx context.Context, userHash string, kind alerts.ChannelKind, source alerts.ChannelSource, reason string, at time.Time) error
	ParkEmailAlerts(ctx context.Context, userHash, reason string) (int64, error)
}

// alertLinkStore is the site's store, or an untyped nil when there is none.
func (s *site) alertLinkStore() alertChannelStore {
	store := s.alerts.Store()
	if store != nil {
		return store
	}
	return nil
}

// confirmAlertEmail verifies the user email row the token was minted for,
// clearing any bounce; a token for another address is a bad token.
func confirmAlertEmail(ctx context.Context, store alertChannelStore, secret []byte, raw string, now time.Time) error {
	t, err := verifyAlertToken(secret, raw, alerts.TokenConfirm, now)
	if err != nil {
		return err
	}
	chans, err := store.Channels(ctx, t.UserHash)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(chans, func(c alerts.Channel) bool {
		return c.Kind == alerts.ChannelEmail && c.Source == alerts.SourceUser
	})
	if t.Address == "" || i < 0 || strings.ToLower(chans[i].Address) != t.Address {
		return alerts.ErrBadToken
	}
	ok, err := store.SetChannelVerified(ctx, t.UserHash, alerts.ChannelEmail, alerts.SourceUser, t.Address, now)
	if err != nil {
		return err
	}
	if !ok {
		return alerts.ErrBadToken
	}
	return nil
}

// unsubscribeAlertEmail disables every email row not already disabled,
// from either source, and parks the user's email alerts.
func unsubscribeAlertEmail(ctx context.Context, store alertChannelStore, secret []byte, raw string, now time.Time) error {
	t, err := verifyAlertToken(secret, raw, alerts.TokenUnsubscribe, now)
	if err != nil {
		return err
	}
	chans, err := store.Channels(ctx, t.UserHash)
	if err != nil {
		return err
	}
	for _, ch := range chans {
		if ch.Kind != alerts.ChannelEmail || ch.DisabledAt != nil {
			continue
		}
		err = store.DisableChannel(ctx, t.UserHash, alerts.ChannelEmail, ch.Source, alerts.ReasonUnsubscribed, now)
		if err != nil {
			return err
		}
	}
	_, err = store.ParkEmailAlerts(ctx, t.UserHash, alerts.ParkUnsubscribed)
	return err
}

// isTokenError is a link that is bad or expired, as opposed to a store failure.
func isTokenError(err error) bool {
	return errors.Is(err, alerts.ErrBadToken) || errors.Is(err, alerts.ErrTokenExpired)
}

// AlertsConfirm verifies an address from its mailed link; no sign-in needed.
func (s *site) AlertsConfirm(w http.ResponseWriter, r *http.Request) {
	s.alertsConfirm(w, r, s.alertLinkStore())
}

func (s *site) alertsConfirm(w http.ResponseWriter, r *http.Request, store alertChannelStore) {
	if r.Method != http.MethodGet {
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	notice := AlertsNoticeVars{Heading: "Confirm alert email"}
	status := http.StatusOK
	if store == nil {
		notice.Text, status = alertsUnavailableText, http.StatusServiceUnavailable
	} else {
		err := confirmAlertEmail(r.Context(), store, alertTokenSecret(), r.FormValue("token"), time.Now())
		switch {
		case err == nil:
			notice.Text = alertsConfirmedText
		case isTokenError(err):
			notice.Text, status = alertsConfirmFailedText, http.StatusBadRequest
		default:
			log.Println("alerts: confirm:", err)
			notice.Text, status = alertsLinkErrorText, http.StatusInternalServerError
		}
	}
	s.renderAlertsNotice(w, r, status, notice)
}

// AlertsUnsubscribe answers a mailed unsubscribe link: GET shows a button,
// POST (the button or List-Unsubscribe-Post) acts; the token is the credential.
func (s *site) AlertsUnsubscribe(w http.ResponseWriter, r *http.Request) {
	s.alertsUnsubscribe(w, r, s.alertLinkStore())
}

func (s *site) alertsUnsubscribe(w http.ResponseWriter, r *http.Request, store alertChannelStore) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	notice := AlertsNoticeVars{Heading: "Unsubscribe from alert email"}
	status := http.StatusOK
	token := r.FormValue("token")
	now := time.Now()
	var err error
	if r.Method == http.MethodGet {
		// Link scanners prefetch GETs, so a GET only checks the token.
		_, err = verifyAlertToken(alertTokenSecret(), token, alerts.TokenUnsubscribe, now)
	} else if store != nil {
		err = unsubscribeAlertEmail(r.Context(), store, alertTokenSecret(), token, now)
	}
	switch {
	case store == nil:
		notice.Text, status = alertsUnavailableText, http.StatusServiceUnavailable
	case isTokenError(err):
		notice.Text, status = alertsUnsubFailedText, http.StatusBadRequest
	case err != nil:
		log.Println("alerts: unsubscribe:", err)
		notice.Text, status = alertsLinkErrorText, http.StatusInternalServerError
	case r.Method == http.MethodGet:
		notice.Text, notice.Token = alertsUnsubscribeAskText, token
	default:
		notice.Text = alertsUnsubscribedText
	}
	s.renderAlertsNotice(w, r, status, notice)
}

// renderAlertsNotice renders the one-line mail link page.
func (s *site) renderAlertsNotice(w http.ResponseWriter, r *http.Request, status int, notice AlertsNoticeVars) {
	pageVars := genPageNav(s, r, "Alerts", getSignatureFromCookies(r))
	// An expired cookie's notice must not replace this page's own.
	pageVars.ErrorMessage = ""
	pageVars.IsMobile = isMobileRequest(r)
	if pageVars.IsMobile {
		pageVars.Nav = filterNavForMobile(pageVars.Nav)
	}
	pageVars.Title = notice.Heading
	pageVars.AlertsNotice = &notice
	render(&statusOnWrite{ResponseWriter: w, status: status}, "alerts_confirm.html", pageVars)
}

// statusOnWrite sends status with the first body byte, so a render that
// fails first can still answer with its own error status.
type statusOnWrite struct {
	http.ResponseWriter
	status int
	sent   bool
}

func (w *statusOnWrite) WriteHeader(code int) {
	if w.sent {
		return
	}
	w.sent = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusOnWrite) Write(b []byte) (int, error) {
	if !w.sent {
		w.WriteHeader(w.status)
	}
	return w.ResponseWriter.Write(b)
}

// AlertsMailEvents serves Resend's bounce and complaint webhook.
func (s *site) AlertsMailEvents(w http.ResponseWriter, r *http.Request) {
	store := s.alerts.Store()
	if store == nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	s.alertsMailEvents(w, r, store)
}

func (s *site) alertsMailEvents(w http.ResponseWriter, r *http.Request, store alerts.WebhookStore) {
	hook := &alerts.Webhook{Secret: s.mailEventsSecret, Store: store, Log: log.Printf}
	hook.ServeHTTP(w, r)
}
