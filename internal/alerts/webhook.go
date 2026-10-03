package alerts

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ErrBadSignature means the request's svix-signature did not match.
var ErrBadSignature = errors.New("alerts: bad webhook signature")

// ErrStaleTimestamp means the request's svix-timestamp is outside tolerance.
var ErrStaleTimestamp = errors.New("alerts: stale webhook timestamp")

// svixTolerance is how far a svix-timestamp may drift from now, either way.
const svixTolerance = 5 * time.Minute

// maxWebhookBody caps the mail-events request body Svix can send us.
const maxWebhookBody = 64 * 1024

// errEmptyWebhookSecret means a secret decoded to nothing; an HMAC with a
// zero-length key is a fixed, publicly computable value, so it must never
// be treated as configured.
var errEmptyWebhookSecret = errors.New("alerts: empty webhook secret")

// DecodeSvixSecret strips Resend's whsec_ prefix and base64-decodes the
// rest; an empty secret, before or after decoding, is an error rather than
// a zero-length key.
func DecodeSvixSecret(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "whsec_")
	if s == "" {
		return nil, errEmptyWebhookSecret
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(decoded) == 0 {
		return nil, errEmptyWebhookSecret
	}
	return decoded, nil
}

// VerifySvix checks a Svix-signed webhook request: svix-timestamp must be
// within tolerance of now, and at least one entry of svix-signature must
// match id + "." + timestamp + "." + body signed with secret. A timestamp
// that does not parse is a bad signature, not a stale one. An empty secret
// never verifies: HMAC-SHA256 with a zero-length key is a fixed value
// anyone can compute without ever seeing the real secret.
func VerifySvix(secret []byte, headers http.Header, body []byte, now time.Time) error {
	if len(secret) == 0 {
		return ErrBadSignature
	}
	id := headers.Get("svix-id")
	ts := headers.Get("svix-timestamp")
	sigHeader := headers.Get("svix-signature")
	if id == "" || ts == "" || sigHeader == "" {
		return ErrBadSignature
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return ErrBadSignature
	}
	when := time.Unix(sec, 0)
	if when.Before(now.Add(-svixTolerance)) || when.After(now.Add(svixTolerance)) {
		return ErrStaleTimestamp
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(id + "." + ts + "."))
	mac.Write(body)
	want := mac.Sum(nil)
	for _, part := range strings.Fields(sigHeader) {
		v, sig, found := strings.Cut(part, ",")
		if !found || v != "v1" {
			continue
		}
		got, err := base64.StdEncoding.DecodeString(sig)
		if err != nil {
			continue
		}
		if hmac.Equal(got, want) {
			return nil
		}
	}
	return ErrBadSignature
}

// MailEvent is a Resend webhook event, parsed down to what the handler needs.
type MailEvent struct {
	Type string
	To   []string
}

// resendEvent is the wire shape of a Resend webhook body.
type resendEvent struct {
	Type string `json:"type"`
	Data struct {
		To flexibleStrings `json:"to"`
	} `json:"data"`
}

// flexibleStrings decodes a JSON value that is either a single string or an
// array of strings, in case data.to is ever sent as one address rather than
// a one-element array.
type flexibleStrings []string

func (f *flexibleStrings) UnmarshalJSON(data []byte) error {
	var one string
	err := json.Unmarshal(data, &one)
	if err == nil {
		*f = flexibleStrings{one}
		return nil
	}
	var many []string
	err = json.Unmarshal(data, &many)
	if err != nil {
		return err
	}
	*f = flexibleStrings(many)
	return nil
}

// ParseMailEvent decodes a Resend webhook body into a MailEvent.
func ParseMailEvent(body []byte) (MailEvent, error) {
	var e resendEvent
	err := json.Unmarshal(body, &e)
	if err != nil {
		return MailEvent{}, err
	}
	return MailEvent{Type: e.Type, To: []string(e.Data.To)}, nil
}

// mailEventReason is what one bounce-like event type writes: the channel's
// disabled_reason and the parked alert's last_error.
type mailEventReason struct {
	channel string
	alert   string
}

// mailEventReasons is every event type the webhook acts on; any other type
// is answered 200 and left alone.
var mailEventReasons = map[string]mailEventReason{
	"email.bounced":    {channel: ReasonBounced, alert: ParkBounced},
	"email.complained": {channel: ReasonComplained, alert: ParkComplained},
}

// WebhookStore is what the mail-events webhook needs from the store.
type WebhookStore interface {
	ChannelByAddress(ctx context.Context, kind ChannelKind, address string) ([]Channel, error)
	DisableChannel(ctx context.Context, userHash string, kind ChannelKind, source ChannelSource, reason string, at time.Time) error
	ParkEmailAlerts(ctx context.Context, userHash, reason string) (int64, error)
	ChannelFor(ctx context.Context, userHash string, kind ChannelKind) (Channel, bool, error)
}

// Webhook serves Resend's mail-events webhook: a bounce or complaint
// disables every channel row at the recipient's address and parks the
// email alerts of a user left with no working address.
type Webhook struct {
	Secret []byte
	Store  WebhookStore
	Now    func() time.Time
	Log    func(string, ...any)
}

func (w *Webhook) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

func (w *Webhook) log(format string, args ...any) {
	if w.Log != nil {
		w.Log(format, args...)
	}
}

// ServeHTTP verifies, then handles a bounce or complaint per recipient.
// Unknown types and addresses answer 200; a store error answers 500.
func (w *Webhook) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		rw.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if len(w.Secret) == 0 {
		w.log("alerts: webhook secret not configured")
		rw.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(rw, r.Body, maxWebhookBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		// Oversized or truncated body; too large to be a legitimate event.
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	err = VerifySvix(w.Secret, r.Header, body, w.now())
	if err != nil {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}
	event, err := ParseMailEvent(body)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	reason, ok := mailEventReasons[event.Type]
	if !ok {
		rw.WriteHeader(http.StatusOK)
		return
	}
	ctx := r.Context()
	at := w.now()
	for _, addr := range event.To {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		err := w.handleAddress(ctx, addr, reason, at)
		if err != nil {
			w.log("alerts: webhook %s for %s: %v", event.Type, addr, err)
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	rw.WriteHeader(http.StatusOK)
}

// handleAddress disables every channel row at addr, then parks the email
// alerts of each affected user who has no working address left.
func (w *Webhook) handleAddress(ctx context.Context, addr string, reason mailEventReason, at time.Time) error {
	channels, err := w.Store.ChannelByAddress(ctx, ChannelEmail, addr)
	if err != nil {
		return err
	}
	var users []string
	for _, ch := range channels {
		err = w.Store.DisableChannel(ctx, ch.UserHash, ch.Kind, ch.Source, reason.channel, at)
		if err != nil {
			return err
		}
		if !slices.Contains(users, ch.UserHash) {
			users = append(users, ch.UserHash)
		}
	}
	for _, user := range users {
		_, ok, err := w.Store.ChannelFor(ctx, user, ChannelEmail)
		if err != nil {
			return err
		}
		if ok {
			continue
		}
		_, err = w.Store.ParkEmailAlerts(ctx, user, reason.alert)
		if err != nil {
			return err
		}
	}
	return nil
}
