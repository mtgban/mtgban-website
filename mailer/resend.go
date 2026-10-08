package mailer

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"os"
	"strings"
	"time"
)

// Resend sends through Resend's HTTP API and returns the message id it assigns.
type Resend struct {
	Key, From string
	// Endpoint is Resend's emails URL; tests point it at a local server.
	Endpoint string
	Client   *http.Client
	// retryWait is the pause before the one retry on 429 or 5xx.
	retryWait time.Duration
}

const resendEndpoint = "https://api.resend.com/emails"

type resendRequest struct {
	From    string            `json:"from"`
	To      []string          `json:"to"`
	Subject string            `json:"subject"`
	Text    string            `json:"text,omitempty"`
	HTML    string            `json:"html,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// Send implements Mailer. 429 and 5xx are retried once; see post for what is permanent.
func (r *Resend) Send(ctx context.Context, m Message) (string, error) {
	if _, err := mail.ParseAddress(m.To); err != nil {
		return "", &SendError{Status: 422, Permanent: true, Msg: "to: " + err.Error()}
	}
	body, err := json.Marshal(resendRequest{From: r.From, To: []string{m.To}, Subject: m.Subject, Text: m.Text, HTML: m.HTML, Headers: m.Headers})
	if err != nil {
		return "", fmt.Errorf("mailer: encode: %w", err)
	}
	wait := r.retryWait
	if wait == 0 {
		wait = time.Second
	}
	// One key for both attempts: Resend sends a retried request once, where
	// the first was accepted and only its answer was lost to a 5xx.
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	idempotencyKey := hex.EncodeToString(key)
	for attempt := 0; ; attempt++ {
		id, err := r.post(ctx, body, idempotencyKey)
		var se *SendError
		retry := errors.As(err, &se) && (se.Status == 429 || se.Status >= 500) && attempt == 0
		if err == nil || !retry {
			return id, err
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(wait):
		}
	}
}

func (r *Resend) post(ctx context.Context, body []byte, idempotencyKey string) (string, error) {
	endpoint := r.Endpoint
	if endpoint == "" {
		endpoint = resendEndpoint
	}
	client := r.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+r.Key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", idempotencyKey)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("mailer: resend: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode/100 == 2 {
		var out struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(raw, &out)
		return out.ID, nil
	}
	var e struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(raw, &e)
	if e.Message == "" {
		e.Message = http.StatusText(resp.StatusCode)
	}
	return "", &SendError{Status: resp.StatusCode, Permanent: permanentStatus(resp.StatusCode, e.Message), Msg: e.Message}
}

// permanentStatus is true for the refusals about the message itself: a 400,
// or a 422 naming the recipient. The rest (auth, domain, from, a wrong
// endpoint, rate limits) are the site's own to fix, and stay transient.
func permanentStatus(status int, msg string) bool {
	switch status {
	case 400:
		return true
	case 422:
		return namesRecipient(msg)
	}
	return false
}

// namesRecipient reports whether a validation message is about the to field.
func namesRecipient(msg string) bool {
	m := strings.ToLower(msg)
	return strings.Contains(m, "`to`") || strings.Contains(m, "\"to\"") || strings.HasPrefix(m, "to:")
}

// ResendFromEnv builds the Resend mailer from RESEND_API_KEY; no key gives nil, nil, use Log.
func ResendFromEnv(from string) (*Resend, error) {
	key := os.Getenv("RESEND_API_KEY")
	if key == "" {
		return nil, nil
	}
	if _, err := mail.ParseAddress(from); err != nil {
		return nil, fmt.Errorf("mail.from: %w", err)
	}
	return &Resend{Key: key, From: from, Endpoint: resendEndpoint}, nil
}
