package main

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mtgban/mtgban-website/userstate"
)

// maxPatreonWebhookBody caps what the webhook reads before it has checked the
// signature. Patreon's member deliveries run to about 5 KB.
const maxPatreonWebhookBody = 64 << 10

// patreonSignature is the hex HMAC-MD5 of body under secret. MD5 is what
// Patreon computes for its webhook deliveries (SHA-1 and SHA-256 do not match
// what it sends), which is the only reason it is here and the one place the
// site uses it.
func patreonSignature(secret string, body []byte) string {
	mac := hmac.New(md5.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// patreonSignatureMatches says whether header is the signature of body under
// secret, comparing in constant time.
func patreonSignatureMatches(secret string, body []byte, header string) bool {
	return hmac.Equal([]byte(patreonSignature(secret, body)), []byte(strings.ToLower(header)))
}

// PatreonWebhook serves Patreon's member webhook, which posts when a pledge is
// created, changed or deleted. A delivery whose signature checks out pokes its
// member's email (auth_poke.go), here and on the peers, and nothing else: the
// reader's next request renews their signature from what Patreon says then. The
// body's own verdict is never read, since the portal's test deliveries say a
// deleted pledge is still active. It answers 404 while the deployment has no
// webhook secret to check a signature with.
func PatreonWebhook(w http.ResponseWriter, r *http.Request) {
	secret := Infrastructure().PatreonWebhookSecret
	if secret == "" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	// The signature covers the raw body, so nothing is parsed before it is read
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxPatreonWebhookBody))
	if err != nil {
		status := http.StatusBadRequest
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			status = http.StatusRequestEntityTooLarge
		}
		LogPages["Admin"].Println("webhook: body not read:", err)
		http.Error(w, http.StatusText(status), status)
		return
	}
	if !patreonSignatureMatches(secret, body, r.Header.Get("X-Patreon-Signature")) {
		LogPages["Admin"].Println("webhook: signature missing or wrong")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// A body we cannot read an email from is answered 200, or Patreon retries it
	// for good; the age window renews the reader in time anyway
	event := r.Header.Get("X-Patreon-Event")
	var delivery struct {
		Data struct {
			Attributes struct {
				Email string `json:"email"`
			} `json:"attributes"`
		} `json:"data"`
	}
	err = json.Unmarshal(body, &delivery)
	email := strings.ToLower(strings.TrimSpace(delivery.Data.Attributes.Email))
	if err != nil || email == "" {
		LogPages["Admin"].Printf("webhook: event=%q carries no email", event)
		w.WriteHeader(http.StatusOK)
		return
	}

	hash := userstate.HashEmail(email)
	Pokes.poke(hash)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 2*time.Second)
	defer cancel()
	notifyPoke(ctx, hash)
	LogPages["Admin"].Printf("webhook: event=%q email=%q", event, email)
	w.WriteHeader(http.StatusOK)
}
