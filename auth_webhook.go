package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/mtgban/mtgban-website/patreon"
	"github.com/mtgban/mtgban-website/userstate"
)

// maxPatreonWebhookBody caps what the webhook reads before it has checked the
// signature. Patreon's member deliveries run to about 5 KB.
const maxPatreonWebhookBody = 64 << 10

// PatreonWebhook serves Patreon's member webhook, which posts when a pledge is
// created, changed or deleted. A delivery whose signature checks out pokes its
// member's email, here and on the peers, and nothing else: the
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
	if !patreon.WebhookSigned(secret, body, r.Header.Get("X-Patreon-Signature")) {
		LogPages["Admin"].Println("webhook: signature missing or wrong")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// A body we cannot read an email from is answered 200, or Patreon retries it
	// for good; the age window renews the reader in time anyway
	event := r.Header.Get("X-Patreon-Event")
	email := patreon.WebhookEmail(body)
	if email == "" {
		LogPages["Admin"].Printf("webhook: event=%q carries no email", event)
		w.WriteHeader(http.StatusOK)
		return
	}

	hash := userstate.HashEmail(email)
	Pokes.Poke(hash, time.Now(), pokeWindow())
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 2*time.Second)
	defer cancel()
	notifyPoke(ctx, hash)
	LogPages["Admin"].Printf("webhook: event=%q email=%q", event, email)
	w.WriteHeader(http.StatusOK)
}
