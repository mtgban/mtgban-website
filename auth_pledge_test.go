package main

import (
	"context"
	"io"
	"log"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/internal/access"
	"github.com/mtgban/mtgban-website/internal/pledge"
)

// Pledge reads this deployment's grant list and admin log: a grant decides a
// reader's tier without asking Patreon, however its email is cased, and the
// admin log says so.
func TestPledgeReadsTheDeploymentsGrantsAndLog(t *testing.T) {
	savedAccess := Access
	t.Cleanup(func() { Access = savedAccess })
	files := map[string]string{
		"acl":    `{}`,
		"grants": `[{"email":"Ann@Example.com","name":"Ann","category":"friend","tier":"Vintage"}]`,
	}
	Access = access.New(access.Hooks{
		Open: func(_ context.Context, path string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(files[path])), nil
		},
	})
	err := Access.Load(context.Background(), access.Sources{TablePath: "acl", GrantsPath: "grants"})
	if err != nil {
		t.Fatal(err)
	}

	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	savedLog := LogPages["Admin"]
	t.Cleanup(func() { LogPages["Admin"] = savedLog })
	var logged strings.Builder
	LogPages["Admin"] = log.New(&logged, "", 0)

	user := &pledge.User{UserID: "u1", Email: "ann@example.com"}
	tier, _, granted, verdict, err := Pledge.Resolve(context.Background(), nil, user)
	if err != nil || verdict != pledge.Entitled || !granted || tier != "Vintage" {
		t.Errorf("Resolve = %q granted %v verdict %v error %v, want the grant's Vintage", tier, granted, verdict, err)
	}
	if !strings.Contains(logged.String(), "Granted Ann (Ann@Example.com) Vintage tier for friend") {
		t.Errorf("admin log %q does not name the grant", logged.String())
	}

	user = &pledge.User{UserID: "u2", Email: "bob@example.com"}
	_, _, granted, verdict, err = Pledge.Resolve(context.Background(), nil, user)
	if err != nil || verdict != pledge.NotEntitled || granted {
		t.Errorf("Resolve for a reader with no grant or membership = granted %v verdict %v error %v, want not entitled", granted, verdict, err)
	}
}
