package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Anonymous request (no signature) must get 401 regardless of DB state.
func TestUserStateAPIAnonymous(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/userstate/", nil)
	w := httptest.NewRecorder()
	UserStateAPI(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for anonymous, got %d", w.Code)
	}
}

// Each game site keeps its own synced favorites/recents: non-default games
// namespace the sync identity, the default game keeps the bare email so
// pre-scoping rows stay reachable.
func TestUserStateIdentityPerGame(t *testing.T) {
	prevGame := Config.Game
	t.Cleanup(func() { Config.Game = prevGame })

	Config.Game = DefaultGame
	if got := userStateIdentity("a@b.c"); got != "a@b.c" {
		t.Errorf("default game identity = %q, want bare email", got)
	}

	Config.Game = "lorcana"
	lorcana := userStateIdentity("a@b.c")
	if lorcana == "a@b.c" {
		t.Error("non-default game should namespace the identity")
	}

	Config.Game = "gundam"
	if userStateIdentity("a@b.c") == lorcana {
		t.Error("different games should not share a namespace")
	}
}
