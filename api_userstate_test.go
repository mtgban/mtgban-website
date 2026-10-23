package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"

	"github.com/mtgban/mtgban-website/internal/access"
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
	prevGame := Config().Game
	t.Cleanup(func() { Config().Game = prevGame })

	Config().Game = DefaultGame
	if got := userStateIdentity("a@b.c"); got != "a@b.c" {
		t.Errorf("default game identity = %q, want bare email", got)
	}

	Config().Game = "lorcana"
	lorcana := userStateIdentity("a@b.c")
	if lorcana == "a@b.c" {
		t.Error("non-default game should namespace the identity")
	}

	Config().Game = "gundam"
	if userStateIdentity("a@b.c") == lorcana {
		t.Error("different games should not share a namespace")
	}
}

// A tier without SearchBackpackMax, or with a value that is not a count,
// keeps the default size, and none goes past the most a sync body carries.
func TestBackpackMaxFromValues(t *testing.T) {
	cases := []struct {
		value string
		want  int
	}{
		{"", defaultBackpackMax},
		{"500", 500},
		{"5000", maxBackpackMax},
		{"0", defaultBackpackMax},
		{"-3", defaultBackpackMax},
		{"lots", defaultBackpackMax},
	}
	for _, tc := range cases {
		v := url.Values{}
		if tc.value != "" {
			v.Set("SearchBackpackMax", tc.value)
		}
		got := backpackMaxFromValues(v)
		if got != tc.want {
			t.Errorf("backpackMaxFromValues(%q) = %d, want %d", tc.value, got, tc.want)
		}
	}
}

// SearchBackpackMax must be signed, and the Search entry must carry it to
// the values.
func TestSearchBackpackMaxIsAnACLProperty(t *testing.T) {
	if !slices.Contains(OptionalFields, "SearchBackpackMax") {
		t.Fatal("OptionalFields lacks SearchBackpackMax")
	}
	table := access.Table{"Admin": {"Search": {"SearchBackpackMax": "500"}}, "Legacy": {"Search": {}}}
	if got := backpackMaxFromValues(aclValuesIn(table, "Admin", nil)); got != 500 {
		t.Errorf("admin backpack = %d, want 500", got)
	}
	if got := backpackMaxFromValues(aclValuesIn(table, "Legacy", nil)); got != defaultBackpackMax {
		t.Errorf("legacy backpack = %d, want %d", got, defaultBackpackMax)
	}
}
