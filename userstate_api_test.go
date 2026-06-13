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
