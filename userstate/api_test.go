package userstate

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A dead pool must yield 500 with a generic body, not a leaked pq error.
func TestServeAPIStoreErrorIs500(t *testing.T) {
	c := testClient(t)
	c.Close() // force every query to fail

	req := httptest.NewRequest(http.MethodPatch, "/api/userstate/favorites",
		strings.NewReader(`{"data":[{"id":"x"}],"version":1}`))
	w := httptest.NewRecorder()
	ServeAPI(w, req, c, "apierr@example.com")

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "pq:") || strings.Contains(body, "sql") {
		t.Fatalf("driver error leaked to client: %s", body)
	}
	if !strings.Contains(body, "write failed") {
		t.Fatalf("expected generic write failed body, got %s", body)
	}
}

func TestServeAPIUnknownSectionIs400(t *testing.T) {
	c := testClient(t)

	req := httptest.NewRequest(http.MethodPatch, "/api/userstate/bogus",
		strings.NewReader(`{"data":[],"version":0}`))
	w := httptest.NewRecorder()
	ServeAPI(w, req, c, "apibad@example.com")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestServeAPIBackpackIsAKnownSection(t *testing.T) {
	c := testClient(t)
	freshHash(t, c) // the row for t.Name()+"@example.com" starts and ends empty

	req := httptest.NewRequest(http.MethodPatch, "/api/userstate/backpack",
		strings.NewReader(`{"data":[],"version":0}`))
	w := httptest.NewRecorder()
	ServeAPI(w, req, c, t.Name()+"@example.com")

	if w.Code != http.StatusOK {
		t.Fatalf("backpack PATCH: expected 200, got %d", w.Code)
	}
}
