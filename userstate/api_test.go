package userstate

import (
	"context"
	"encoding/json"
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
	ServeAPI(w, req, c, "apierr@example.com", "")

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
	ServeAPI(w, req, c, "apibad@example.com", "")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// The share section: one live link per owner, made on POST, shown on GET,
// ended on DELETE.
func TestServeAPIShareLifecycle(t *testing.T) {
	c := testClient(t)
	email := "share-api@example.com"
	h := HashEmail(email)
	if _, err := c.db.Exec(`DELETE FROM favorites_shares WHERE email_hash = $1`, h); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = c.db.Exec(`DELETE FROM favorites_shares WHERE email_hash = $1`, h) })

	call := func(method string) (int, map[string]string) {
		t.Helper()
		req := httptest.NewRequest(method, "/api/userstate/share", nil)
		req.Header.Set("X-Requested-With", "fetch")
		w := httptest.NewRecorder()
		ServeAPI(w, req, c, email, "")
		var body map[string]string
		if w.Body.Len() > 0 {
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("%s: body %q: %v", method, w.Body.String(), err)
			}
		}
		return w.Code, body
	}

	if code, body := call(http.MethodGet); code != http.StatusOK || body["id"] != "" {
		t.Fatalf("GET before sharing = %d %v, want 200 and no id", code, body)
	}
	code, body := call(http.MethodPost)
	if code != http.StatusOK || !ValidShareID(body["id"]) {
		t.Fatalf("POST = %d %v, want 200 and an id", code, body)
	}
	id := body["id"]
	if code, body := call(http.MethodGet); code != http.StatusOK || body["id"] != id {
		t.Fatalf("GET after sharing = %d %v, want %q", code, body, id)
	}
	if code, _ := call(http.MethodDelete); code != http.StatusNoContent {
		t.Fatalf("DELETE = %d, want 204", code)
	}
	if code, body := call(http.MethodGet); code != http.StatusOK || body["id"] != "" {
		t.Fatalf("GET after revoke = %d %v, want no id", code, body)
	}
	if got, _ := c.ShareFor(context.Background(), h); got != "" {
		t.Fatalf("store still has a live share %q", got)
	}
	// A separate email: apiLimiter is per email, and this call is the sixth.
	req := httptest.NewRequest(http.MethodPatch, "/api/userstate/share", nil)
	w := httptest.NewRecorder()
	ServeAPI(w, req, c, "share-405@example.com", "")
	if code := w.Code; code != http.StatusMethodNotAllowed {
		t.Fatalf("PATCH = %d, want 405", code)
	}
}

// A POST or DELETE without the script's header is another site's form.
func TestServeAPIShareRefusesCrossSiteWrites(t *testing.T) {
	c := testClient(t)
	email := "share-csrf@example.com"
	h := HashEmail(email)
	t.Cleanup(func() { _, _ = c.db.Exec(`DELETE FROM favorites_shares WHERE email_hash = $1`, h) })
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		req := httptest.NewRequest(method, "/api/userstate/share", nil)
		w := httptest.NewRecorder()
		ServeAPI(w, req, c, email, "")
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "same-origin only") {
			t.Fatalf("%s without the header = %d %s, want 403", method, w.Code, w.Body.String())
		}
	}
	if got, _ := c.ShareFor(context.Background(), h); got != "" {
		t.Fatalf("a refused POST made share %q", got)
	}
}

func TestServeAPIShareWithoutDBIs503(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/userstate/share", nil)
	w := httptest.NewRecorder()
	ServeAPI(w, req, nil, "share-nodb@example.com", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}
