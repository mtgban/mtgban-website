package userstate

import (
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
	ServeAPI(w, req, c, "apierr@example.com", 200)

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
	ServeAPI(w, req, c, "apibad@example.com", 200)

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
	ServeAPI(w, req, c, t.Name()+"@example.com", 200)

	if w.Code != http.StatusOK {
		t.Fatalf("backpack PATCH: expected 200, got %d", w.Code)
	}
}

func TestBackpackErrorCountsLiveCards(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"at the limit", `[{"id":"a"},{"id":"b"}]`, ""},
		{"over the limit", `[{"id":"a"},{"id":"b"},{"id":"c"}]`, "backpack is full"},
		{"tombstones do not count", `[{"id":"a"},{"id":"b"},{"id":"c","del":5}]`, ""},
		{"a falsy del is live", `[{"id":"a"},{"id":"b"},{"id":"c","del":0}]`, "backpack is full"},
		{"empty", `[]`, ""},
		{"not a list", `{"id":"a"}`, "bad body"},
		{"no data", ``, "bad body"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := backpackError(json.RawMessage(tc.raw), 2)
			if got != tc.want {
				t.Errorf("backpackError(%s, 2) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}
