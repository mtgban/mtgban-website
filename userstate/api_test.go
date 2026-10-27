package userstate

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
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
	ServeAPI(w, req, c, "apierr@example.com", "", 200, 1)

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
	ServeAPI(w, req, c, "apibad@example.com", "", 200, 1)

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
	ServeAPI(w, req, c, t.Name()+"@example.com", "", 200, 1)

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
		{"each backpack at the limit", `[{"id":"a"},{"id":"b"},{"id":"a","pack":2},{"id":"b","pack":"2"}]`, ""},
		{"one backpack over the limit", `[{"id":"a"},{"id":"a","pack":2},{"id":"b","pack":2},{"id":"c","pack":2}]`, "backpack is full"},
		{"pack 1 named or not is one backpack", `[{"id":"a"},{"id":"b","pack":1},{"id":"c","pack":"x"}]`, "backpack is full"},
		{"over the total across backpacks", `[{"id":"a"},{"id":"a","pack":2},{"id":"a","pack":3},{"id":"b","pack":3},{"id":"a","pack":4}]`, "backpack is full"},
		{"not a list", `{"id":"a"}`, "bad body"},
		{"no data", ``, "bad body"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := backpackError(json.RawMessage(tc.raw), 2, 2)
			if got != tc.want {
				t.Errorf("backpackError(%s, 2, 2) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// A one-backpack tier cannot spread past its size across more backpacks.
func TestBackpackErrorCapsTheTotal(t *testing.T) {
	two := json.RawMessage(`[{"id":"a"},{"id":"b","pack":2}]`)
	if got := backpackError(two, 1, 1); got != "backpack is full" {
		t.Errorf("two cards in two backpacks of one, one allowed: %q", got)
	}
	if got := backpackError(two, 1, 2); got != "" {
		t.Errorf("two cards in two backpacks of one, two allowed: %q", got)
	}
}

// A sync body may come gzipped, and is held to maxBody as sent and to
// maxDecoded once unpacked.
func TestDecodeBodyTakesGzip(t *testing.T) {
	gz := func(s string) *bytes.Buffer {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		zw.Write([]byte(s))
		zw.Close()
		return &buf
	}
	cases := []struct {
		name    string
		body    io.Reader
		gzipped bool
		ok      bool
	}{
		{"plain", strings.NewReader(`{"data":"x"}`), false, true},
		{"gzipped", gz(`{"data":"x"}`), true, true},
		{"gzipped past maxDecoded", gz(`{"data":"` + strings.Repeat("x", maxDecoded) + `"}`), true, false},
		{"plain past maxBody", strings.NewReader(`{"data":"` + strings.Repeat("x", maxBody) + `"}`), false, false},
		{"not gzip", strings.NewReader(`{"data":"x"}`), true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPatch, "/api/userstate/backpack", tc.body)
			if tc.gzipped {
				req.Header.Set("Content-Encoding", "gzip")
			}
			var got struct {
				Data string `json:"data"`
			}
			err := decodeBody(httptest.NewRecorder(), req, &got)
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok %v", err, tc.ok)
			}
			if tc.ok && got.Data != "x" {
				t.Errorf("data = %q", got.Data)
			}
		})
	}
}

// The share section: one live link per owner and game, made on POST, shown
// on GET, ended on DELETE. These call serveShare past apiLimiter, whose
// burst of five a run of calls for one email outlasts.
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
		serveShare(w, req, c, h, "")
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
	if got, _ := c.ShareFor(context.Background(), h, ""); got != "" {
		t.Fatalf("store still has a live share %q", got)
	}
	req := httptest.NewRequest(http.MethodPatch, "/api/userstate/share", nil)
	w := httptest.NewRecorder()
	ServeAPI(w, req, c, "share-405@example.com", "", 200, 1)
	if code := w.Code; code != http.StatusMethodNotAllowed {
		t.Fatalf("PATCH = %d, want 405", code)
	}
}

// A game site shows and ends only the links made on it.
func TestServeAPIShareIsPerGame(t *testing.T) {
	c := testClient(t)
	email := "share-games@example.com"
	h := HashEmail(email)
	if _, err := c.db.Exec(`DELETE FROM favorites_shares WHERE email_hash = $1`, h); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = c.db.Exec(`DELETE FROM favorites_shares WHERE email_hash = $1`, h) })

	call := func(method, game string) map[string]string {
		t.Helper()
		req := httptest.NewRequest(method, "/api/userstate/share", nil)
		req.Header.Set("X-Requested-With", "fetch")
		w := httptest.NewRecorder()
		serveShare(w, req, c, h, game)
		var body map[string]string
		if w.Body.Len() > 0 {
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("%s %q: body %q: %v", method, game, w.Body.String(), err)
			}
		}
		return body
	}

	magic := call(http.MethodPost, "")["id"]
	if body := call(http.MethodGet, "lorcana"); body["id"] != "" {
		t.Fatalf("lorcana GET shows the default site's link %v", body)
	}
	lorcana := call(http.MethodPost, "lorcana")["id"]
	if got := call(http.MethodGet, "")["id"]; got != magic {
		t.Fatalf("default site GET after a lorcana POST = %q, want %q", got, magic)
	}
	call(http.MethodDelete, "lorcana")
	if got := call(http.MethodGet, "")["id"]; got != magic {
		t.Fatalf("default site GET after a lorcana DELETE = %q, want %q", got, magic)
	}
	if got := call(http.MethodGet, "lorcana")["id"]; got != "" {
		t.Fatalf("lorcana GET after its DELETE = %q (made %q), want none", got, lorcana)
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
		ServeAPI(w, req, c, email, "", 200, 1)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "same-origin only") {
			t.Fatalf("%s without the header = %d %s, want 403", method, w.Code, w.Body.String())
		}
	}
	if got, _ := c.ShareFor(context.Background(), h, ""); got != "" {
		t.Fatalf("a refused POST made share %q", got)
	}
}

func TestServeAPIShareWithoutDBIs503(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/userstate/share", nil)
	w := httptest.NewRecorder()
	ServeAPI(w, req, nil, "share-nodb@example.com", "", 200, 1)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

// emptyShareStore is a CreateShare that lost a race whose winner was
// revoked before it looked: no error, no id.
type emptyShareStore struct{}

func (emptyShareStore) ShareFor(context.Context, string, string) (string, error)    { return "", nil }
func (emptyShareStore) CreateShare(context.Context, string, string) (string, error) { return "", nil }
func (emptyShareStore) RevokeShare(context.Context, string, string) error           { return nil }

// A POST that ends with no live id is a failure, not a link to nowhere.
func TestServeShareWithoutAnIDIs500(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/userstate/share", nil)
	req.Header.Set("X-Requested-With", "fetch")
	w := httptest.NewRecorder()
	serveShare(w, req, emptyShareStore{}, HashEmail("share-empty@example.com"), "")
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "write failed") {
		t.Fatalf("POST with no id = %d %s, want 500 write failed", w.Code, w.Body.String())
	}
}
