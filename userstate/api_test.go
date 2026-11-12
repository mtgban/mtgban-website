package userstate

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/mtgban/mtgban-website/observability"
	"github.com/mtgban/mtgban-website/ratelimit"
)

// A dead pool must yield 500 with a generic body, not a leaked pq error.
func TestServeAPIStoreErrorIs500(t *testing.T) {
	c := testClient(t)
	c.Close() // force every query to fail

	req := httptest.NewRequest(http.MethodPatch, "/api/userstate/favorites",
		strings.NewReader(`{"data":[{"id":"x"}],"version":1}`))
	w := httptest.NewRecorder()
	ServeAPI(w, req, c, "apierr@example.com", "", 200, 1, Hooks{})

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
	ServeAPI(w, req, c, "apibad@example.com", "", 200, 1, Hooks{})

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
	ServeAPI(w, req, c, t.Name()+"@example.com", "", 200, 1, Hooks{})

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
// maxDecoded once unpacked; a body past either is refused with 413.
func TestDecodeBodyTakesGzip(t *testing.T) {
	gz := func(s string) *bytes.Buffer {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		zw.Write([]byte(s))
		zw.Close()
		return &buf
	}
	// Random bytes barely compress, so this stays past maxBody gzipped.
	noise := make([]byte, maxBody)
	_, err := rand.Read(noise)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		body    io.Reader
		gzipped bool
		status  int
	}{
		{"plain", strings.NewReader(`{"data":"x"}`), false, http.StatusOK},
		{"gzipped", gz(`{"data":"x"}`), true, http.StatusOK},
		{"gzipped past maxDecoded", gz(`{"data":"` + strings.Repeat("x", maxDecoded) + `"}`), true, http.StatusRequestEntityTooLarge},
		{"gzipped past maxBody", gz(`{"data":"` + base64.StdEncoding.EncodeToString(noise) + `"}`), true, http.StatusRequestEntityTooLarge},
		{"plain past maxBody", strings.NewReader(`{"data":"` + strings.Repeat("x", maxBody) + `"}`), false, http.StatusRequestEntityTooLarge},
		{"not gzip", strings.NewReader(`{"data":"x"}`), true, http.StatusBadRequest},
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
			if err == nil {
				if tc.status != http.StatusOK {
					t.Fatalf("decoded, want %d", tc.status)
				}
				if got.Data != "x" {
					t.Errorf("data = %q", got.Data)
				}
				return
			}
			rec := httptest.NewRecorder()
			badBody(rec, err)
			if rec.Code != tc.status {
				t.Errorf("err %v answered %d, want %d", err, rec.Code, tc.status)
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
		serveShare(w, req, c, h, "", Hooks{})
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
	ServeAPI(w, req, c, "share-405@example.com", "", 200, 1, Hooks{})
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
		serveShare(w, req, c, h, game, Hooks{})
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
		ServeAPI(w, req, c, email, "", 200, 1, Hooks{})
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
	ServeAPI(w, req, nil, "share-nodb@example.com", "", 200, 1, Hooks{})
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
	serveShare(w, req, emptyShareStore{}, HashEmail("share-empty@example.com"), "", Hooks{})
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "write failed") {
		t.Fatalf("POST with no id = %d %s, want 500 write failed", w.Code, w.Body.String())
	}
}

// recordHooks is a hook that keeps each scope, name and value it is handed.
func recordHooks(got *[][3]string) Hooks {
	return Hooks{Observe: func(_ *http.Request, s, n, v string) { *got = append(*got, [3]string{s, n, v}) }}
}

// slowAPILimiter has apiLimiter allow one request an hour per email.
func slowAPILimiter(t *testing.T) {
	t.Helper()
	saved := apiLimiter
	t.Cleanup(func() { apiLimiter = saved })
	apiLimiter = ratelimit.NewLimiter(rate.Every(time.Hour), 1)
}

// The limiter's refusal is observed; the request it let through, to no db, is not.
func TestServeAPIObservesTheLimiterRefusal(t *testing.T) {
	slowAPILimiter(t)
	var got [][3]string
	hooks := recordHooks(&got)
	for range 2 {
		ServeAPI(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/userstate/", nil), nil, "limit@example.com", "", 200, 1, hooks)
	}
	if !slices.Equal(got, [][3]string{{"", "ratelimit.reject", "userstate"}}) {
		t.Fatalf("observed %v", got)
	}
}

// A zero Hooks observes nothing and does not panic, refused or served.
func TestServeAPITakesANilHook(t *testing.T) {
	slowAPILimiter(t)
	for range 2 {
		w := httptest.NewRecorder()
		ServeAPI(w, httptest.NewRequest(http.MethodGet, "/api/userstate/", nil), nil, "nilhook@example.com", "", 200, 1, Hooks{})
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/userstate/share", nil)
	req.Header.Set("X-Requested-With", "fetch")
	serveShare(w, req, &fixedShareStore{id: "abc"}, HashEmail("nilhook@example.com"), "", Hooks{})
	if w.Code != http.StatusOK {
		t.Fatalf("POST with a zero Hooks = %d, want 200", w.Code)
	}
}

// fixedShareStore always makes and ends the share id it holds.
type fixedShareStore struct{ id string }

func (f *fixedShareStore) ShareFor(context.Context, string, string) (string, error) { return f.id, nil }
func (f *fixedShareStore) CreateShare(context.Context, string, string) (string, error) {
	return f.id, nil
}
func (f *fixedShareStore) RevokeShare(context.Context, string, string) error { return nil }

// A share made or ended is observed once; a refused or failed one is not.
func TestServeShareObservesCreateAndStop(t *testing.T) {
	hash := HashEmail("share-observe@example.com")
	call := func(store shareStore, method string, fetch bool) (int, [][3]string) {
		t.Helper()
		var got [][3]string
		req := httptest.NewRequest(method, "/api/userstate/share", nil)
		if fetch {
			req.Header.Set("X-Requested-With", "fetch")
		}
		w := httptest.NewRecorder()
		serveShare(w, req, store, hash, "", recordHooks(&got))
		return w.Code, got
	}
	for _, tc := range []struct {
		name   string
		store  shareStore
		method string
		fetch  bool
		code   int
		want   [][3]string
	}{
		{"create", &fixedShareStore{id: "abc"}, http.MethodPost, true, http.StatusOK, [][3]string{{"", "favshare.create", ""}}},
		{"stop", &fixedShareStore{id: "abc"}, http.MethodDelete, true, http.StatusNoContent, [][3]string{{"", "favshare.stop", ""}}},
		{"show", &fixedShareStore{id: "abc"}, http.MethodGet, true, http.StatusOK, nil},
		{"cross-site create", &fixedShareStore{id: "abc"}, http.MethodPost, false, http.StatusForbidden, nil},
		{"create with no id", emptyShareStore{}, http.MethodPost, true, http.StatusInternalServerError, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, got := call(tc.store, tc.method, tc.fetch)
			if code != tc.code || !slices.Equal(got, tc.want) {
				t.Fatalf("%s = %d observing %v, want %d observing %v", tc.method, code, got, tc.code, tc.want)
			}
		})
	}
}

// A read, a section write and a write that lost are each observed once,
// a conflict not as a write.
func TestServeAPIObservesSync(t *testing.T) {
	c := testClient(t)
	freshHash(t, c)
	email := t.Name() + "@example.com"
	call := func(method, path, body string) (*httptest.ResponseRecorder, [][3]string) {
		t.Helper()
		var got [][3]string
		w := httptest.NewRecorder()
		ServeAPI(w, httptest.NewRequest(method, path, strings.NewReader(body)), c, email, "", 200, 1, recordHooks(&got))
		return w, got
	}

	w, got := call(http.MethodGet, "/api/userstate/", "")
	if w.Code != http.StatusOK || !slices.Equal(got, [][3]string{{"", "userstate.get", ""}}) {
		t.Fatalf("GET = %d observing %v", w.Code, got)
	}
	var st State
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	patch := `{"data":[{"id":"x"}],"version":` + strconv.FormatInt(st.Version, 10) + `}`
	w, got = call(http.MethodPatch, "/api/userstate/favorites", patch)
	if w.Code != http.StatusOK || !slices.Equal(got, [][3]string{{"", "userstate.patch", "favorites"}}) {
		t.Fatalf("PATCH = %d observing %v", w.Code, got)
	}
	var written struct {
		Version int64 `json:"version"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &written); err != nil {
		t.Fatal(err)
	}
	w, got = call(http.MethodPatch, "/api/userstate/favorites", patch)
	if w.Code != http.StatusConflict || !slices.Equal(got, [][3]string{{"", "userstate.conflict", ""}}) {
		t.Fatalf("stale PATCH = %d observing %v", w.Code, got)
	}
	put := `{"favorites":[{"id":"y"}],"version":` + strconv.FormatInt(written.Version, 10) + `}`
	w, got = call(http.MethodPut, "/api/userstate/", put)
	if w.Code != http.StatusOK || !slices.Equal(got, [][3]string{{"", "userstate.put", ""}}) {
		t.Fatalf("PUT = %d observing %v", w.Code, got)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &written); err != nil {
		t.Fatal(err)
	}
	var notModified [][3]string
	w = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/userstate/", nil)
	req.Header.Set("If-None-Match", `"`+strconv.FormatInt(written.Version, 10)+`"`)
	ServeAPI(w, req, c, email, "", 200, 1, recordHooks(&notModified))
	if w.Code != http.StatusNotModified || !slices.Equal(notModified, [][3]string{{"", "userstate.get", ""}}) {
		t.Fatalf("conditional GET = %d observing %v", w.Code, notModified)
	}
}

// Every section a PATCH may write is a value userstate.patch accepts.
func TestSectionsMatchTheRegistry(t *testing.T) {
	n, ok := observability.Lookup("userstate.patch")
	if !ok {
		t.Fatal("userstate.patch is not registered")
	}
	for section := range validSections {
		if _, _, ok := n.Check("", section, observability.Validators{}); !ok {
			t.Errorf("the registry refuses section %q", section)
		}
	}
}
