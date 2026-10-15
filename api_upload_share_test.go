package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/userstate"
)

type fakeShareWriter struct {
	got  []userstate.UploadShare
	fail error
	live int
}

func (f *fakeShareWriter) CountLiveUploadShares(context.Context, string) (int, error) {
	return f.live, nil
}

func (f *fakeShareWriter) CreateUploadShare(_ context.Context, emailHash, game, rows string, buylist bool, ttl time.Duration) (userstate.UploadShare, error) {
	if f.fail != nil {
		return userstate.UploadShare{}, f.fail
	}
	s := userstate.UploadShare{Key: "AbCdEfGhIjKlMnOpQrStUv", EmailHash: emailHash, Game: game, Rows: rows, Buylist: buylist, ExpiresAt: time.Now().Add(ttl)}
	f.got = append(f.got, s)
	return s, nil
}

// shareTestSeq numbers the emails the tests sign in with: the limiter is
// per email, so each request gets its own unless a test wants otherwise.
var shareTestSeq atomic.Int64

func nextShareEmail() string {
	return fmt.Sprintf("share%d@b.com", shareTestSeq.Add(1))
}

// shareRequest posts body as the page does, signed in as email with the
// grants named, or unsigned when tier is "".
func shareRequest(t *testing.T, tier, email string, grants map[string]map[string]string, body string, withHeader bool) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/upload/share", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if withHeader {
		r.Header.Set("X-Requested-With", "fetch")
	}
	if tier != "" {
		user := &PatreonUserData{FullName: "A", Email: email, EmailVerified: true}
		r.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sign(tier, user, grants, time.Hour)})
	}
	return r
}

func shareStatus(t *testing.T, store uploadShareWriter, r *http.Request) (int, map[string]string) {
	t.Helper()
	rec := httptest.NewRecorder()
	serveUploadShare(rec, r, store)
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

var uploadGrant = map[string]map[string]string{"Upload": {}}

func TestUploadShareAPIStoresTheRows(t *testing.T) {
	withSigMode(t, false, true)
	store := &fakeShareWriter{}
	rows := "uuid-1\t2\tNM\t\t\t\t\nuuid-2\t1\t\t\t\t\t"
	email := nextShareEmail()
	code, body := shareStatus(t, store, shareRequest(t, "Legacy", email, uploadGrant, `{"rows":"`+strings.ReplaceAll(strings.ReplaceAll(rows, "\t", `\t`), "\n", `\n`)+`","buylist":true}`, true))
	if code != http.StatusCreated {
		t.Fatalf("status %d body %v", code, body)
	}
	if body["key"] != "AbCdEfGhIjKlMnOpQrStUv" || body["url"] != "/upload?share=AbCdEfGhIjKlMnOpQrStUv" || body["expires"] == "" {
		t.Fatalf("body %v", body)
	}
	if len(store.got) != 1 || store.got[0].Rows != rows || !store.got[0].Buylist {
		t.Fatalf("stored %+v", store.got)
	}
	if store.got[0].EmailHash != userstate.HashEmail(userStateIdentity(email)) {
		t.Fatalf("owner hash %q is not the userstate identity", store.got[0].EmailHash)
	}
}

func TestUploadShareAPIRefusals(t *testing.T) {
	withSigMode(t, false, true)
	good := `{"rows":"uuid-1\t1\t\t\t\t\t","buylist":false}`
	cases := []struct {
		name  string
		tier  string
		grant map[string]map[string]string
		body  string
		hdr   bool
		store uploadShareWriter
		want  int
	}{
		{"not signed in", "", nil, good, true, &fakeShareWriter{}, http.StatusUnauthorized},
		{"no Upload grant", "Legacy", map[string]map[string]string{"Search": {}}, good, true, &fakeShareWriter{}, http.StatusForbidden},
		{"no store", "Legacy", uploadGrant, good, true, nil, http.StatusServiceUnavailable},
		{"at the live cap", "Legacy", uploadGrant, good, true, &fakeShareWriter{live: uploadShareMaxLive}, http.StatusTooManyRequests},
		{"insert failed", "Legacy", uploadGrant, good, true, &fakeShareWriter{fail: errors.New("down")}, http.StatusServiceUnavailable},
		{"empty rows", "Legacy", uploadGrant, `{"rows":""}`, true, &fakeShareWriter{}, http.StatusBadRequest},
		{"row without a hash", "Legacy", uploadGrant, `{"rows":"\t1\t\t\t\t\t"}`, true, &fakeShareWriter{}, http.StatusBadRequest},
		{"not json", "Legacy", uploadGrant, `rows=1`, true, &fakeShareWriter{}, http.StatusBadRequest},
	}
	for _, c := range cases {
		code, body := shareStatus(t, c.store, shareRequest(t, c.tier, nextShareEmail(), c.grant, c.body, c.hdr))
		if code != c.want {
			t.Errorf("%s: status %d body %v, want %d", c.name, code, body, c.want)
		}
		if body["error"] == "" {
			t.Errorf("%s: no error message in %v", c.name, body)
		}
	}
}

// The cookie rides a cross-site form post; the header needs a preflight
// another site's page cannot pass.
func TestUploadShareAPIRequiresTheFetchHeader(t *testing.T) {
	withSigMode(t, false, true)
	code, _ := shareStatus(t, &fakeShareWriter{}, shareRequest(t, "Legacy", nextShareEmail(), uploadGrant, `{"rows":"uuid-1\t1\t\t\t\t\t"}`, false))
	if code != http.StatusForbidden {
		t.Fatalf("status %d without the header, want 403", code)
	}
}

// Shares are clicks: ten in a burst, then the limiter answers.
func TestUploadShareAPIRateLimited(t *testing.T) {
	withSigMode(t, false, true)
	email := nextShareEmail()
	store := &fakeShareWriter{}
	var codes []int
	for range 11 {
		code, _ := shareStatus(t, store, shareRequest(t, "Legacy", email, uploadGrant, `{"rows":"uuid-1\t1\t\t\t\t\t"}`, true))
		codes = append(codes, code)
	}
	if codes[9] != http.StatusCreated || codes[10] != http.StatusTooManyRequests {
		t.Fatalf("codes %v, want ten 201s then a 429", codes)
	}
}

// The header check comes before the sign-in check, so an unsigned
// cross-site post learns nothing.
func TestUploadShareAPIHeaderComesBeforeSignIn(t *testing.T) {
	withSigMode(t, false, true)
	code, _ := shareStatus(t, &fakeShareWriter{}, shareRequest(t, "", "", nil, `{"rows":"uuid-1\t1\t\t\t\t\t"}`, false))
	if code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", code)
	}
}

func TestUploadShareAPIStoresTheGame(t *testing.T) {
	withSigMode(t, false, true)
	store := &fakeShareWriter{}
	shareStatus(t, store, shareRequest(t, "Legacy", nextShareEmail(), uploadGrant, `{"rows":"uuid-1\t1\t\t\t\t\t"}`, true))
	if len(store.got) != 1 || store.got[0].Game != string(Config().Game) {
		t.Fatalf("stored %+v", store.got)
	}
}

func TestUploadShareAPITooManyRows(t *testing.T) {
	withSigMode(t, false, true)
	lines := make([]string, MaxUploadTotalEntries+1)
	for i := range lines {
		lines[i] = `uuid\t1\t\t\t\t\t`
	}
	code, _ := shareStatus(t, &fakeShareWriter{}, shareRequest(t, "Legacy", nextShareEmail(), uploadGrant, `{"rows":"`+strings.Join(lines, `\n`)+`"}`, true))
	if code != http.StatusBadRequest {
		t.Fatalf("status %d for %d rows, want 400", code, len(lines))
	}
}

func TestUploadShareAPIRejectsGet(t *testing.T) {
	withSigMode(t, false, true)
	r := httptest.NewRequest(http.MethodGet, "/api/upload/share", nil)
	rec := httptest.NewRecorder()
	serveUploadShare(rec, r, &fakeShareWriter{})
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d, want 405", rec.Code)
	}
}

func TestValidateShareRows(t *testing.T) {
	if err := validateShareRows("uuid-1\t1\t\t\t\t\t\nuuid-2\t2\t\t\t\t\t\n"); err != nil {
		t.Fatalf("trailing newline refused: %v", err)
	}
	for _, bad := range []string{"", "\n", "\t1", "uuid-1\t1\n\t2"} {
		if err := validateShareRows(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestUploadShareStoreNilWithoutClient(t *testing.T) {
	saved := UserStateDB
	t.Cleanup(func() { UserStateDB = saved })
	UserStateDB = nil
	if store := uploadShareStore(); store != nil {
		t.Fatalf("store %#v, want a nil interface", store)
	}
}
