package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/userstate"
)

// fakeShareStore answers SharedFavorites from a map, counts the calls and
// keeps the game the last one asked for.
type fakeShareStore struct {
	favorites map[string]string
	err       error
	calls     int
	game      string
}

func (f *fakeShareStore) SharedFavorites(_ context.Context, id, game string) (json.RawMessage, error) {
	f.calls++
	f.game = game
	if f.err != nil {
		return nil, f.err
	}
	raw, ok := f.favorites[id]
	if !ok {
		return nil, userstate.ErrShareNotFound
	}
	return json.RawMessage(raw), nil
}

const liveShareID = "AAAAAAAAAAAAAAAAAAAAAA"

// Three cards: a tombstone, a plain one, and a pinned one older than the plain
// one, so pinned-first beats newest-first.
const sharedListJSON = `[
	{"id":"gone-1","name":"Gone Card","set":"LEA","t":30,"del":29,"query":"Gone Card s:LEA"},
	{"id":"plain-2","name":"Sol Ring","set":"CMR","number":"350","t":20,"foil":false,"query":"Sol Ring s:CMR cns:350 f:nonfoil","img":"https://img.example/sol.jpg"},
	{"id":"pinned-3","name":"Mox Opal","set":"SLD","number":"1072","t":10,"pinned":15,"etched":true,"finishTag":"Etched","finishClass":"etched","query":"Mox Opal s:SLD cns:1072 f:etched"}
]`

// sharedGet runs the handler as the page does, from a distinct client address
// per test so the rate limiter's budget is each test's own.
func sharedGet(t *testing.T, store sharedFavoritesStore, query, addr string, mobile bool) *httptest.ResponseRecorder {
	t.Helper()
	withSigMode(t, true, false)
	req := httptest.NewRequest(http.MethodGet, "/search/shared"+query, nil)
	req.RemoteAddr = addr
	if mobile {
		req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1")
	}
	rec := httptest.NewRecorder()
	testSite.favoritesShared(rec, req, store)
	return rec
}

func TestFavoritesSharedRendersTheLiveList(t *testing.T) {
	store := &fakeShareStore{favorites: map[string]string{liveShareID: sharedListJSON}}
	rec := sharedGet(t, store, "?id="+liveShareID, "192.0.2.10:1", false)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Errorf("Referrer-Policy = %q, want same-origin", got)
	}
	for _, want := range []string{`data-fav-id="plain-2"`, `data-fav-id="pinned-3"`, "Sol Ring", "Mox Opal", `id="shared-merge"`, "Shared favorites (2)"} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q", want)
		}
	}
	for _, absent := range []string{"gone-1", "Gone Card"} {
		if strings.Contains(body, absent) {
			t.Errorf("body carries %q", absent)
		}
	}
	// Pinned first, then newest first.
	if strings.Index(body, `data-fav-id="pinned-3"`) > strings.Index(body, `data-fav-id="plain-2"`) {
		t.Error("pinned row is not first")
	}
	if flat := strings.Join(strings.Fields(body), " "); !strings.Contains(flat, "BAN_SHARED_FAVORITES") || !strings.Contains(flat, "signedIn: false") {
		t.Error("page does not hand the script its rows and sign-in state")
	}
	if store.game != string(Config().Game) {
		t.Errorf("store asked for game %q, want the site's %q", store.game, Config().Game)
	}
}

// A non-Magic site asks the store for its own game's shares only.
func TestFavoritesSharedAsksForTheSitesGame(t *testing.T) {
	withConfigCopy(t)
	Config().Game = "lorcana"
	store := &fakeShareStore{favorites: map[string]string{liveShareID: sharedListJSON}}
	sharedGet(t, store, "?id="+liveShareID, "192.0.2.20:1", false)
	if store.calls != 1 || store.game != "lorcana" {
		t.Fatalf("store calls %d with game %q, want 1 with lorcana", store.calls, store.game)
	}
}

func TestFavoritesSharedMobileRendersTheSameList(t *testing.T) {
	store := &fakeShareStore{favorites: map[string]string{liveShareID: sharedListJSON}}
	rec := sharedGet(t, store, "?id="+liveShareID, "192.0.2.11:1", true)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, `class="m-fav-item"`) || !strings.Contains(body, `id="shared-merge"`) {
		t.Fatalf("mobile page = %d %s", rec.Code, body)
	}
}

func TestFavoritesSharedUnknownIDIsGone(t *testing.T) {
	store := &fakeShareStore{favorites: map[string]string{}}
	rec := sharedGet(t, store, "?id=BBBBBBBBBBBBBBBBBBBBBB", "192.0.2.12:1", false)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), sharedGoneText) {
		t.Fatalf("unknown id = %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `id="shared-merge"`) {
		t.Error("a gone list offers Merge")
	}
}

func TestFavoritesSharedMalformedID(t *testing.T) {
	store := &fakeShareStore{favorites: map[string]string{liveShareID: sharedListJSON}}
	for i, query := range []string{"", "?id=", "?id=short", "?id=AAAAAAAAAAAAAAAAAAAAA/", "?id=" + liveShareID + "x", "?sig=abc&id=AAAAAAAAAAAAAAAAAAAAA="} {
		rec := sharedGet(t, store, query, "198.51.100."+strconv.Itoa(i+1)+":1", false)
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), sharedGoneText) {
			t.Errorf("%d %q: = %d, want 404 with the notice", i, query, rec.Code)
		}
	}
	if store.calls != 0 {
		t.Errorf("a malformed id reached the store %d times", store.calls)
	}
}

func TestFavoritesSharedStoreStates(t *testing.T) {
	if rec := sharedGet(t, nil, "?id="+liveShareID, "192.0.2.14:1", false); rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), sharedUnavailableText) {
		t.Errorf("nil store = %d %s", rec.Code, rec.Body.String())
	}
	broken := &fakeShareStore{err: errors.New("pq: boom")}
	rec := sharedGet(t, broken, "?id="+liveShareID, "192.0.2.15:1", false)
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), sharedErrorText) || strings.Contains(rec.Body.String(), "pq:") {
		t.Errorf("store error = %d %s", rec.Code, rec.Body.String())
	}
}

func TestFavoritesSharedRateLimit(t *testing.T) {
	store := &fakeShareStore{favorites: map[string]string{liveShareID: sharedListJSON}}
	var last *httptest.ResponseRecorder
	for i := 0; i < 6; i++ {
		last = sharedGet(t, store, "?id="+liveShareID, "192.0.2.16:1", false)
	}
	if last.Code != http.StatusTooManyRequests || !strings.Contains(last.Body.String(), sharedBusyText) {
		t.Fatalf("sixth request = %d, want 429 with the notice", last.Code)
	}
	if last.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("429 Cache-Control = %q, want no-store", last.Header().Get("Cache-Control"))
	}
	if rec := sharedGet(t, store, "?id="+liveShareID, "192.0.2.17:1", false); rec.Code != http.StatusOK {
		t.Errorf("another address = %d, want 200", rec.Code)
	}
}

func TestFavoritesSharedEmptyAndCapped(t *testing.T) {
	var many []string
	for i := 0; i < 60; i++ {
		many = append(many, `{"id":"c`+strconv.Itoa(i)+`","name":"Card","t":`+strconv.Itoa(i)+`}`)
	}
	store := &fakeShareStore{favorites: map[string]string{
		liveShareID:              "[" + strings.Join(many, ",") + "]",
		"CCCCCCCCCCCCCCCCCCCCCC": "[]",
	}}
	rec := sharedGet(t, store, "?id="+liveShareID, "192.0.2.18:1", false)
	if rec.Code != http.StatusOK || strings.Count(rec.Body.String(), "data-fav-id=") != sharedListCap {
		t.Errorf("capped list has %d rows, want %d", strings.Count(rec.Body.String(), "data-fav-id="), sharedListCap)
	}
	rec = sharedGet(t, store, "?id=CCCCCCCCCCCCCCCCCCCCCC", "192.0.2.19:1", false)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "This list is empty.") || strings.Contains(rec.Body.String(), `id="shared-merge"`) {
		t.Errorf("empty list = %d %s", rec.Code, rec.Body.String())
	}
}

// sharedRows reads the shape the browser syncs: pinned and del may be a
// number, true, false, null or absent.
func TestSharedRowsReadsTheSyncShape(t *testing.T) {
	raw := `[
		{"id":"a","name":"A","t":5,"pinned":false,"del":null},
		{"id":"b","name":"B","t":6,"pinned":true},
		{"id":"c","name":"C","t":7,"del":false},
		{"id":"d","name":"D","t":8,"del":true},
		{"id":"e","name":"E","t":9,"del":0},
		{"id":"","name":"no id","t":10},
		{"id":"f","name":"","t":11},
		{"id":"g","name":"G","t":12.5,"pinned":1700000000000}
	]`
	rows := sharedRows(json.RawMessage(raw))
	var ids []string
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	want := []string{"g", "b", "e", "c", "a"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("rows = %v, want %v", ids, want)
	}
	if rows := sharedRows(json.RawMessage(`not json`)); rows != nil {
		t.Errorf("bad JSON gave rows %v", rows)
	}
}
