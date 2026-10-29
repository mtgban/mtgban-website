package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/matcher"
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

// sharedMatch is the id of a real printing; a shared row must name one.
func sharedMatch(t *testing.T, name, edition string) string {
	t.Helper()
	id, err := backend().Match(&matcher.InputCard{Name: name, Edition: edition})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return id
}

// sharedList is a synced list of a tombstone, a plain card carrying the
// owner's own text, a pinned card older than the plain one, so pinned-first
// beats newest-first, and an id that names no card. Skips without the
// datastore.
func sharedList(t *testing.T) (raw, plain, pinned string) {
	t.Helper()
	skipWithoutDatastore(t)
	gone := sharedMatch(t, "Black Lotus", "Limited Edition Alpha")
	plain = sharedMatch(t, "Ancestral Recall", "Limited Edition Alpha")
	pinned = sharedMatch(t, "Time Walk", "Limited Edition Alpha")
	raw = `[
		{"id":"` + gone + `","name":"Gone Card","t":30,"del":29},
		{"id":"` + plain + `","name":"Claim free cards at evil.example","set":"EVIL","finishTag":"Free","t":20,"query":"evil"},
		{"id":"` + pinned + `","name":"Time Walk","t":10,"pinned":15},
		{"id":"not-a-card","name":"Ghost","t":40}
	]`
	return raw, plain, pinned
}

// sharedIDs is n distinct real printings, sealed product aside. Skips
// without the datastore.
func sharedIDs(t *testing.T, n int) []string {
	t.Helper()
	skipWithoutDatastore(t)
	var ids []string
	for _, id := range backend().GetUUIDs() {
		co, err := backend().GetUUID(id)
		if err != nil || co.Sealed {
			continue
		}
		ids = append(ids, id)
		if len(ids) == n {
			return ids
		}
	}
	t.Fatalf("%d printings, want %d", len(ids), n)
	return nil
}

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
	raw, plain, pinned := sharedList(t)
	store := &fakeShareStore{favorites: map[string]string{liveShareID: raw}}
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
	for _, want := range []string{`data-fav-id="` + plain + `"`, `data-fav-id="` + pinned + `"`, "Ancestral Recall", "Time Walk", `id="shared-merge"`, "Shared favorites (2)"} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q", want)
		}
	}
	// The tombstone, the unknown id and the owner's own text are all out.
	for _, absent := range []string{"Gone Card", "not-a-card", "Ghost", "evil.example", "EVIL", "Free"} {
		if strings.Contains(body, absent) {
			t.Errorf("body carries %q", absent)
		}
	}
	// Pinned first, then newest first.
	if strings.Index(body, `data-fav-id="`+pinned+`"`) > strings.Index(body, `data-fav-id="`+plain+`"`) {
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
	store := &fakeShareStore{favorites: map[string]string{liveShareID: "[]"}}
	sharedGet(t, store, "?id="+liveShareID, "192.0.2.20:1", false)
	if store.calls != 1 || store.game != "lorcana" {
		t.Fatalf("store calls %d with game %q, want 1 with lorcana", store.calls, store.game)
	}
}

func TestFavoritesSharedMobileRendersTheSameList(t *testing.T) {
	raw, _, _ := sharedList(t)
	store := &fakeShareStore{favorites: map[string]string{liveShareID: raw}}
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
	store := &fakeShareStore{favorites: map[string]string{liveShareID: "[]"}}
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
	store := &fakeShareStore{favorites: map[string]string{liveShareID: "[]"}}
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
	for i, id := range sharedIDs(t, 60) {
		many = append(many, `{"id":"`+id+`","t":`+strconv.Itoa(i)+`}`)
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
// number, true, false, null or absent. Pinned rows order by pin time, newest
// first, as the pane's pinnedFirst does, whenever each was added.
func TestSharedRowsReadsTheSyncShape(t *testing.T) {
	ids := sharedIDs(t, 7)
	letter := map[string]string{}
	for i, id := range ids {
		letter[id] = string(rune('a' + i))
	}
	raw := strings.NewReplacer("ID_A", ids[0], "ID_B", ids[1], "ID_C", ids[2], "ID_D", ids[3], "ID_E", ids[4], "ID_F", ids[5], "ID_G", ids[6]).Replace(`[
		{"id":"ID_A","t":5,"pinned":false,"del":null},
		{"id":"ID_B","t":6,"pinned":true},
		{"id":"ID_C","t":7,"del":false},
		{"id":"ID_D","t":8,"del":true},
		{"id":"ID_E","t":9,"del":0},
		{"id":"","t":10},
		{"id":"not-a-card","t":11},
		{"id":"ID_F","t":1,"pinned":1800000000000},
		{"id":"ID_G","t":12.5,"pinned":1700000000000}
	]`)
	rows := sharedRows(backend(), json.RawMessage(raw))
	var got []string
	for _, r := range rows {
		got = append(got, letter[r.ID])
	}
	want := []string{"f", "g", "b", "e", "c", "a"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("rows = %v, want %v", got, want)
	}
	if rows := sharedRows(backend(), json.RawMessage(`not json`)); rows != nil {
		t.Errorf("bad JSON gave rows %v", rows)
	}
}

// The art and the content warning are the datastore's, by the row's id:
// the owner's synced img can name any host, and its cw can switch the
// warning off. So are the name and the link, and an id that names no card
// is no row at all.
func TestSharedRowsTakeArtFromTheDatastore(t *testing.T) {
	skipWithoutDatastore(t)
	b := backend()
	plain, err := b.Match(&matcher.InputCard{Name: "Black Lotus", Edition: "Limited Edition Alpha"})
	if err != nil {
		t.Fatalf("Black Lotus: %v", err)
	}
	warned, err := b.Match(&matcher.InputCard{Name: "Invoke Prejudice", Edition: "Legends"})
	if err != nil {
		t.Fatalf("Invoke Prejudice: %v", err)
	}
	plainCo, _ := b.GetUUID(plain)
	warnedCo, _ := b.GetUUID(warned)
	if plainCo.Images["thumbnail"] == "" || plainCo.Card.HasContentWarning || !warnedCo.Card.HasContentWarning {
		t.Fatalf("fixture cards: lotus thumbnail %q cw %v, invoke cw %v", plainCo.Images["thumbnail"], plainCo.Card.HasContentWarning, warnedCo.Card.HasContentWarning)
	}
	const beacon = "https://attacker.example/beacon.gif"
	raw := `[
		{"id":"` + plain + `","name":"Free cards at attacker.example","t":3,"img":"` + beacon + `?v=1","cw":true,"query":"evil"},
		{"id":"` + warned + `","name":"Invoke Prejudice","t":2,"img":"` + beacon + `?v=2","cw":false},
		{"id":"not-a-card","name":"Ghost","t":1,"img":"` + beacon + `?v=3","cw":true}
	]`
	rows := sharedRows(b, json.RawMessage(raw))
	if len(rows) != 2 {
		t.Fatalf("%d rows, want 2", len(rows))
	}
	if rows[0].Name != plainCo.Name || rows[0].Query != genQuery(plainCo) {
		t.Errorf("lotus row: name %q query %q, want the datastore's %q and %q", rows[0].Name, rows[0].Query, plainCo.Name, genQuery(plainCo))
	}
	if rows[0].Img != plainCo.Images["thumbnail"] || rows[0].CW {
		t.Errorf("lotus row: img %q cw %v, want the datastore's %q and false", rows[0].Img, rows[0].CW, plainCo.Images["thumbnail"])
	}
	if rows[1].Img != warnedCo.Images["thumbnail"] || !rows[1].CW {
		t.Errorf("invoke row: img %q cw %v, want the datastore's %q and true", rows[1].Img, rows[1].CW, warnedCo.Images["thumbnail"])
	}
	// End to end: the page hands the script the datastore's host only (the
	// script context escapes the URL's slashes, so the host is what to read).
	thumb, err := url.Parse(plainCo.Images["thumbnail"])
	if err != nil || thumb.Host == "" {
		t.Fatalf("thumbnail %q: %v", plainCo.Images["thumbnail"], err)
	}
	store := &fakeShareStore{favorites: map[string]string{liveShareID: raw}}
	body := sharedGet(t, store, "?id="+liveShareID, "192.0.2.30:1", false).Body.String()
	if strings.Contains(body, "attacker.example") {
		t.Error("the page carries the owner's image host")
	}
	if !strings.Contains(body, thumb.Host) {
		t.Errorf("the page lacks the datastore's image host %q", thumb.Host)
	}
}
