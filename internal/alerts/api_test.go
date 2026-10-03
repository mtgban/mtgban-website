package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeAlertStore keeps rows in memory; ids are assigned in order.
type fakeAlertStore struct {
	contacts map[string]Contact
	rows     map[int64]Alert
	channels map[channelKey]Channel
	nextID   int64
}

type channelKey struct {
	userHash string
	kind     ChannelKind
	source   ChannelSource
}

func newFakeAlertStore() *fakeAlertStore {
	return &fakeAlertStore{contacts: map[string]Contact{}, rows: map[int64]Alert{}, channels: map[channelKey]Channel{}}
}

func (f *fakeAlertStore) Channels(_ context.Context, h string) ([]Channel, error) {
	var out []Channel
	for k, c := range f.channels {
		if k.userHash == h {
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b Channel) int {
		return strings.Compare(string(a.Kind)+"|"+string(a.Source), string(b.Kind)+"|"+string(b.Source))
	})
	return out, nil
}

// ChannelFor mirrors the store: a verified user row over an undisabled
// patreon one, then the contact's Discord id when no Discord row exists.
func (f *fakeAlertStore) ChannelFor(_ context.Context, h string, kind ChannelKind) (Channel, bool, error) {
	user, ok := f.channels[channelKey{h, kind, SourceUser}]
	if ok && user.VerifiedAt != nil && user.DisabledAt == nil {
		return user, true, nil
	}
	patreon, ok := f.channels[channelKey{h, kind, SourcePatreon}]
	if ok && patreon.DisabledAt == nil {
		return patreon, true, nil
	}
	if kind != ChannelDiscord {
		return Channel{}, false, nil
	}
	for k := range f.channels {
		if k.userHash == h && k.kind == kind {
			return Channel{}, false, nil
		}
	}
	c, ok := f.contacts[h]
	if !ok || c.DiscordUserID == "" {
		return Channel{}, false, nil
	}
	at := time.Unix(1, 0)
	return Channel{UserHash: h, Kind: ChannelDiscord, Address: c.DiscordUserID, Source: SourcePatreon, VerifiedAt: &at}, true, nil
}

// UpsertChannel mirrors the store: the same address keeps its state, a new one resets it.
func (f *fakeAlertStore) UpsertChannel(_ context.Context, c Channel) error {
	k := channelKey{c.UserHash, c.Kind, c.Source}
	cur, ok := f.channels[k]
	if ok && strings.EqualFold(cur.Address, c.Address) {
		if c.VerifiedAt == nil {
			c.VerifiedAt = cur.VerifiedAt
		}
		c.DisabledAt, c.DisabledReason = cur.DisabledAt, cur.DisabledReason
	} else {
		c.DisabledAt, c.DisabledReason = nil, ""
	}
	f.channels[k] = c
	return nil
}
func (f *fakeAlertStore) ChannelByAddress(_ context.Context, kind ChannelKind, address string) ([]Channel, error) {
	var out []Channel
	for k, c := range f.channels {
		if k.kind == kind && strings.EqualFold(c.Address, address) {
			out = append(out, c)
		}
	}
	return out, nil
}
func (f *fakeAlertStore) DeleteChannel(_ context.Context, h string, kind ChannelKind, source ChannelSource) error {
	delete(f.channels, channelKey{h, kind, source})
	return nil
}
func (f *fakeAlertStore) EnableChannel(_ context.Context, h string, kind ChannelKind, source ChannelSource) error {
	k := channelKey{h, kind, source}
	c, ok := f.channels[k]
	if ok {
		c.DisabledAt, c.DisabledReason = nil, ""
		f.channels[k] = c
	}
	return nil
}

func (f *fakeAlertStore) Contact(_ context.Context, h string) (Contact, bool, error) {
	c, ok := f.contacts[h]
	return c, ok, nil
}
func (f *fakeAlertStore) EnsureContact(_ context.Context, h, tier string) error {
	c := f.contacts[h]
	c.UserHash, c.Tier = h, tier
	f.contacts[h] = c
	return nil
}
func (f *fakeAlertStore) Create(_ context.Context, a Alert) (Alert, error) {
	f.nextID++
	a.ID, a.Status = f.nextID, StatusActive
	f.rows[a.ID] = a
	return a, nil
}
func (f *fakeAlertStore) ListByUser(_ context.Context, h, game string) ([]Alert, error) {
	var out []Alert
	for _, a := range f.rows {
		if a.UserHash == h && a.Game == game {
			out = append(out, a)
		}
	}
	return out, nil
}
func (f *fakeAlertStore) Get(_ context.Context, id int64, h string) (Alert, bool, error) {
	a, ok := f.rows[id]
	if !ok || a.UserHash != h {
		return Alert{}, false, nil
	}
	return a, true, nil
}
func (f *fakeAlertStore) Update(_ context.Context, a Alert) (bool, error) {
	cur, ok := f.rows[a.ID]
	if !ok || cur.UserHash != a.UserHash {
		return false, nil
	}
	a.Status = cur.Status
	f.rows[a.ID] = a
	return true, nil
}
func (f *fakeAlertStore) SetStatus(_ context.Context, id int64, h string, st Status) (bool, error) {
	a, ok := f.rows[id]
	if !ok || a.UserHash != h {
		return false, nil
	}
	a.Status = st
	if st == StatusActive {
		a.AboveArmed, a.BelowArmed, a.LastError = true, true, ""
	}
	f.rows[id] = a
	return true, nil
}
func (f *fakeAlertStore) Delete(_ context.Context, id int64, h string) (bool, error) {
	a, ok := f.rows[id]
	if !ok || a.UserHash != h {
		return false, nil
	}
	delete(f.rows, id)
	return true, nil
}
func (f *fakeAlertStore) LastEvents(context.Context, []int64) (map[int64]Event, error) {
	return map[int64]Event{}, nil
}

const testUnverifiedMsg = "verify your email to use alerts"

// testCaller names a caller for testIdentity: an email and a tier, where
// Legacy carries the page flag and an allowance of 2.
func testCaller(email, tier string) string { return email + "|" + tier }

// testHash stands in for the hashed email a real Identity returns.
func testHash(email string) string { return "hash:" + email }

// testIdentity reads the caller off X-Test-Caller in place of a signature.
func testIdentity(r *http.Request) (Caller, int, string) {
	h := r.Header.Get("X-Test-Caller")
	switch h {
	case "":
		return Caller{}, http.StatusUnauthorized, "not signed in"
	case "unverified":
		return Caller{}, http.StatusForbidden, testUnverifiedMsg
	}
	email, tier, _ := strings.Cut(h, "|")
	v := url.Values{"UserTier": {tier}}
	if tier == "Legacy" {
		v.Set("Alerts", "true")
		v.Set("AlertsMax", "2")
	}
	return Caller{UserHash: testHash(email), Tier: tier, Values: v, Origin: r.Header.Get("X-Test-Origin")}, http.StatusOK, ""
}

func testAlertsAPI(store APIStore) *API {
	return NewAPI(APIDeps{
		Store:     store,
		Identity:  testIdentity,
		Allowance: alertsMaxAllowance,
		Prices: func(cardID string, side Side, _ url.Values) []StorePrice {
			if cardID != "card-1" {
				return nil
			}
			return []StorePrice{{Shorthand: "CK", Name: "Card Kingdom", Prices: map[string]float64{"NM": 12}}}
		},
		Resolve: func(cardID string) (Card, bool, bool) {
			switch cardID {
			case "card-1":
				return Card{Name: "Bolt", Set: "LEA", Number: "161", Finish: "nonfoil"}, false, true
			case "sealed-1":
				return Card{Name: "Sealed Box", Set: "LEA", Number: "0", Finish: "nonfoil"}, true, true
			default:
				return Card{}, false, false
			}
		},
		Game: func() string { return "magic" },
	})
}

func alertsRequest(method, path, body, caller string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if caller != "" {
		r.Header.Set("X-Test-Caller", caller)
	}
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestAlertsAPIAuthAndTier(t *testing.T) {
	api := testAlertsAPI(newFakeAlertStore())
	w := httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("GET", "/api/alerts/", "", ""))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned = %d", w.Code)
	}

	// An unverified email is refused outright, whatever the tier.
	unverified := "unverified"
	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("GET", "/api/alerts/", "", unverified))
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), testUnverifiedMsg) {
		t.Fatalf("unverified = %d %s", w.Code, w.Body)
	}

	// A tier with no allowance still lists (and could delete) its rows.
	sig := testCaller("a@b.com", "Pioneer")
	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("GET", "/api/alerts/", "", sig))
	if w.Code != http.StatusOK {
		t.Fatalf("list without allowance = %d %s", w.Code, w.Body)
	}
	var list []View
	err := json.Unmarshal(w.Body.Bytes(), &list)
	if err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("list without allowance = %+v", list)
	}

	// Creating still needs the allowance.
	body := `{"card_id":"card-1","side":"buylist","condition":"NM","above":{"kind":"abs","value":15},"delivery":"discord"}`
	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/", body, sig))
	if w.Code != http.StatusForbidden {
		t.Fatalf("create without allowance = %d", w.Code)
	}
}

func TestAlertsAPIPauseAndDeleteWithoutAllowance(t *testing.T) {
	store := newFakeAlertStore()
	api := testAlertsAPI(store)
	h := testHash("a@b.com")
	store.rows[1] = Alert{ID: 1, UserHash: h, Game: "magic", CardID: "card-1", Status: StatusActive}
	sig := testCaller("a@b.com", "Pioneer")

	w := httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("PATCH", "/api/alerts/1", `{"status":"paused"}`, sig))
	if w.Code != http.StatusOK || store.rows[1].Status != StatusPaused {
		t.Fatalf("pause without allowance = %d %s", w.Code, w.Body)
	}

	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("DELETE", "/api/alerts/1", "", sig))
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete without allowance = %d %s", w.Code, w.Body)
	}
	_, ok := store.rows[1]
	if ok {
		t.Fatal("row survived delete")
	}
}

// TestAlertsAPIStatusFollowsThePage allows the moves the page offers, pause
// on an active alert and resume on a paused or undeliverable one, and
// refuses the rest: a parked alert resumed would be parked and DMed again.
func TestAlertsAPIStatusFollowsThePage(t *testing.T) {
	for _, tt := range []struct {
		from, to Status
		want     int
	}{
		{StatusActive, StatusPaused, http.StatusOK},
		{StatusPaused, StatusActive, http.StatusOK},
		{StatusUndeliverable, StatusActive, http.StatusOK},
		{StatusPaused, StatusPaused, http.StatusOK},
		{StatusOverAllowance, StatusActive, http.StatusConflict},
		{StatusOverAllowance, StatusPaused, http.StatusConflict},
		{StatusUnresolvable, StatusActive, http.StatusOK},
		{StatusUnresolvable, StatusPaused, http.StatusConflict},
	} {
		store := newFakeAlertStore()
		api := testAlertsAPI(store)
		hash := testHash("a@b.com")
		store.contacts[hash] = Contact{UserHash: hash, DiscordUserID: "1", Tier: "Legacy"}
		store.rows[1] = Alert{ID: 1, UserHash: hash, Game: "magic", CardID: "card-1", Status: tt.from}
		w := httptest.NewRecorder()
		api.ServeHTTP(w, alertsRequest("PATCH", "/api/alerts/1", `{"status":"`+string(tt.to)+`"}`, testCaller("a@b.com", "Legacy")))
		if w.Code != tt.want {
			t.Errorf("%s to %s = %d %s, want %d", tt.from, tt.to, w.Code, w.Body, tt.want)
		}
		if tt.want == http.StatusConflict && store.rows[1].Status != tt.from {
			t.Errorf("%s to %s: refused, yet the row is now %s", tt.from, tt.to, store.rows[1].Status)
		}
	}
}

func TestAlertsAPIPatchNeedsAllowanceToEditOrResume(t *testing.T) {
	store := newFakeAlertStore()
	api := testAlertsAPI(store)
	hash := testHash("a@b.com")
	store.contacts[hash] = Contact{UserHash: hash, DiscordUserID: "1", Tier: "Legacy"}
	store.rows[1] = Alert{ID: 1, UserHash: hash, Game: "magic", CardID: "card-1", Side: SideBuylist, Condition: "NM",
		ReferencePrice: 10, Above: Threshold{Kind: KindAbs, Value: 15}, Status: StatusPaused}
	store.nextID = 1
	lapsed := testCaller("a@b.com", "Pioneer")

	for _, body := range []string{`{"status":"active"}`, `{"above":{"kind":"abs","value":20}}`} {
		w := httptest.NewRecorder()
		api.ServeHTTP(w, alertsRequest("PATCH", "/api/alerts/1", body, lapsed))
		if w.Code != http.StatusForbidden {
			t.Fatalf("lapsed patch %s = %d %s", body, w.Code, w.Body)
		}
	}
	// Pausing and deleting stay open to a lapsed tier.
	store.rows[1] = func(a Alert) Alert { a.Status = StatusActive; return a }(store.rows[1])
	w := httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("PATCH", "/api/alerts/1", `{"status":"paused"}`, lapsed))
	if w.Code != http.StatusOK {
		t.Fatalf("lapsed pause = %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("DELETE", "/api/alerts/1", "", lapsed))
	if w.Code != http.StatusNoContent {
		t.Fatalf("lapsed delete = %d %s", w.Code, w.Body)
	}
}

func TestAlertsAPICSRF(t *testing.T) {
	api := testAlertsAPI(newFakeAlertStore())
	sig := testCaller("a@b.com", "Legacy")

	r := alertsRequest("POST", "/api/alerts/", "{}", sig)
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	api.ServeHTTP(w, r)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain body = %d, want 415", w.Code)
	}

	r = alertsRequest("POST", "/api/alerts/", "{}", sig)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w = httptest.NewRecorder()
	api.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-site POST = %d, want 403", w.Code)
	}

	r = alertsRequest("PATCH", "/api/alerts/1", "{}", sig)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w = httptest.NewRecorder()
	api.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-site PATCH = %d, want 403", w.Code)
	}

	r = alertsRequest("DELETE", "/api/alerts/1", "", sig)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w = httptest.NewRecorder()
	api.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-site DELETE = %d, want 403", w.Code)
	}
}

func TestAlertsAPICreateListEditDelete(t *testing.T) {
	store := newFakeAlertStore()
	api := testAlertsAPI(store)
	sig := testCaller("a@b.com", "Legacy")
	hash := testHash("a@b.com")
	store.contacts[hash] = Contact{UserHash: hash, DiscordUserID: "1", Tier: "Legacy"}

	body := `{"card_id":"card-1","side":"buylist","condition":"NM","stores":["ck"],"above":{"kind":"abs","value":15},"below":{"kind":"abs","value":5},"delivery":"discord"}`
	w := httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/", body, sig))
	if w.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}
	var created View
	err := json.Unmarshal(w.Body.Bytes(), &created)
	if err != nil {
		t.Fatalf("decode created: %v", err)
	}
	if created.ReferencePrice != 12 || created.Card.Name != "Bolt" || created.Stores[0] != "CK" || *created.CreatedPrice != 12 {
		t.Fatalf("created = %+v", created)
	}

	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("GET", "/api/alerts/", "", sig))
	var list []View
	err = json.Unmarshal(w.Body.Bytes(), &list)
	if err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list) != 1 || list[0].Current == nil || *list[0].Current != 12 || list[0].CurrentStore != "CK" {
		t.Fatalf("list = %+v", list)
	}

	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("PATCH", "/api/alerts/1", `{"status":"paused"}`, sig))
	if w.Code != http.StatusOK || store.rows[1].Status != StatusPaused {
		t.Fatalf("pause = %d status=%s", w.Code, store.rows[1].Status)
	}

	// Simulate a fired alert, then resume: both sides re-arm and the error clears.
	fired := store.rows[1]
	fired.AboveArmed, fired.BelowArmed, fired.LastError = false, false, "boom"
	store.rows[1] = fired
	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("PATCH", "/api/alerts/1", `{"status":"active"}`, sig))
	if w.Code != http.StatusOK || store.rows[1].Status != StatusActive ||
		!store.rows[1].AboveArmed || !store.rows[1].BelowArmed || store.rows[1].LastError != "" {
		t.Fatalf("resume = %d row=%+v", w.Code, store.rows[1])
	}

	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("PATCH", "/api/alerts/1", `{"above":{"kind":"pct","value":30}}`, sig))
	if w.Code != http.StatusOK || store.rows[1].Above.Kind != KindPct ||
		store.rows[1].Below.Kind != KindAbs || store.rows[1].Below.Value != 5 {
		t.Fatalf("edit = %d %s", w.Code, w.Body)
	}

	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("PATCH", "/api/alerts/1", `{"below":{}}`, sig))
	if w.Code != http.StatusOK || store.rows[1].Below.Set() || store.rows[1].Above.Kind != KindPct {
		t.Fatalf("clear below = %d %s", w.Code, w.Body)
	}

	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("PATCH", "/api/alerts/1", `{"above":{},"below":{}}`, sig))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("clear both = %d %s", w.Code, w.Body)
	}

	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("DELETE", "/api/alerts/1", "", testCaller("x@y.com", "Legacy")))
	if w.Code != http.StatusNotFound {
		t.Fatalf("delete by another user = %d", w.Code)
	}
	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("DELETE", "/api/alerts/1", "", sig))
	if w.Code != http.StatusNoContent || len(store.rows) != 0 {
		t.Fatalf("delete = %d rows=%d", w.Code, len(store.rows))
	}
}

func TestAlertsAPIArmsOnlyTheSidesNotYetPast(t *testing.T) {
	store := newFakeAlertStore()
	api := testAlertsAPI(store)
	sig := testCaller("a@b.com", "Legacy")
	hash := testHash("a@b.com")
	store.contacts[hash] = Contact{UserHash: hash, DiscordUserID: "1", Tier: "Legacy"}

	// Bought at 20, best offer now 12: "below 20%" (16) is already past.
	body := `{"card_id":"card-1","side":"buylist","condition":"NM","reference_price":20,"above":{"kind":"abs","value":25},"below":{"kind":"pct","value":20},"delivery":"discord"}`
	w := httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/", body, sig))
	if w.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}
	if !store.rows[1].AboveArmed || store.rows[1].BelowArmed {
		t.Fatalf("create armed above=%v below=%v, want true false", store.rows[1].AboveArmed, store.rows[1].BelowArmed)
	}

	// Moving the line under the best offer arms it again.
	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("PATCH", "/api/alerts/1", `{"below":{"kind":"abs","value":10}}`, sig))
	if w.Code != http.StatusOK || !store.rows[1].BelowArmed {
		t.Fatalf("edit = %d below armed=%v, want 200 true", w.Code, store.rows[1].BelowArmed)
	}
}

func TestAlertsAPISavesTheOrigin(t *testing.T) {
	store := newFakeAlertStore()
	api := testAlertsAPI(store)
	sig := testCaller("a@b.com", "Legacy")
	hash := testHash("a@b.com")
	store.contacts[hash] = Contact{UserHash: hash, DiscordUserID: "1", Tier: "Legacy"}
	from := func(r *http.Request, origin string) *http.Request {
		r.Header.Set("X-Test-Origin", origin)
		return r
	}

	body := `{"card_id":"card-1","side":"buylist","condition":"NM","above":{"kind":"abs","value":15},"delivery":"discord"}`
	w := httptest.NewRecorder()
	api.ServeHTTP(w, from(alertsRequest("POST", "/api/alerts/", body, sig), "https://lorcana.mtgban.com"))
	if w.Code != http.StatusCreated || store.rows[1].Origin != "https://lorcana.mtgban.com" {
		t.Fatalf("create = %d origin=%q", w.Code, store.rows[1].Origin)
	}
	w = httptest.NewRecorder()
	api.ServeHTTP(w, from(alertsRequest("PATCH", "/api/alerts/1", `{"above":{"kind":"abs","value":16}}`, sig), "https://mtgban.com"))
	if w.Code != http.StatusOK || store.rows[1].Origin != "https://mtgban.com" {
		t.Fatalf("edit = %d origin=%q, want the site it was saved on", w.Code, store.rows[1].Origin)
	}
	// A request from a host the site does not trust keeps the saved one.
	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("PATCH", "/api/alerts/1", `{"above":{"kind":"abs","value":17}}`, sig))
	if w.Code != http.StatusOK || store.rows[1].Origin != "https://mtgban.com" {
		t.Fatalf("edit without origin = %d origin=%q", w.Code, store.rows[1].Origin)
	}
}

func TestAlertsAPIRefusals(t *testing.T) {
	store := newFakeAlertStore()
	api := testAlertsAPI(store)
	sig := testCaller("a@b.com", "Legacy")
	hash := testHash("a@b.com")
	store.contacts[hash] = Contact{UserHash: hash, Tier: "Legacy"}

	cases := []struct {
		name string
		body string
		want int
	}{
		{"no discord", `{"card_id":"card-1","side":"buylist","condition":"NM","above":{"kind":"abs","value":15},"delivery":"discord"}`, 422},
		{"unknown card", `{"card_id":"nope","side":"buylist","condition":"NM","above":{"kind":"abs","value":15},"delivery":"discord"}`, 422},
		{"invisible store", `{"card_id":"card-1","side":"buylist","condition":"NM","stores":["SCG"],"above":{"kind":"abs","value":15},"delivery":"discord"}`, 422},
		{"no threshold", `{"card_id":"card-1","side":"buylist","condition":"NM","delivery":"discord"}`, 422},
		{"email delivery", `{"card_id":"card-1","side":"buylist","condition":"NM","above":{"kind":"abs","value":15},"delivery":"email"}`, 422},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/", tc.body, sig))
			if w.Code != tc.want {
				t.Fatalf("code = %d, want %d: %s", w.Code, tc.want, w.Body)
			}
		})
	}

	// Link Discord, then hit the allowance of 2.
	store.contacts[hash] = Contact{UserHash: hash, DiscordUserID: "1", Tier: "Legacy"}
	ok := `{"card_id":"card-1","side":"buylist","condition":"NM","above":{"kind":"abs","value":15},"delivery":"discord"}`
	for i, v := range []string{`"value":15`, `"value":16`} {
		w := httptest.NewRecorder()
		api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/", strings.Replace(ok, `"value":15`, v, 1), sig))
		if w.Code != http.StatusCreated {
			t.Fatalf("create %d = %d %s", i, w.Code, w.Body)
		}
	}
	w := httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/", strings.Replace(ok, `"value":15`, `"value":17`, 1), sig))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "allowance") {
		t.Fatalf("over allowance = %d %s", w.Code, w.Body)
	}
}

func TestAlertsAPIPatchKeepsSealedCondition(t *testing.T) {
	store := newFakeAlertStore()
	api := testAlertsAPI(store)
	sig := testCaller("a@b.com", "Legacy")
	hash := testHash("a@b.com")
	store.contacts[hash] = Contact{UserHash: hash, DiscordUserID: "1", Tier: "Legacy"}

	body := `{"card_id":"sealed-1","side":"buylist","condition":"SP","above":{"kind":"abs","value":60},"delivery":"discord","reference_price":50}`
	w := httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/", body, sig))
	if w.Code != http.StatusCreated || store.rows[1].Condition != "NM" {
		t.Fatalf("create sealed = %d condition=%s", w.Code, store.rows[1].Condition)
	}

	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("PATCH", "/api/alerts/1", `{"condition":"SP"}`, sig))
	if w.Code != http.StatusOK || store.rows[1].Condition != "NM" {
		t.Fatalf("patch sealed condition = %d condition=%s", w.Code, store.rows[1].Condition)
	}
}

func TestAlertsAPIOptions(t *testing.T) {
	store := newFakeAlertStore()
	api := testAlertsAPI(store)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("GET", "/api/alerts/options?card=card-1&side=buylist", "", testCaller("a@b.com", "Legacy")))
	if w.Code != http.StatusOK {
		t.Fatalf("options = %d %s", w.Code, w.Body)
	}
	var opts Options
	err := json.Unmarshal(w.Body.Bytes(), &opts)
	if err != nil {
		t.Fatalf("decode options: %v", err)
	}
	if len(opts.Stores) != 1 || opts.DiscordLinked || len(opts.Conditions) != 5 {
		t.Fatalf("options = %+v", opts)
	}
}

func TestAlertsAPIOptionsKeepsGoneStore(t *testing.T) {
	store := newFakeAlertStore()
	api := testAlertsAPI(store)
	opts, status, msg := api.OptionsFor(context.Background(), Caller{UserHash: "hash-1", Tier: "Legacy", Values: url.Values{"Alerts": {"true"}, "AlertsMax": {"2"}}}, "card-1", SideBuylist, []string{"GONE"})
	if status != http.StatusOK {
		t.Fatalf("OptionsFor = %d %s", status, msg)
	}
	i := slices.IndexFunc(opts.Stores, func(p StorePrice) bool { return p.Shorthand == "GONE" })
	if i < 0 {
		t.Fatalf("kept store missing from options: %+v", opts.Stores)
	}
	if len(opts.Stores[i].Prices) != 0 {
		t.Fatalf("kept store should have no prices: %+v", opts.Stores[i])
	}
	if len(opts.Stores) != 2 {
		t.Fatalf("expected the priced store plus the kept one, got %+v", opts.Stores)
	}
}

func TestAlertsAPIPatchStatusMustBeAlone(t *testing.T) {
	store := newFakeAlertStore()
	api := testAlertsAPI(store)
	sig := testCaller("a@b.com", "Legacy")
	hash := testHash("a@b.com")
	store.contacts[hash] = Contact{UserHash: hash, DiscordUserID: "1", Tier: "Legacy"}

	body := `{"card_id":"card-1","side":"buylist","condition":"NM","above":{"kind":"abs","value":15},"delivery":"discord"}`
	w := httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/", body, sig))
	if w.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}

	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("PATCH", "/api/alerts/1", `{"status":"paused","above":{"kind":"abs","value":20}}`, sig))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("mixed status patch = %d, want 422: %s", w.Code, w.Body)
	}
}

// writeFailsStore wraps a fakeAlertStore whose Update and SetStatus always
// report not found, simulating a row that vanished between Get and write.
type writeFailsStore struct{ *fakeAlertStore }

func (s writeFailsStore) Update(context.Context, Alert) (bool, error) { return false, nil }
func (s writeFailsStore) SetStatus(context.Context, int64, string, Status) (bool, error) {
	return false, nil
}

func TestAlertsAPIPatchNotFoundOnWrite(t *testing.T) {
	store := newFakeAlertStore()
	api := testAlertsAPI(store)
	sig := testCaller("a@b.com", "Legacy")
	hash := testHash("a@b.com")
	store.contacts[hash] = Contact{UserHash: hash, DiscordUserID: "1", Tier: "Legacy"}

	body := `{"card_id":"card-1","side":"buylist","condition":"NM","above":{"kind":"abs","value":15},"delivery":"discord"}`
	w := httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/", body, sig))
	if w.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}
	api.deps.Store = writeFailsStore{store}

	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("PATCH", "/api/alerts/1", `{"status":"paused"}`, sig))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status write race = %d, want 404: %s", w.Code, w.Body)
	}

	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("PATCH", "/api/alerts/1", `{"above":{"kind":"abs","value":25}}`, sig))
	if w.Code != http.StatusNotFound {
		t.Fatalf("update write race = %d, want 404: %s", w.Code, w.Body)
	}
}

func TestAlertsAPIPatchKeepsUnpricedStore(t *testing.T) {
	store := newFakeAlertStore()
	api := testAlertsAPI(store)
	sig := testCaller("a@b.com", "Legacy")
	hash := testHash("a@b.com")
	store.contacts[hash] = Contact{UserHash: hash, DiscordUserID: "1", Tier: "Legacy"}

	body := `{"card_id":"card-1","side":"buylist","condition":"NM","stores":["ck"],"above":{"kind":"abs","value":15},"delivery":"discord"}`
	w := httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/", body, sig))
	if w.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}

	// Manually scope the row to a store the fake prices() never returns,
	// as if it had stopped offering the card by the time of the edit.
	row := store.rows[1]
	row.Stores = []string{"GONE"}
	store.rows[1] = row

	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("PATCH", "/api/alerts/1", `{"stores":["GONE"]}`, sig))
	if w.Code != http.StatusOK {
		t.Fatalf("patch resubmitting an unpriced store = %d %s", w.Code, w.Body)
	}
	if len(store.rows[1].Stores) != 1 || store.rows[1].Stores[0] != "GONE" {
		t.Fatalf("unpriced store was dropped: %+v", store.rows[1].Stores)
	}
}

// The edit dialog asks options to keep an alert's own stores even when
// nothing prices them, so the boxes render checked.
func TestAlertsAPIOptionsKeepParam(t *testing.T) {
	api := testAlertsAPI(newFakeAlertStore())
	w := httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("GET", "/api/alerts/options?card=card-1&side=buylist&keep=GONE,ck", "", testCaller("a@b.com", "Legacy")))
	if w.Code != http.StatusOK {
		t.Fatalf("options = %d %s", w.Code, w.Body)
	}
	var opts Options
	err := json.Unmarshal(w.Body.Bytes(), &opts)
	if err != nil {
		t.Fatal(err)
	}
	var gone bool
	for _, s := range opts.Stores {
		if s.Shorthand == "GONE" && len(s.Prices) == 0 {
			gone = true
		}
	}
	if !gone || len(opts.Stores) != 2 {
		t.Fatalf("stores = %+v, want CK plus an unpriced GONE", opts.Stores)
	}
}

func TestAlertsAPICreateRejectsDuplicate(t *testing.T) {
	store := newFakeAlertStore()
	api := testAlertsAPI(store)
	sig := testCaller("a@b.com", "Legacy")
	hash := testHash("a@b.com")
	store.contacts[hash] = Contact{UserHash: hash, DiscordUserID: "1", Tier: "Legacy"}

	body := `{"card_id":"card-1","side":"buylist","condition":"NM","stores":["ck"],"above":{"kind":"abs","value":15},"delivery":"discord"}`
	w := httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/", body, sig))
	if w.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}

	// The same card, side, condition, stores and thresholds again is refused, naming the first.
	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/", body, sig))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"alert_id":1`) {
		t.Fatalf("duplicate = %d %s", w.Code, w.Body)
	}

	// So is one that matches once rounded to cents.
	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/", strings.Replace(body, `"value":15`, `"value":15.004`, 1), sig))
	if w.Code != http.StatusConflict {
		t.Fatalf("rounded duplicate = %d %s", w.Code, w.Body)
	}

	// Any one of those differing makes it a new alert.
	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/", strings.Replace(body, `"value":15`, `"value":16`, 1), sig))
	if w.Code != http.StatusCreated || len(store.rows) != 2 {
		t.Fatalf("variant = %d %s rows=%d", w.Code, w.Body, len(store.rows))
	}
}

// With no store, the API still refuses an unsigned caller first, then
// answers 503; a nil Service's API answers 503 to everyone.
func TestAlertsAPIUnavailable(t *testing.T) {
	s := NewService(nil, EvalDeps{}, APIDeps{Identity: testIdentity, Allowance: alertsMaxAllowance})
	if s.API().Store() != nil {
		t.Fatal("a nil *Store became a non-nil APIStore")
	}
	// NewAPI must not start a limiter janitor goroutine for an API that
	// will only ever answer 503.
	if s.API().deps.ConfirmLimiter != nil {
		t.Fatal("a nil store got a confirm limiter")
	}
	w := httptest.NewRecorder()
	s.API().ServeHTTP(w, alertsRequest("GET", "/api/alerts/", "", ""))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned = %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.API().ServeHTTP(w, alertsRequest("GET", "/api/alerts/", "", testCaller("a@b.com", "Legacy")))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("no store = %d %s", w.Code, w.Body)
	}

	var nilService *Service
	w = httptest.NewRecorder()
	nilService.API().ServeHTTP(w, alertsRequest("GET", "/api/alerts/", "", testCaller("a@b.com", "Legacy")))
	if w.Code != http.StatusServiceUnavailable || nilService.API().Store() != nil {
		t.Fatalf("nil service = %d %s", w.Code, w.Body)
	}
}

func TestServiceAPIDefaultsToItsStore(t *testing.T) {
	store := &Store{}
	got := NewService(store, EvalDeps{}, APIDeps{}).API().Store()
	if got != APIStore(store) {
		t.Fatalf("API store = %v, want the service's", got)
	}
}

// SetStore attaches a store after construction, the way the site does once
// its databases open, and detaching it leaves an untyped nil behind.
func TestServiceSetStore(t *testing.T) {
	s := NewService(nil, EvalDeps{}, APIDeps{})
	store := &Store{}
	s.SetStore(store)
	if s.Store() != store || s.API().Store() != APIStore(store) || s.deps.Store != EvalStore(store) || s.unavailable() {
		t.Fatalf("attached: store=%v api=%v eval=%v", s.Store(), s.API().Store(), s.deps.Store)
	}
	s.SetStore(nil)
	if s.Store() != nil || s.API().Store() != nil || s.deps.Store != nil || !s.unavailable() {
		t.Fatalf("detached: store=%v api=%v eval=%v", s.Store(), s.API().Store(), s.deps.Store)
	}
	var nilService *Service
	if nilService.Store() != nil {
		t.Fatal("nil service has a store")
	}
}

var testTokenSecret = []byte("test-secret")

const testOrigin = "https://mtgban.com"

type sentConfirm struct{ to, link string }

// testChannelAPI is testAlertsAPI with email allowed on Legacy and a
// confirm mailer recording what it sends; fail makes every send fail.
func testChannelAPI(store APIStore, sent *[]sentConfirm, fail *bool) *API {
	api := testAlertsAPI(store)
	api.deps.Channels = func(v url.Values) []ChannelKind {
		if v.Get("UserTier") == "Legacy" {
			return []ChannelKind{ChannelDiscord, ChannelEmail}
		}
		return []ChannelKind{ChannelDiscord}
	}
	api.deps.Mint = func(t Token) string { return MintToken(testTokenSecret, t) }
	api.deps.SendConfirm = func(_ context.Context, to, link string) error {
		if fail != nil && *fail {
			return errors.New("mail down")
		}
		*sent = append(*sent, sentConfirm{to, link})
		return nil
	}
	return api
}

// channelRequest is alertsRequest from the trusted test origin.
func channelRequest(method, path, body, caller string) *http.Request {
	r := alertsRequest(method, path, body, caller)
	r.Header.Set("X-Test-Origin", testOrigin)
	return r
}

func TestAlertsAPIDeliveryChannel(t *testing.T) {
	store := newFakeAlertStore()
	sent := []sentConfirm{}
	api := testChannelAPI(store, &sent, nil)
	hash := testHash("a@b.com")
	legacy, pioneer := testCaller("a@b.com", "Legacy"), testCaller("a@b.com", "Pioneer")
	email := `{"card_id":"card-1","side":"buylist","condition":"NM","above":{"kind":"abs","value":15},"delivery":"email"}`

	// No confirmed address yet.
	w := httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/", email, legacy))
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "confirm an email address first") {
		t.Fatalf("no channel = %d %s", w.Code, w.Body)
	}
	// A pending address is not enough.
	store.channels[channelKey{hash, ChannelEmail, SourceUser}] = Channel{UserHash: hash, Kind: ChannelEmail, Address: "x@y.com", Source: SourceUser}
	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/", email, legacy))
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "confirm an email address first") {
		t.Fatalf("pending channel = %d %s", w.Code, w.Body)
	}

	now := time.Now()
	store.channels[channelKey{hash, ChannelEmail, SourceUser}] = Channel{UserHash: hash, Kind: ChannelEmail, Address: "x@y.com", Source: SourceUser, VerifiedAt: &now}
	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/", email, legacy))
	if w.Code != http.StatusCreated || store.rows[1].Delivery != DeliveryEmail {
		t.Fatalf("verified channel = %d %s", w.Code, w.Body)
	}

	// The allowance still comes first.
	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/", strings.Replace(email, `"value":15`, `"value":16`, 1), pioneer))
	if w.Code != http.StatusForbidden {
		t.Fatalf("pioneer has no allowance = %d %s", w.Code, w.Body)
	}
	api.deps.Channels = func(url.Values) []ChannelKind { return []ChannelKind{ChannelDiscord} }
	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/", strings.Replace(email, `"value":15`, `"value":16`, 1), legacy))
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "channel not available on your tier") {
		t.Fatalf("tier without email = %d %s", w.Code, w.Body)
	}

	// Discord keeps its message on create and now on patch too.
	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("PATCH", "/api/alerts/1", `{"delivery":"discord"}`, legacy))
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "link Discord") {
		t.Fatalf("patch to unlinked discord = %d %s", w.Code, w.Body)
	}
	store.contacts[hash] = Contact{UserHash: hash, DiscordUserID: "1", Tier: "Legacy"}
	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("PATCH", "/api/alerts/1", `{"delivery":"discord"}`, legacy))
	if w.Code != http.StatusOK || store.rows[1].Delivery != DeliveryDiscord {
		t.Fatalf("patch to discord = %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("PATCH", "/api/alerts/1", `{"delivery":"email"}`, legacy))
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "channel not available on your tier") {
		t.Fatalf("patch to email without tier = %d %s", w.Code, w.Body)
	}

	// An empty delivery on create is discord.
	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/", strings.Replace(strings.Replace(email, `,"delivery":"email"`, "", 1), `"value":15`, `"value":17`, 1), legacy))
	if w.Code != http.StatusCreated || store.rows[2].Delivery != DeliveryDiscord {
		t.Fatalf("default delivery = %d %s", w.Code, w.Body)
	}

	// Back on a tier with email, a patch to it needs the address active.
	api = testChannelAPI(store, &sent, nil)
	store.channels[channelKey{hash, ChannelEmail, SourceUser}] = Channel{UserHash: hash, Kind: ChannelEmail, Address: "x@y.com", Source: SourceUser, VerifiedAt: &now, DisabledAt: &now}
	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("PATCH", "/api/alerts/2", `{"delivery":"email"}`, legacy))
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "confirm an email address first") {
		t.Fatalf("patch to disabled email = %d %s", w.Code, w.Body)
	}
	store.channels[channelKey{hash, ChannelEmail, SourceUser}] = Channel{UserHash: hash, Kind: ChannelEmail, Address: "x@y.com", Source: SourceUser, VerifiedAt: &now}
	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("PATCH", "/api/alerts/2", `{"delivery":"email"}`, legacy))
	if w.Code != http.StatusOK || store.rows[2].Delivery != DeliveryEmail {
		t.Fatalf("patch to email = %d %s", w.Code, w.Body)
	}
}

func TestAlertsAPISetEmail(t *testing.T) {
	store := newFakeAlertStore()
	sent := []sentConfirm{}
	api := testChannelAPI(store, &sent, nil)
	sig := testCaller("a@b.com", "Legacy")
	hash := testHash("a@b.com")

	for _, bad := range []string{"", "nope", "a@", "Bob <bob@example.com>", "<bob@example.com>", "a@b.com\r\nBcc: c@d.com", "a|b@example.com", strings.Repeat("a", 250) + "@b.com"} {
		body, _ := json.Marshal(map[string]string{"address": bad})
		w := httptest.NewRecorder()
		api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email", string(body), sig))
		if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "enter a valid email address") {
			t.Fatalf("address %q = %d %s", bad, w.Code, w.Body)
		}
	}
	if len(store.channels) != 0 || len(sent) != 0 {
		t.Fatalf("bad addresses stored %v sent %v", store.channels, sent)
	}

	w := httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email", `{"address":"  Me@Example.COM "}`, sig))
	if w.Code != http.StatusAccepted {
		t.Fatalf("good address = %d %s", w.Code, w.Body)
	}
	var got struct{ State, Address string }
	err := json.Unmarshal(w.Body.Bytes(), &got)
	if err != nil || got.State != "pending" || got.Address != "me@example.com" {
		t.Fatalf("body = %s (%v)", w.Body, err)
	}
	if c, ok := store.contacts[hash]; !ok || c.Tier != "Legacy" {
		t.Fatalf("no contact behind the new channel row: %+v", store.contacts)
	}
	row, ok := store.channels[channelKey{hash, ChannelEmail, SourceUser}]
	if !ok || row.Address != "me@example.com" || row.VerifiedAt != nil {
		t.Fatalf("row = %+v ok=%v", row, ok)
	}
	if len(sent) != 1 || sent[0].to != "me@example.com" || !strings.HasPrefix(sent[0].link, testOrigin+"/alerts/confirm?token=") {
		t.Fatalf("sent = %+v", sent)
	}
	u, err := url.Parse(sent[0].link)
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	tok, err := VerifyToken(testTokenSecret, u.Query().Get("token"), time.Now())
	if err != nil || tok.Kind != TokenConfirm || tok.UserHash != hash || tok.Address != "me@example.com" {
		t.Fatalf("token = %+v %v", tok, err)
	}
	if d := time.Until(tok.Expires); d < 23*time.Hour || d > 25*time.Hour {
		t.Fatalf("token expires in %v, want about a day", d)
	}

	// Three mails an hour; the fourth is refused, resend included.
	for i := 0; i < 2; i++ {
		w = httptest.NewRecorder()
		api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email", `{"address":"me@example.com"}`, sig))
		if w.Code != http.StatusAccepted {
			t.Fatalf("send %d = %d %s", i+2, w.Code, w.Body)
		}
	}
	w = httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email/resend", `{}`, sig))
	if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), "too many confirmation mails") {
		t.Fatalf("fourth = %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email", `{"address":"other@example.com"}`, sig))
	if w.Code != http.StatusTooManyRequests || len(sent) != 3 || store.channels[channelKey{hash, ChannelEmail, SourceUser}].Address != "me@example.com" {
		t.Fatalf("fifth = %d %s sent=%d", w.Code, w.Body, len(sent))
	}
	// Another user has a limit of their own.
	w = httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email", `{"address":"x@example.com"}`, testCaller("x@y.com", "Legacy")))
	if w.Code != http.StatusAccepted {
		t.Fatalf("other user = %d %s", w.Code, w.Body)
	}
}

func TestAlertsAPISetEmailRefusals(t *testing.T) {
	store := newFakeAlertStore()
	sent := []sentConfirm{}
	fail := false
	api := testChannelAPI(store, &sent, &fail)
	sig := testCaller("a@b.com", "Legacy")
	hash := testHash("a@b.com")
	body := `{"address":"me@example.com"}`

	// A tier without email cannot ask for confirmation mails.
	w := httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email", body, testCaller("a@b.com", "Pioneer")))
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "channel not available on your tier") {
		t.Fatalf("pioneer = %d %s", w.Code, w.Body)
	}
	// A link needs a trusted origin.
	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/channels/email", body, sig))
	if w.Code != http.StatusBadRequest || len(store.channels) != 0 {
		t.Fatalf("no origin = %d %s", w.Code, w.Body)
	}

	// A failed send keeps the row for a resend.
	fail = true
	w = httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email", body, sig))
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "could not send the confirmation mail") {
		t.Fatalf("send fails = %d %s", w.Code, w.Body)
	}
	if store.channels[channelKey{hash, ChannelEmail, SourceUser}].Address != "me@example.com" {
		t.Fatalf("row after failed send = %+v", store.channels)
	}
	fail = false
	w = httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email/resend", `{}`, sig))
	if w.Code != http.StatusAccepted || len(sent) != 1 || sent[0].to != "me@example.com" {
		t.Fatalf("resend = %d %s sent=%+v", w.Code, w.Body, sent)
	}

	// Re-entering a confirmed address sends nothing.
	now := time.Now()
	row := store.channels[channelKey{hash, ChannelEmail, SourceUser}]
	row.VerifiedAt = &now
	store.channels[channelKey{hash, ChannelEmail, SourceUser}] = row
	w = httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email", `{"address":"ME@example.com"}`, sig))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"verified"`) || len(sent) != 1 {
		t.Fatalf("same verified address = %d %s sent=%d", w.Code, w.Body, len(sent))
	}

	// Nothing to resend once verified, or with no row.
	w = httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email/resend", `{}`, sig))
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "no address to confirm") {
		t.Fatalf("resend verified = %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email/resend", `{}`, testCaller("x@y.com", "Legacy")))
	if w.Code != http.StatusNotFound {
		t.Fatalf("resend without row = %d %s", w.Code, w.Body)
	}
}

func TestAlertsAPIConfirmNotConfigured(t *testing.T) {
	sig := testCaller("a@b.com", "Legacy")
	for name, unset := range map[string]func(*API){
		"no mint": func(a *API) { a.deps.Mint = nil },
		"no send": func(a *API) { a.deps.SendConfirm = nil },
	} {
		t.Run(name, func(t *testing.T) {
			store := newFakeAlertStore()
			sent := []sentConfirm{}
			api := testChannelAPI(store, &sent, nil)
			unset(api)
			hash := testHash("a@b.com")
			store.channels[channelKey{hash, ChannelEmail, SourceUser}] = Channel{UserHash: hash, Kind: ChannelEmail, Address: "me@example.com", Source: SourceUser}
			for _, path := range []string{"/api/alerts/channels/email", "/api/alerts/channels/email/resend"} {
				w := httptest.NewRecorder()
				api.ServeHTTP(w, channelRequest("POST", path, `{"address":"me@example.com"}`, sig))
				if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "email confirmation not configured") {
					t.Fatalf("%s = %d %s", path, w.Code, w.Body)
				}
			}
		})
	}
}

func TestAlertsAPIListChannels(t *testing.T) {
	store := newFakeAlertStore()
	sent := []sentConfirm{}
	api := testChannelAPI(store, &sent, nil)
	sig := testCaller("a@b.com", "Legacy")
	hash := testHash("a@b.com")

	list := func() []map[string]any {
		t.Helper()
		w := httptest.NewRecorder()
		api.ServeHTTP(w, channelRequest("GET", "/api/alerts/channels", "", sig))
		if w.Code != http.StatusOK {
			t.Fatalf("list = %d %s", w.Code, w.Body)
		}
		var out []map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &out)
		if err != nil || out == nil {
			t.Fatalf("decode %s: %v", w.Body, err)
		}
		return out
	}
	if got := list(); len(got) != 0 {
		t.Fatalf("empty = %v", got)
	}

	// The legacy Discord id shows as a verified patreon row.
	store.contacts[hash] = Contact{UserHash: hash, DiscordUserID: "42", Tier: "Legacy"}
	got := list()
	if len(got) != 1 || got[0]["kind"] != "discord" || got[0]["address"] != "42" || got[0]["source"] != "patreon" || got[0]["state"] != "verified" {
		t.Fatalf("synthesized = %v", got)
	}

	now := time.Now()
	store.channels[channelKey{hash, ChannelDiscord, SourcePatreon}] = Channel{UserHash: hash, Kind: ChannelDiscord, Address: "42", Source: SourcePatreon, VerifiedAt: &now, DisabledAt: &now, DisabledReason: "blocked"}
	store.channels[channelKey{hash, ChannelEmail, SourcePatreon}] = Channel{UserHash: hash, Kind: ChannelEmail, Address: "Pat@Example.com", Source: SourcePatreon, VerifiedAt: &now}
	store.channels[channelKey{hash, ChannelEmail, SourceUser}] = Channel{UserHash: hash, Kind: ChannelEmail, Address: "me@example.com", Source: SourceUser}
	got = list()
	if len(got) != 3 {
		t.Fatalf("rows = %v", got)
	}
	want := []struct{ kind, source, address, state, reason string }{
		{"discord", "patreon", "42", "disabled", "blocked"},
		{"email", "patreon", "Pat@Example.com", "verified", ""},
		{"email", "user", "me@example.com", "pending", ""},
	}
	for i, wnt := range want {
		g := got[i]
		if g["kind"] != wnt.kind || g["source"] != wnt.source || g["address"] != wnt.address || g["state"] != wnt.state || g["reason"] != wnt.reason {
			t.Fatalf("row %d = %v, want %+v", i, g, wnt)
		}
		for _, key := range []string{"verified_at", "disabled_at"} {
			_, ok := g[key]
			if !ok {
				t.Fatalf("row %d lacks %s: %v", i, key, g)
			}
		}
	}
	if got[2]["verified_at"] != nil || got[1]["disabled_at"] != nil || got[0]["disabled_at"] == nil {
		t.Fatalf("timestamps = %v", got)
	}
}

func TestAlertsAPIDeleteAndEnableChannel(t *testing.T) {
	store := newFakeAlertStore()
	sent := []sentConfirm{}
	api := testChannelAPI(store, &sent, nil)
	sig := testCaller("a@b.com", "Legacy")
	hash := testHash("a@b.com")
	now := time.Now()
	store.channels[channelKey{hash, ChannelEmail, SourcePatreon}] = Channel{UserHash: hash, Kind: ChannelEmail, Address: "pat@example.com", Source: SourcePatreon, VerifiedAt: &now, DisabledAt: &now, DisabledReason: "unsubscribed"}
	store.channels[channelKey{hash, ChannelEmail, SourceUser}] = Channel{UserHash: hash, Kind: ChannelEmail, Address: "me@example.com", Source: SourceUser}

	w := httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("DELETE", "/api/alerts/channels/email", "", sig))
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete = %d %s", w.Code, w.Body)
	}
	_, userLeft := store.channels[channelKey{hash, ChannelEmail, SourceUser}]
	_, patreonLeft := store.channels[channelKey{hash, ChannelEmail, SourcePatreon}]
	if userLeft || !patreonLeft {
		t.Fatalf("after delete user=%v patreon=%v", userLeft, patreonLeft)
	}
	w = httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("DELETE", "/api/alerts/channels/email", "", sig))
	if w.Code != http.StatusNotFound {
		t.Fatalf("delete again = %d %s", w.Code, w.Body)
	}

	w = httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/enable", `{"kind":"sms"}`, sig))
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "unknown channel") {
		t.Fatalf("enable sms = %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/enable", `{"kind":"discord"}`, sig))
	if w.Code != http.StatusNotFound {
		t.Fatalf("enable without patreon row = %d %s", w.Code, w.Body)
	}
	// A complained address is never mailed again, Enable included.
	complained := store.channels[channelKey{hash, ChannelEmail, SourcePatreon}]
	complained.DisabledReason = ReasonComplained
	store.channels[channelKey{hash, ChannelEmail, SourcePatreon}] = complained
	w = httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/enable", `{"kind":"email"}`, sig))
	if w.Code != http.StatusUnprocessableEntity || store.channels[channelKey{hash, ChannelEmail, SourcePatreon}].DisabledAt == nil {
		t.Fatalf("enable complained = %d %s", w.Code, w.Body)
	}
	complained.DisabledReason = ReasonUnsubscribed
	store.channels[channelKey{hash, ChannelEmail, SourcePatreon}] = complained

	w = httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/enable", `{"kind":"email"}`, sig))
	row := store.channels[channelKey{hash, ChannelEmail, SourcePatreon}]
	if w.Code != http.StatusNoContent || row.DisabledAt != nil || row.DisabledReason != "" {
		t.Fatalf("enable = %d %s row=%+v", w.Code, w.Body, row)
	}

	w = httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("PATCH", "/api/alerts/channels/email", `{}`, sig))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("patch channel = %d %s", w.Code, w.Body)
	}
}

// A spam complaint on any user's row stops confirm mail to that address;
// a bounce does not, and both attempts are charged to the limiter.
func TestAlertsAPIConfirmComplainedAddress(t *testing.T) {
	store := newFakeAlertStore()
	sent := []sentConfirm{}
	api := testChannelAPI(store, &sent, nil)
	sig := testCaller("a@b.com", "Legacy")
	hash, other := testHash("a@b.com"), testHash("x@y.com")
	now := time.Now()
	store.channels[channelKey{other, ChannelEmail, SourceUser}] = Channel{UserHash: other, Kind: ChannelEmail, Address: "Victim@example.com", Source: SourceUser, DisabledAt: &now, DisabledReason: "complained"}

	w := httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email", `{"address":"victim@example.com"}`, sig))
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "this address cannot receive mail from us") {
		t.Fatalf("post complained = %d %s", w.Code, w.Body)
	}
	_, stored := store.channels[channelKey{hash, ChannelEmail, SourceUser}]
	if stored || len(sent) != 0 {
		t.Fatalf("complained address stored=%v sent=%d", stored, len(sent))
	}

	// The user's own pending row, complained after it was entered.
	store.channels[channelKey{hash, ChannelEmail, SourceUser}] = Channel{UserHash: hash, Kind: ChannelEmail, Address: "victim@example.com", Source: SourceUser, DisabledAt: &now, DisabledReason: "complained"}
	delete(store.channels, channelKey{other, ChannelEmail, SourceUser})
	w = httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email/resend", `{}`, sig))
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "this address cannot receive mail from us") || len(sent) != 0 {
		t.Fatalf("resend complained = %d %s sent=%d", w.Code, w.Body, len(sent))
	}

	// A bounced pending row can resend.
	store.channels[channelKey{hash, ChannelEmail, SourceUser}] = Channel{UserHash: hash, Kind: ChannelEmail, Address: "me@example.com", Source: SourceUser, DisabledAt: &now, DisabledReason: "bounced"}
	w = httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email/resend", `{}`, sig))
	if w.Code != http.StatusAccepted || len(sent) != 1 || sent[0].to != "me@example.com" {
		t.Fatalf("resend bounced = %d %s sent=%+v", w.Code, w.Body, sent)
	}

	// Two refusals and one send used the burst of three.
	w = httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email/resend", `{}`, sig))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("fourth = %d %s", w.Code, w.Body)
	}
}

// A verified address a bounce disabled can be confirmed again, by resend or by re-entering it.
func TestAlertsAPIResendBouncedVerified(t *testing.T) {
	store := newFakeAlertStore()
	sent := []sentConfirm{}
	api := testChannelAPI(store, &sent, nil)
	sig := testCaller("a@b.com", "Legacy")
	hash := testHash("a@b.com")
	now := time.Now()
	store.channels[channelKey{hash, ChannelEmail, SourceUser}] = Channel{UserHash: hash, Kind: ChannelEmail, Address: "me@example.com", Source: SourceUser, VerifiedAt: &now, DisabledAt: &now, DisabledReason: "bounced"}

	w := httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email/resend", `{}`, sig))
	if w.Code != http.StatusAccepted || len(sent) != 1 {
		t.Fatalf("resend = %d %s sent=%d", w.Code, w.Body, len(sent))
	}
	w = httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email", `{"address":"me@example.com"}`, sig))
	if w.Code != http.StatusAccepted || len(sent) != 2 {
		t.Fatalf("re-enter = %d %s sent=%d", w.Code, w.Body, len(sent))
	}
}

// Echoing the stored delivery is not a change, so an edit passes with the channel gone.
func TestAlertsAPIPatchUnchangedDelivery(t *testing.T) {
	store := newFakeAlertStore()
	sent := []sentConfirm{}
	api := testChannelAPI(store, &sent, nil)
	sig := testCaller("a@b.com", "Legacy")
	hash := testHash("a@b.com")
	store.rows[1] = Alert{ID: 1, UserHash: hash, Game: "magic", CardID: "card-1", Side: SideBuylist, Condition: "NM",
		ReferencePrice: 12, Above: Threshold{Kind: KindAbs, Value: 15}, Delivery: DeliveryDiscord, Status: StatusActive}

	w := httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("PATCH", "/api/alerts/1", `{"above":{"kind":"abs","value":16},"delivery":"discord"}`, sig))
	if w.Code != http.StatusOK || store.rows[1].Above.Value != 16 {
		t.Fatalf("unchanged delivery = %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("PATCH", "/api/alerts/1", `{"delivery":"email"}`, sig))
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "confirm an email address first") {
		t.Fatalf("switch to email = %d %s", w.Code, w.Body)
	}
}

// A downgraded user cannot resend to a pending address.
func TestAlertsAPIResendNeedsTier(t *testing.T) {
	store := newFakeAlertStore()
	sent := []sentConfirm{}
	api := testChannelAPI(store, &sent, nil)
	hash := testHash("a@b.com")
	store.channels[channelKey{hash, ChannelEmail, SourceUser}] = Channel{UserHash: hash, Kind: ChannelEmail, Address: "me@example.com", Source: SourceUser}
	w := httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email/resend", `{}`, testCaller("a@b.com", "Pioneer")))
	if w.Code != http.StatusUnprocessableEntity || len(sent) != 0 {
		t.Fatalf("downgraded resend = %d %s sent=%d", w.Code, w.Body, len(sent))
	}
}

// A patreon email row is an active channel without a user address.
func TestAlertsAPICreateOnPatreonEmail(t *testing.T) {
	store := newFakeAlertStore()
	sent := []sentConfirm{}
	api := testChannelAPI(store, &sent, nil)
	hash := testHash("a@b.com")
	now := time.Now()
	store.channels[channelKey{hash, ChannelEmail, SourcePatreon}] = Channel{UserHash: hash, Kind: ChannelEmail, Address: "a@b.com", Source: SourcePatreon, VerifiedAt: &now}
	body := `{"card_id":"card-1","side":"buylist","condition":"NM","above":{"kind":"abs","value":15},"delivery":"email"}`
	w := httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/", body, testCaller("a@b.com", "Legacy")))
	if w.Code != http.StatusCreated || store.rows[1].Delivery != DeliveryEmail {
		t.Fatalf("create on patreon email = %d %s", w.Code, w.Body)
	}
}

// Only a bounce may be re-verified: an unsubscribed address is refused on
// resend and on re-entering it, while a different address still goes through.
func TestAlertsAPIUnsubscribedNotReverified(t *testing.T) {
	store := newFakeAlertStore()
	sent := []sentConfirm{}
	api := testChannelAPI(store, &sent, nil)
	sig := testCaller("a@b.com", "Legacy")
	hash := testHash("a@b.com")
	now := time.Now()
	store.channels[channelKey{hash, ChannelEmail, SourceUser}] = Channel{UserHash: hash, Kind: ChannelEmail, Address: "me@example.com", Source: SourceUser, VerifiedAt: &now, DisabledAt: &now, DisabledReason: "unsubscribed"}
	const msg = "this address unsubscribed; use Enable to turn it back on"

	w := httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email/resend", `{}`, sig))
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), msg) || len(sent) != 0 {
		t.Fatalf("resend unsubscribed = %d %s sent=%d", w.Code, w.Body, len(sent))
	}
	w = httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email", `{"address":"ME@example.com"}`, sig))
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), msg) || len(sent) != 0 {
		t.Fatalf("re-post unsubscribed = %d %s sent=%d", w.Code, w.Body, len(sent))
	}
	if row := store.channels[channelKey{hash, ChannelEmail, SourceUser}]; row.DisabledReason != "unsubscribed" {
		t.Fatalf("row changed = %+v", row)
	}

	// A reason nobody planned for is refused too.
	store.channels[channelKey{hash, ChannelEmail, SourceUser}] = Channel{UserHash: hash, Kind: ChannelEmail, Address: "me@example.com", Source: SourceUser, DisabledAt: &now, DisabledReason: "other"}
	w = httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email/resend", `{}`, sig))
	if w.Code != http.StatusUnprocessableEntity || len(sent) != 0 {
		t.Fatalf("resend other reason = %d %s sent=%d", w.Code, w.Body, len(sent))
	}

	w = httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email", `{"address":"new@example.com"}`, sig))
	if w.Code != http.StatusAccepted || len(sent) != 1 || sent[0].to != "new@example.com" {
		t.Fatalf("different address = %d %s sent=%+v", w.Code, w.Body, sent)
	}
}

// A mint that signs nothing (no secret behind it) must not mail a dead link.
func TestAlertsAPIConfirmRefusesAnUnsignedToken(t *testing.T) {
	store := newFakeAlertStore()
	sent := []sentConfirm{}
	api := testChannelAPI(store, &sent, nil)
	api.deps.Mint = func(Token) string { return "" }
	sig := testCaller("a@b.com", "Legacy")

	w := httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email", `{"address":"me@example.com"}`, sig))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "not configured") || len(sent) != 0 {
		t.Fatalf("= %d %s, sent %d", w.Code, w.Body, len(sent))
	}
}
