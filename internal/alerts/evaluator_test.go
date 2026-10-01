package alerts

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bwmarrin/discordgo"
)

// fakeEvalStore keeps each row's status and armed flags so the guards the
// real SQL applies (status, compare-and-set) hold here too.
type fakeEvalStore struct {
	rows      []ActiveAlert
	status    map[int64]Status
	armed     map[int64][2]bool
	fired     map[int64]time.Time
	states    map[int64]State
	claims    []int64
	claimFail bool
	events    []Event
	marked    map[string]int
	calls     int
	pruned    int
}

func newFakeEvalStore(rows ...ActiveAlert) *fakeEvalStore {
	f := &fakeEvalStore{
		rows: rows, status: map[int64]Status{}, armed: map[int64][2]bool{},
		fired: map[int64]time.Time{}, states: map[int64]State{}, marked: map[string]int{},
	}
	for _, a := range rows {
		f.status[a.ID] = a.Status
		f.armed[a.ID] = [2]bool{a.AboveArmed, a.BelowArmed}
	}
	return f
}

func (f *fakeEvalStore) UsersWithAlerts(context.Context, string) ([]Contact, error) {
	f.calls++
	var out []Contact
	for _, a := range f.rows {
		st := f.status[a.ID]
		if st != StatusActive && st != StatusOverAllowance {
			continue
		}
		if !slices.ContainsFunc(out, func(c Contact) bool { return c.UserHash == a.UserHash }) {
			out = append(out, a.Contact)
		}
	}
	return out, nil
}

// ListActive returns the rows whose current status is active on the sides.
func (f *fakeEvalStore) ListActive(_ context.Context, _ string, sides []Side) ([]ActiveAlert, error) {
	f.calls++
	var out []ActiveAlert
	for _, a := range f.rows {
		if f.status[a.ID] != StatusActive || !slices.Contains(sides, a.Side) {
			continue
		}
		a.Status = StatusActive
		a.AboveArmed, a.BelowArmed = f.armed[a.ID][0], f.armed[a.ID][1]
		t, ok := f.fired[a.ID]
		if ok {
			a.LastFiredAt = &t
		}
		out = append(out, a)
	}
	return out, nil
}

// MarkOverAllowance keeps a user's n highest ids active and parks the rest,
// restoring parked ones inside the allowance.
func (f *fakeEvalStore) MarkOverAllowance(_ context.Context, h, _ string, n int) (int64, error) {
	f.calls++
	f.marked[h] = n
	var ids []int64
	for _, a := range f.rows {
		st := f.status[a.ID]
		if a.UserHash == h && (st == StatusActive || st == StatusOverAllowance) {
			ids = append(ids, a.ID)
		}
	}
	slices.Sort(ids)
	slices.Reverse(ids)
	var changed int64
	for i, id := range ids {
		want := StatusActive
		if i >= n {
			want = StatusOverAllowance
		}
		if f.status[id] != want {
			f.status[id] = want
			changed++
		}
	}
	return changed, nil
}

func (f *fakeEvalStore) row(id int64) ActiveAlert {
	for _, a := range f.rows {
		if a.ID == id {
			return a
		}
	}
	return ActiveAlert{}
}

// ClaimFire compares status, updated_at and both flags before flipping them.
func (f *fakeEvalStore) ClaimFire(_ context.Context, id int64, seen time.Time, wasAbove, wasBelow, nextAbove, nextBelow bool) (bool, error) {
	f.calls++
	if f.claimFail || f.status[id] != StatusActive || !f.row(id).UpdatedAt.Equal(seen) || f.armed[id] != [2]bool{wasAbove, wasBelow} {
		return false, nil
	}
	f.armed[id] = [2]bool{nextAbove, nextBelow}
	f.claims = append(f.claims, id)
	return true, nil
}

// SetState writes only rows whose current status is active.
func (f *fakeEvalStore) SetState(_ context.Context, id int64, st State) (bool, error) {
	f.calls++
	if f.status[id] != StatusActive {
		return false, nil
	}
	f.states[id] = st
	f.status[id] = st.Status
	f.armed[id] = [2]bool{st.AboveArmed, st.BelowArmed}
	if st.LastFiredAt != nil {
		f.fired[id] = *st.LastFiredAt
	}
	return true, nil
}

func (f *fakeEvalStore) AddEvent(_ context.Context, e Event) error {
	f.calls++
	f.events = append(f.events, e)
	return nil
}

func (f *fakeEvalStore) PruneEvents(context.Context, time.Time) (int64, error) {
	f.calls++
	f.pruned++
	return 0, nil
}

type fakeSender struct {
	sent   []string
	embeds []*discordgo.MessageEmbed
	err    error
}

func (f *fakeSender) Send(id string, embed *discordgo.MessageEmbed) error {
	f.sent = append(f.sent, id)
	f.embeds = append(f.embeds, embed)
	return f.err
}

var evalNow = time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)

func evalDeps(store *fakeEvalStore, sender *fakeSender, price float64) EvalDeps {
	// A fresh prune clock, so each test starts due.
	return EvalDeps{
		Store: store, Sender: sender, Game: "magic", Pace: 0,
		PruneDue:  (&Service{}).pruneDue,
		Ready:     func() bool { return true },
		Allowance: func(url.Values) int { return 5 },
		Values:    func(string, string) url.Values { return url.Values{"Alerts": {"true"}, "AlertsMax": {"5"}} },
		Now:       func() time.Time { return evalNow },
		Prices: func(cardID string, side Side, _ url.Values) []StorePrice {
			return []StorePrice{{Shorthand: "CK", Name: "Card Kingdom", Prices: map[string]float64{"NM": price}}}
		},
		Resolve: func(cardID string) (Card, bool, bool) {
			return Card{Name: "Bolt"}, false, cardID != "gone"
		},
	}
}

func activeAlert() ActiveAlert {
	return ActiveAlert{
		Alert: Alert{
			ID: 7, UserHash: "u", Game: "magic", CardID: "card-1", Side: SideBuylist, Condition: "NM",
			ReferencePrice: 10, Above: Threshold{Kind: KindAbs, Value: 12},
			Status: StatusActive, AboveArmed: true, BelowArmed: true, Delivery: DeliveryDiscord,
			UpdatedAt: time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC), Origin: "https://lorcana.mtgban.com",
		},
		Contact: Contact{UserHash: "u", DiscordUserID: "d1", Tier: "Legacy", UpdatedAt: evalNow.Add(-24 * time.Hour)},
	}
}

var buylistOnly = []Side{SideBuylist}

func TestRunAlertEvaluationFiresAndRecords(t *testing.T) {
	store := newFakeEvalStore(activeAlert())
	sender := &fakeSender{}
	runEvaluation(context.Background(), evalDeps(store, sender, 13), buylistOnly)

	if len(sender.sent) != 1 || sender.sent[0] != "d1" {
		t.Fatalf("sent = %v", sender.sent)
	}
	// The DM links to the site the alert was saved on.
	e := sender.embeds[0]
	if e.URL != "https://lorcana.mtgban.com/alerts" || !strings.Contains(e.Description, "https://lorcana.mtgban.com/go/b/CK/card-1") {
		t.Fatalf("links: url=%q\n%s", e.URL, e.Description)
	}
	if !slices.Equal(store.claims, []int64{7}) || store.armed[7] != [2]bool{false, true} || !store.fired[7].Equal(evalNow) {
		t.Fatalf("claim: claims=%v armed=%v fired=%v", store.claims, store.armed[7], store.fired[7])
	}
	st := store.states[7]
	if st.Status != StatusActive || st.AboveArmed || !st.BelowArmed || st.LastError != "" || st.LastFiredAt == nil || !st.LastFiredAt.Equal(evalNow) {
		t.Fatalf("delivery must stamp the fire time on the row: %+v", st)
	}
	if len(store.events) != 1 || !store.events[0].Delivered || store.events[0].Store != "CK" || store.events[0].Price != 13 {
		t.Fatalf("events = %+v", store.events)
	}
	if store.marked["u"] != 5 || store.pruned != 1 {
		t.Fatalf("allowance/prune bookkeeping: %+v pruned=%d", store.marked, store.pruned)
	}
}

func TestRunAlertEvaluationQuietBelowThreshold(t *testing.T) {
	store := newFakeEvalStore(activeAlert())
	sender := &fakeSender{}
	runEvaluation(context.Background(), evalDeps(store, sender, 11), buylistOnly)
	if len(sender.sent) != 0 || len(store.states) != 0 || len(store.claims) != 0 {
		t.Fatalf("quiet run sent %v, wrote %v, claimed %v", sender.sent, store.states, store.claims)
	}
}

func TestRunAlertEvaluationMarksRefusedDM(t *testing.T) {
	cases := map[string]*discordgo.RESTError{
		"50007": {
			Response: &http.Response{StatusCode: http.StatusForbidden},
			Message:  &discordgo.APIErrorMessage{Code: discordgo.ErrCodeCannotSendMessagesToThisUser, Message: "Cannot send messages to this user"},
		},
		"404": {
			Response: &http.Response{StatusCode: http.StatusNotFound},
			Message:  &discordgo.APIErrorMessage{Code: 10013, Message: "Unknown User"},
		},
	}
	for name, restErr := range cases {
		t.Run(name, func(t *testing.T) {
			store := newFakeEvalStore(activeAlert())
			sender := &fakeSender{err: restErr}
			runEvaluation(context.Background(), evalDeps(store, sender, 13), buylistOnly)
			st, ok := store.states[7]
			if !ok || st.Status != StatusUndeliverable || st.AboveArmed || !strings.Contains(st.LastError, restErr.Message.Message) {
				t.Fatalf("state = %+v ok=%v", st, ok)
			}
			if len(store.events) != 1 || store.events[0].Delivered {
				t.Fatalf("events = %+v", store.events)
			}
		})
	}
}

func TestRunAlertEvaluationSkipsUnlinkedAndUnresolvable(t *testing.T) {
	unlinked := activeAlert()
	unlinked.Contact.DiscordUserID = ""
	gone := activeAlert()
	gone.ID, gone.CardID = 8, "gone"
	store := newFakeEvalStore(unlinked, gone)
	sender := &fakeSender{}
	runEvaluation(context.Background(), evalDeps(store, sender, 13), buylistOnly)
	if len(sender.sent) != 0 || len(store.claims) != 0 {
		t.Fatalf("sent to an unlinked user: %v claims=%v", sender.sent, store.claims)
	}
	if store.states[8].Status != StatusUnresolvable {
		t.Fatalf("gone card state = %+v", store.states[8])
	}
	st, ok := store.states[7]
	if !ok || st.Status != StatusUndeliverable {
		t.Fatalf("unlinked state = %+v ok=%v", st, ok)
	}
}

func TestRunAlertEvaluationRetriesOtherSendErrors(t *testing.T) {
	store := newFakeEvalStore(activeAlert())
	sender := &fakeSender{err: errors.New("dial tcp")}
	runEvaluation(context.Background(), evalDeps(store, sender, 13), buylistOnly)

	st := store.states[7]
	if st.Status != StatusActive || !st.AboveArmed || !st.BelowArmed || st.LastError != "delivery failed, will retry" || st.LastFiredAt != nil {
		t.Fatalf("state = %+v", st)
	}
	if store.armed[7] != [2]bool{true, true} || !store.fired[7].IsZero() {
		t.Fatalf("retry must restore the flags and leave the fire time unset: armed=%v fired=%v", store.armed[7], store.fired[7])
	}
	if len(store.events) != 1 || store.events[0].Delivered || store.events[0].Error == "" {
		t.Fatalf("events = %+v", store.events)
	}
}

func TestRunAlertEvaluationLostClaimSendsNothing(t *testing.T) {
	store := newFakeEvalStore(activeAlert())
	store.claimFail = true
	sender := &fakeSender{}
	runEvaluation(context.Background(), evalDeps(store, sender, 13), buylistOnly)
	if len(sender.sent) != 0 || len(store.events) != 0 || len(store.states) != 0 {
		t.Fatalf("lost claim still acted: sent=%v events=%v states=%v", sender.sent, store.events, store.states)
	}
}

func TestRunAlertEvaluationFakeClaimCompares(t *testing.T) {
	a := activeAlert()
	store := newFakeEvalStore(a)
	// An edit landed after the list: the fake's row moved on.
	store.rows[0].UpdatedAt = a.UpdatedAt.Add(time.Second)
	listed := store.rows[0]
	listed.UpdatedAt = a.UpdatedAt
	ok, _ := store.ClaimFire(context.Background(), 7, listed.UpdatedAt, true, true, false, true)
	if ok {
		t.Fatal("fake claimed a row edited since it was listed")
	}
	ok, _ = store.ClaimFire(context.Background(), 7, store.rows[0].UpdatedAt, false, true, false, true)
	if ok {
		t.Fatal("fake claimed with stale flags")
	}
}

func TestRunAlertEvaluationRearmsQuietly(t *testing.T) {
	a := activeAlert()
	a.AboveArmed = false
	store := newFakeEvalStore(a)
	sender := &fakeSender{}
	runEvaluation(context.Background(), evalDeps(store, sender, 11), buylistOnly)

	if len(sender.sent) != 0 {
		t.Fatalf("sent = %v", sender.sent)
	}
	if len(store.states) != 1 {
		t.Fatalf("expected exactly one state write, got %+v", store.states)
	}
	st := store.states[7]
	if !st.AboveArmed || st.Status != StatusActive {
		t.Fatalf("state = %+v", st)
	}
	if len(store.events) != 0 {
		t.Fatalf("events = %+v", store.events)
	}
}

func TestRunAlertEvaluationThrottledWritesNothing(t *testing.T) {
	a := activeAlert()
	fired := time.Date(2026, 9, 28, 11, 0, 0, 0, time.UTC)
	a.LastFiredAt = &fired
	store := newFakeEvalStore(a)
	sender := &fakeSender{}
	runEvaluation(context.Background(), evalDeps(store, sender, 13), buylistOnly)

	if len(sender.sent) != 0 || len(store.states) != 0 || len(store.events) != 0 || len(store.claims) != 0 {
		t.Fatalf("throttled run acted: sent=%v states=%+v events=%+v claims=%v", sender.sent, store.states, store.events, store.claims)
	}
}

func TestRunAlertEvaluationParksBeyondAllowance(t *testing.T) {
	older := activeAlert()
	newer := activeAlert()
	newer.ID = 8
	store := newFakeEvalStore(older, newer)
	sender := &fakeSender{}
	deps := evalDeps(store, sender, 13)
	deps.Allowance = func(url.Values) int { return 1 }
	runEvaluation(context.Background(), deps, buylistOnly)

	if len(sender.sent) != 1 || !slices.Equal(store.claims, []int64{8}) {
		t.Fatalf("sent = %v claims = %v", sender.sent, store.claims)
	}
	if store.status[7] != StatusOverAllowance {
		t.Fatalf("alert 7 status = %s", store.status[7])
	}
	_, ok := store.states[7]
	if ok {
		t.Fatalf("parked alert 7 got a state write: %+v", store.states[7])
	}
	for _, e := range store.events {
		if e.AlertID == 7 {
			t.Fatalf("parked alert 7 got an event: %+v", e)
		}
	}
}

func TestRunAlertEvaluationRestoresParkedUser(t *testing.T) {
	a := activeAlert()
	a.Status = StatusOverAllowance
	store := newFakeEvalStore(a)
	sender := &fakeSender{}
	runEvaluation(context.Background(), evalDeps(store, sender, 13), buylistOnly)

	if store.marked["u"] != 5 || store.status[7] != StatusActive {
		t.Fatalf("parked user not restored: marked=%v status=%s", store.marked, store.status[7])
	}
	if len(sender.sent) != 1 || !slices.Equal(store.claims, []int64{7}) {
		t.Fatalf("restored alert did not fire: sent=%v claims=%v", sender.sent, store.claims)
	}
}

// alertsMaxAllowance reads AlertsMax off values that grant alerts, as the
// site does; 0 means alerts are off.
func alertsMaxAllowance(v url.Values) int {
	if v.Get("Alerts") != "true" {
		return 0
	}
	n, err := strconv.Atoi(v.Get("AlertsMax"))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// TestRunAlertEvaluationUsesEachUsersValues proves the evaluator asks deps.Values
// per user rather than reusing one tier's values for everyone: user u's values
// grant alerts, v's values grant nothing, and only u's allowance and card see them.
func TestRunAlertEvaluationUsesEachUsersValues(t *testing.T) {
	u := activeAlert()
	v := activeAlert()
	v.ID, v.UserHash, v.CardID = 9, "v", "card-2"
	v.Contact = Contact{UserHash: "v", DiscordUserID: "d2", Tier: "Legacy", UpdatedAt: evalNow.Add(-24 * time.Hour)}

	store := newFakeEvalStore(u, v)
	sender := &fakeSender{}
	deps := evalDeps(store, sender, 13)
	deps.Allowance = alertsMaxAllowance
	deps.Values = func(userHash, _ string) url.Values {
		if userHash == "u" {
			return url.Values{"Alerts": {"true"}, "AlertsMax": {"1"}}
		}
		return url.Values{}
	}
	received := map[string]url.Values{}
	deps.Prices = func(cardID string, _ Side, v url.Values) []StorePrice {
		received[cardID] = v
		return []StorePrice{{Shorthand: "CK", Name: "Card Kingdom", Prices: map[string]float64{"NM": 13}}}
	}
	runEvaluation(context.Background(), deps, buylistOnly)

	if store.marked["u"] != 1 {
		t.Fatalf("marked[u] = %d, want 1", store.marked["u"])
	}
	if store.marked["v"] != 0 {
		t.Fatalf("marked[v] = %d, want 0", store.marked["v"])
	}
	got, ok := received["card-1"]
	if !ok || got.Get("Alerts") != "true" || got.Get("AlertsMax") != "1" {
		t.Fatalf("prices not called with u's own values: %v ok=%v", got, ok)
	}
}

func TestRunAlertEvaluationParksStaleContacts(t *testing.T) {
	stale := activeAlert()
	stale.Contact.UpdatedAt = evalNow.Add(-40 * 24 * time.Hour)

	fresh := activeAlert()
	fresh.ID, fresh.UserHash, fresh.Contact.UserHash, fresh.Contact.DiscordUserID = 8, "u2", "u2", "d2"
	fresh.Contact.UpdatedAt = evalNow.Add(-10 * 24 * time.Hour)

	store := newFakeEvalStore(stale, fresh)
	sender := &fakeSender{}
	runEvaluation(context.Background(), evalDeps(store, sender, 13), buylistOnly)

	if store.marked["u"] != 0 {
		t.Fatalf("stale contact allowance = %d, want 0", store.marked["u"])
	}
	if store.marked["u2"] != 5 {
		t.Fatalf("fresh contact allowance = %d, want 5", store.marked["u2"])
	}
	if len(sender.sent) != 1 || sender.sent[0] != "d2" {
		t.Fatalf("sent = %v, want only the fresh contact", sender.sent)
	}
	if !slices.Equal(store.claims, []int64{8}) {
		t.Fatalf("claims = %v, want only the fresh alert", store.claims)
	}
	_, ok := store.states[7]
	if ok {
		t.Fatalf("stale alert got a state write: %+v", store.states[7])
	}
	for _, e := range store.events {
		if e.AlertID == 7 {
			t.Fatalf("stale alert got an event: %+v", e)
		}
	}
}

// noUsersStore answers UsersWithAlerts with nothing, as if a concurrent
// run's MarkOverAllowance park had not reached this one's ListActive read
// yet: the row stays active with a stale contact attached.
type noUsersStore struct{ *fakeEvalStore }

func (noUsersStore) UsersWithAlerts(context.Context, string) ([]Contact, error) {
	return nil, nil
}

// TestRunAlertEvaluationStaleContactSkipsBeforeUnresolvable covers the
// active loop's own guard: a stale contact gets no state write at all, so
// the staleness check must run before the card-resolve check.
func TestRunAlertEvaluationStaleContactSkipsBeforeUnresolvable(t *testing.T) {
	stale := activeAlert()
	stale.CardID = "gone"
	stale.Contact.UpdatedAt = evalNow.Add(-40 * 24 * time.Hour)

	store := newFakeEvalStore(stale)
	sender := &fakeSender{}
	deps := evalDeps(store, sender, 13)
	deps.Store = noUsersStore{store}
	runEvaluation(context.Background(), deps, buylistOnly)

	if len(sender.sent) != 0 {
		t.Fatalf("sent = %v", sender.sent)
	}
	if len(store.states) != 0 {
		t.Fatalf("stale, unresolvable alert got a state write: %+v", store.states)
	}
	if len(store.events) != 0 {
		t.Fatalf("stale, unresolvable alert got an event: %+v", store.events)
	}
}

func TestRunAlertEvaluationPrunesAtMostHourly(t *testing.T) {
	store := newFakeEvalStore(activeAlert())
	deps := evalDeps(store, &fakeSender{}, 11)
	runEvaluation(context.Background(), deps, buylistOnly)
	runEvaluation(context.Background(), deps, buylistOnly)
	if store.pruned != 1 {
		t.Fatalf("pruned %d times inside the hour", store.pruned)
	}
	deps.Now = func() time.Time { return evalNow.Add(61 * time.Minute) }
	runEvaluation(context.Background(), deps, buylistOnly)
	if store.pruned != 2 {
		t.Fatalf("no prune after the hour: %d", store.pruned)
	}
}

// A temporary send failure must not start the send gap: the next pass, still
// across the line, tries the DM again.
func TestRunAlertEvaluationRetriesOnTheNextPass(t *testing.T) {
	store := newFakeEvalStore(activeAlert())
	sender := &fakeSender{err: errors.New("dial tcp")}
	deps := evalDeps(store, sender, 13)
	runEvaluation(context.Background(), deps, buylistOnly)
	sender.err = nil
	runEvaluation(context.Background(), deps, buylistOnly)

	if len(sender.sent) != 2 || !slices.Equal(store.claims, []int64{7, 7}) {
		t.Fatalf("second pass did not retry: sent=%v claims=%v", sender.sent, store.claims)
	}
	st := store.states[7]
	if st.LastError != "" || st.LastFiredAt == nil || !st.LastFiredAt.Equal(evalNow) || store.armed[7] != [2]bool{false, true} {
		t.Fatalf("delivered retry left state %+v armed=%v", st, store.armed[7])
	}
	if len(store.events) != 2 || store.events[0].Delivered || !store.events[1].Delivered {
		t.Fatalf("events = %+v", store.events)
	}

	// Delivered once, the gap now holds a third pass quiet.
	runEvaluation(context.Background(), deps, buylistOnly)
	if len(sender.sent) != 2 {
		t.Fatalf("gap ignored after delivery: sent=%v", sender.sent)
	}
}
