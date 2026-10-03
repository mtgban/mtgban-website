package alerts

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bwmarrin/discordgo"

	"github.com/mtgban/mtgban-website/mailer"
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
	// emails is each user's active email address; Discord comes off the contact.
	emails map[string]string
	// chanParked is the rows parked for their channel, as last_error marks them.
	chanParked map[int64]bool
	allowed    map[string][]ChannelKind
	// steps is the per-user park calls in order, "channel:u" or "allowance:u".
	steps []string
	// prunedChannels counts PruneUnverifiedChannels calls.
	prunedChannels int
	// disabledSince is what ChannelsDisabledSince reports.
	disabledSince int
	// disabledUntil is the upper bound ChannelsDisabledSince was last asked for.
	disabledUntil time.Time
}

func newFakeEvalStore(rows ...ActiveAlert) *fakeEvalStore {
	f := &fakeEvalStore{
		rows: rows, status: map[int64]Status{}, armed: map[int64][2]bool{},
		fired: map[int64]time.Time{}, states: map[int64]State{}, marked: map[string]int{},
		emails: map[string]string{}, chanParked: map[int64]bool{}, allowed: map[string][]ChannelKind{},
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
// restoring parked ones inside the allowance; channel-parked rows sit out.
func (f *fakeEvalStore) MarkOverAllowance(_ context.Context, h, _ string, n int) ([]Moved, error) {
	f.calls++
	f.marked[h] = n
	f.steps = append(f.steps, "allowance:"+h)
	var ids []int64
	for _, a := range f.rows {
		st := f.status[a.ID]
		if a.UserHash == h && (st == StatusActive || st == StatusOverAllowance && !f.chanParked[a.ID]) {
			ids = append(ids, a.ID)
		}
	}
	slices.Sort(ids)
	slices.Reverse(ids)
	var moved []Moved
	for i, id := range ids {
		want := StatusActive
		if i >= n {
			want = StatusOverAllowance
		}
		if f.status[id] != want {
			f.status[id] = want
			a := f.row(id)
			moved = append(moved, Moved{ID: id, Status: want, Card: a.Card, Side: a.Side, Condition: a.Condition, Origin: a.Origin})
		}
	}
	return moved, nil
}

// MarkChannelDisallowed parks rows on a channel not allowed, re-marking
// allowance-parked ones silently, and restores rows it parked once their
// channel is allowed again.
func (f *fakeEvalStore) MarkChannelDisallowed(_ context.Context, h, _ string, allowed []ChannelKind) ([]Moved, error) {
	f.calls++
	f.allowed[h] = allowed
	f.steps = append(f.steps, "channel:"+h)
	var moved []Moved
	for _, a := range f.rows {
		if a.UserHash != h {
			continue
		}
		ok := slices.Contains(allowed, ChannelKind(a.Delivery))
		st := f.status[a.ID]
		switch {
		case st == StatusOverAllowance && !f.chanParked[a.ID] && !ok:
			f.chanParked[a.ID] = true
			continue
		case st == StatusActive && !ok:
			f.status[a.ID], f.chanParked[a.ID] = StatusOverAllowance, true
		case st == StatusOverAllowance && f.chanParked[a.ID] && ok:
			f.status[a.ID], f.chanParked[a.ID] = StatusActive, false
		default:
			continue
		}
		moved = append(moved, Moved{ID: a.ID, Status: f.status[a.ID], Card: a.Card, Side: a.Side, Condition: a.Condition, Origin: a.Origin})
	}
	return moved, nil
}

// channelFor answers as ChannelFor does: Discord off the contact, email
// from emails.
func (f *fakeEvalStore) channelFor(_ context.Context, h string, kind ChannelKind) (Channel, bool, error) {
	addr := f.emails[h]
	if kind == ChannelDiscord {
		addr = ""
		for _, a := range f.rows {
			if a.Contact.UserHash == h {
				addr = a.Contact.DiscordUserID
				break
			}
		}
	}
	if addr == "" {
		return Channel{}, false, nil
	}
	return Channel{UserHash: h, Kind: kind, Address: addr, Source: SourcePatreon}, true, nil
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

func (f *fakeEvalStore) PruneUnverifiedChannels(context.Context, time.Time) (int64, error) {
	f.calls++
	f.prunedChannels++
	return 0, nil
}

func (f *fakeEvalStore) ChannelsDisabledSince(_ context.Context, _, until time.Time) (int, error) {
	f.calls++
	f.disabledUntil = until
	return f.disabledSince, nil
}

// fakeDeliverer records what it was handed; err, or errs per alert id,
// is each firing's result. It takes the park notices too.
type fakeDeliverer struct {
	kind     ChannelKind
	sent     []Firing
	digests  []Digest
	channels []Channel
	err      error
	errs     map[int64]error
	notices  []*discordgo.MessageEmbed
	noticeTo []string
	// messageID, when set, is the provider id a successful delivery reports.
	messageID string
}

func (f *fakeDeliverer) Kind() ChannelKind { return f.kind }

func (f *fakeDeliverer) Deliver(_ context.Context, d Digest, ch Channel, _ func(string) string) []Delivery {
	f.digests = append(f.digests, d)
	f.channels = append(f.channels, ch)
	var out []Delivery
	for _, fr := range d.Firings {
		f.sent = append(f.sent, fr)
		err, ok := f.errs[fr.Alert.ID]
		if !ok {
			err = f.err
		}
		id := ""
		if err == nil {
			id = f.messageID
		}
		out = append(out, Delivery{AlertID: fr.Alert.ID, Err: err, MessageID: id})
	}
	return out
}

func (f *fakeDeliverer) notify(discordUserID string, embed *discordgo.MessageEmbed) error {
	f.noticeTo = append(f.noticeTo, discordUserID)
	f.notices = append(f.notices, embed)
	return f.err
}

// ids is the alert ids of the firings delivered, in order.
func (f *fakeDeliverer) ids() []int64 {
	var out []int64
	for _, fr := range f.sent {
		out = append(out, fr.Alert.ID)
	}
	return out
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

func evalDeps(store *fakeEvalStore, discord *fakeDeliverer, price float64) EvalDeps {
	discord.kind = ChannelDiscord
	// A fresh prune clock, so each test starts due.
	return EvalDeps{
		Store: store, Deliverers: []Deliverer{discord}, Game: "magic",
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
		ChannelFor: store.channelFor,
		Channels:   func(url.Values) []ChannelKind { return []ChannelKind{ChannelDiscord, ChannelEmail} },
	}
}

func activeAlert() ActiveAlert {
	return ActiveAlert{
		Alert: Alert{
			ID: 7, UserHash: "u", Game: "magic", CardID: "card-1", Side: SideBuylist, Condition: "NM",
			Card:           Card{Name: "Bolt", Set: "LEA", Number: "161", Finish: "nonfoil"},
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
	dd := &fakeDeliverer{}
	runEvaluation(context.Background(), evalDeps(store, dd, 13), buylistOnly)

	if !slices.Equal(dd.ids(), []int64{7}) || dd.channels[0].Address != "d1" {
		t.Fatalf("sent = %v to %+v", dd.ids(), dd.channels)
	}
	// The firing carries the site the alert was saved on, for its links.
	f := dd.sent[0]
	if f.Origin != "https://lorcana.mtgban.com" || !f.Decision.FireAbove || f.Contact.UserHash != "u" {
		t.Fatalf("firing = %+v", f)
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
	dd := &fakeDeliverer{}
	runEvaluation(context.Background(), evalDeps(store, dd, 11), buylistOnly)
	if len(dd.sent) != 0 || len(store.states) != 0 || len(store.claims) != 0 {
		t.Fatalf("quiet run sent %v, wrote %v, claimed %v", dd.sent, store.states, store.claims)
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
			dd := &fakeDeliverer{err: restErr}
			runEvaluation(context.Background(), evalDeps(store, dd, 13), buylistOnly)
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
	dd := &fakeDeliverer{}
	runEvaluation(context.Background(), evalDeps(store, dd, 13), buylistOnly)
	if len(dd.sent) != 0 || len(store.claims) != 0 {
		t.Fatalf("sent to an unlinked user: %v claims=%v", dd.sent, store.claims)
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
	dd := &fakeDeliverer{err: errors.New("dial tcp")}
	runEvaluation(context.Background(), evalDeps(store, dd, 13), buylistOnly)

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
	dd := &fakeDeliverer{}
	runEvaluation(context.Background(), evalDeps(store, dd, 13), buylistOnly)
	if len(dd.sent) != 0 || len(store.events) != 0 || len(store.states) != 0 {
		t.Fatalf("lost claim still acted: sent=%v events=%v states=%v", dd.sent, store.events, store.states)
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
	dd := &fakeDeliverer{}
	runEvaluation(context.Background(), evalDeps(store, dd, 11), buylistOnly)

	if len(dd.sent) != 0 {
		t.Fatalf("sent = %v", dd.sent)
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
	dd := &fakeDeliverer{}
	runEvaluation(context.Background(), evalDeps(store, dd, 13), buylistOnly)

	if len(dd.sent) != 0 || len(store.states) != 0 || len(store.events) != 0 || len(store.claims) != 0 {
		t.Fatalf("throttled run acted: sent=%v states=%+v events=%+v claims=%v", dd.sent, store.states, store.events, store.claims)
	}
}

func TestRunAlertEvaluationParksBeyondAllowance(t *testing.T) {
	older := activeAlert()
	newer := activeAlert()
	newer.ID = 8
	store := newFakeEvalStore(older, newer)
	dd := &fakeDeliverer{}
	deps := evalDeps(store, dd, 13)
	deps.Allowance = func(url.Values) int { return 1 }
	runEvaluation(context.Background(), deps, buylistOnly)

	// The park notice for 7, then the firing on 8.
	if len(dd.notices) != 1 || dd.noticeTo[0] != "d1" || !slices.Equal(dd.ids(), []int64{8}) || !slices.Equal(store.claims, []int64{8}) {
		t.Fatalf("notices = %v sent = %v claims = %v", dd.noticeTo, dd.ids(), store.claims)
	}
	notice := dd.notices[0]
	if notice.Title != "Price alerts parked" || !strings.Contains(notice.Description, "Your tier allows 1 alert.") ||
		!strings.Contains(notice.Description, "Bolt LEA #161, nonfoil, NM buylist\n") || notice.URL != "https://lorcana.mtgban.com/alerts" {
		t.Fatalf("notice: title=%q url=%q\n%s", notice.Title, notice.URL, notice.Description)
	}
	if store.status[7] != StatusOverAllowance {
		t.Fatalf("alert 7 status = %s", store.status[7])
	}
	// The next run parks nothing new, so it says nothing again.
	runEvaluation(context.Background(), deps, buylistOnly)
	if len(dd.notices) != 1 {
		t.Fatalf("second run sent %d notices, want no repeat", len(dd.notices))
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
	dd := &fakeDeliverer{}
	runEvaluation(context.Background(), evalDeps(store, dd, 13), buylistOnly)

	if store.marked["u"] != 5 || store.status[7] != StatusActive {
		t.Fatalf("parked user not restored: marked=%v status=%s", store.marked, store.status[7])
	}
	if len(dd.sent) != 1 || !slices.Equal(store.claims, []int64{7}) {
		t.Fatalf("restored alert did not fire: sent=%v claims=%v", dd.sent, store.claims)
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
	dd := &fakeDeliverer{}
	deps := evalDeps(store, dd, 13)
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
	dd := &fakeDeliverer{}
	runEvaluation(context.Background(), evalDeps(store, dd, 13), buylistOnly)

	if store.marked["u"] != 0 {
		t.Fatalf("stale contact allowance = %d, want 0", store.marked["u"])
	}
	if store.marked["u2"] != 5 {
		t.Fatalf("fresh contact allowance = %d, want 5", store.marked["u2"])
	}
	// The stale contact hears its alerts are parked; only the fresh one fires.
	if !slices.Equal(dd.noticeTo, []string{"d1"}) || !slices.Equal(dd.ids(), []int64{8}) || dd.channels[0].Address != "d2" {
		t.Fatalf("notices to %v, sent %v to %+v: want the stale contact's notice and the fresh contact's firing", dd.noticeTo, dd.ids(), dd.channels)
	}
	if !strings.Contains(dd.notices[0].Description, "No Patreon sign-in for over a month.") {
		t.Fatalf("notice reason:\n%s", dd.notices[0].Description)
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

func TestRunAlertEvaluationNoNoticeWithoutDiscord(t *testing.T) {
	a := activeAlert()
	a.Contact.DiscordUserID = ""
	store := newFakeEvalStore(a)
	dd := &fakeDeliverer{}
	deps := evalDeps(store, dd, 9)
	deps.Allowance = func(url.Values) int { return 0 }
	sum := runEvaluation(context.Background(), deps, buylistOnly)
	if store.status[7] != StatusOverAllowance || len(dd.notices) != 0 || sum.notices != 0 || sum.skipped != 1 {
		t.Fatalf("status=%s notices=%d/%d skipped=%d", store.status[7], len(dd.notices), sum.notices, sum.skipped)
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
	dd := &fakeDeliverer{}
	deps := evalDeps(store, dd, 13)
	deps.Store = noUsersStore{store}
	runEvaluation(context.Background(), deps, buylistOnly)

	if len(dd.sent) != 0 {
		t.Fatalf("sent = %v", dd.sent)
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
	deps := evalDeps(store, &fakeDeliverer{}, 11)
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
	dd := &fakeDeliverer{err: errors.New("dial tcp")}
	deps := evalDeps(store, dd, 13)
	runEvaluation(context.Background(), deps, buylistOnly)
	dd.err = nil
	runEvaluation(context.Background(), deps, buylistOnly)

	if len(dd.sent) != 2 || !slices.Equal(store.claims, []int64{7, 7}) {
		t.Fatalf("second pass did not retry: sent=%v claims=%v", dd.sent, store.claims)
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
	if len(dd.sent) != 2 {
		t.Fatalf("gap ignored after delivery: sent=%v", dd.sent)
	}
}

// alertOn is activeAlert for user h on a delivery channel, created id
// hours before evalNow so a lower id is newer.
func alertOn(id int64, h string, delivery DeliveryChannel) ActiveAlert {
	a := activeAlert()
	a.ID, a.UserHash, a.Delivery = id, h, delivery
	a.CreatedAt = evalNow.Add(-time.Duration(id) * time.Hour)
	a.Contact.UserHash, a.Contact.DiscordUserID = h, "d-"+h
	return a
}

func firingIDs(d Digest) []int64 {
	var out []int64
	for _, f := range d.Firings {
		out = append(out, f.Alert.ID)
	}
	return out
}

// eventsFor is the events recorded for one alert.
func eventsFor(store *fakeEvalStore, id int64) []Event {
	var out []Event
	for _, e := range store.events {
		if e.AlertID == id {
			out = append(out, e)
		}
	}
	return out
}

func TestRunGroupsFiringsPerUserAndChannel(t *testing.T) {
	store := newFakeEvalStore(alertOn(1, "u1", DeliveryEmail), alertOn(2, "u1", DeliveryEmail),
		alertOn(3, "u1", DeliveryDiscord), alertOn(4, "u2", DeliveryEmail))
	store.emails["u1"], store.emails["u2"] = "u1@example.com", "u2@example.com"
	dd := &fakeDeliverer{}
	ed := &fakeDeliverer{kind: ChannelEmail}
	deps := evalDeps(store, dd, 13)
	deps.Deliverers = append(deps.Deliverers, ed)
	sum := runEvaluation(context.Background(), deps, buylistOnly)

	if len(ed.digests) != 2 {
		t.Fatalf("email digests = %d, want one per user", len(ed.digests))
	}
	u1, u2 := ed.digests[0], ed.digests[1]
	if u1.UserHash != "u1" || !slices.Equal(firingIDs(u1), []int64{1, 2}) || ed.channels[0].Address != "u1@example.com" {
		t.Fatalf("u1 digest = %v %v to %+v", u1.UserHash, firingIDs(u1), ed.channels[0])
	}
	if u2.UserHash != "u2" || !slices.Equal(firingIDs(u2), []int64{4}) || ed.channels[1].Address != "u2@example.com" {
		t.Fatalf("u2 digest = %v %v to %+v", u2.UserHash, firingIDs(u2), ed.channels[1])
	}
	if len(dd.digests) != 1 || !slices.Equal(dd.ids(), []int64{3}) || dd.channels[0].Address != "d-u1" {
		t.Fatalf("discord digests = %d, sent %v to %+v", len(dd.digests), dd.ids(), dd.channels)
	}
	// A firing on the other channel still counts among the user's others.
	if len(u1.Others) != 1 || u1.Others[0].ID != 3 || len(u2.Others) != 0 {
		t.Fatalf("others: u1=%+v u2=%+v", u1.Others, u2.Others)
	}
	for _, id := range []int64{1, 2, 3, 4} {
		ev := eventsFor(store, id)
		if len(ev) != 1 || !ev[0].Delivered {
			t.Errorf("alert %d events = %+v", id, ev)
		}
		st := store.states[id]
		if st.Status != StatusActive || st.LastFiredAt == nil || !st.LastFiredAt.Equal(evalNow) {
			t.Errorf("alert %d state = %+v", id, st)
		}
	}
	if sum.sent != 4 || sum.problem() != "" {
		t.Fatalf("summary = %s, problem %q", sum, sum.problem())
	}
}

func TestRunParksWhenChannelIsMissing(t *testing.T) {
	email := alertOn(1, "u1", DeliveryEmail)
	unlinked := alertOn(2, "u2", DeliveryDiscord)
	unlinked.Contact.DiscordUserID = ""
	store := newFakeEvalStore(email, unlinked)
	dd := &fakeDeliverer{}
	ed := &fakeDeliverer{kind: ChannelEmail}
	deps := evalDeps(store, dd, 13)
	deps.Deliverers = append(deps.Deliverers, ed)
	sum := runEvaluation(context.Background(), deps, buylistOnly)

	if len(dd.sent) != 0 || len(ed.sent) != 0 || len(store.claims) != 0 || len(store.events) != 0 {
		t.Fatalf("acted without a channel: discord=%v email=%v claims=%v events=%+v", dd.ids(), ed.ids(), store.claims, store.events)
	}
	for id, want := range map[int64]string{1: "no confirmed email address", 2: "no Discord account linked on Patreon"} {
		st := store.states[id]
		if st.Status != StatusUndeliverable || st.LastError != want || !st.AboveArmed || !st.BelowArmed {
			t.Errorf("alert %d state = %+v, want undeliverable with %q", id, st, want)
		}
	}
	if sum.skipped != 2 {
		t.Fatalf("skipped = %d", sum.skipped)
	}
}

func TestRunRecordsPermanentDeliveryAsUndeliverable(t *testing.T) {
	store := newFakeEvalStore(alertOn(1, "u1", DeliveryEmail), alertOn(2, "u1", DeliveryEmail))
	store.emails["u1"] = "u1@example.com"
	refused := fmt.Errorf("mailer: rcpt: %w", &mailer.SendError{Status: 550, Permanent: true, Msg: "no such user"})
	ed := &fakeDeliverer{kind: ChannelEmail, errs: map[int64]error{1: refused}}
	deps := evalDeps(store, &fakeDeliverer{}, 13)
	deps.Deliverers = append(deps.Deliverers, ed)
	sum := runEvaluation(context.Background(), deps, buylistOnly)

	if len(ed.digests) != 1 || !slices.Equal(firingIDs(ed.digests[0]), []int64{1, 2}) {
		t.Fatalf("digests = %+v", ed.digests)
	}
	// The user sees a fixed reason; the provider's text stays in the event.
	parked := store.states[1]
	if parked.Status != StatusUndeliverable || parked.LastError != "this address refused our mail" || parked.LastFiredAt != nil {
		t.Fatalf("refused alert state = %+v", parked)
	}
	kept := store.states[2]
	if kept.Status != StatusActive || kept.LastError != "" || kept.LastFiredAt == nil || !kept.LastFiredAt.Equal(evalNow) {
		t.Fatalf("delivered alert state = %+v", kept)
	}
	ev := eventsFor(store, 1)
	if len(ev) != 1 || ev[0].Delivered || !strings.Contains(ev[0].Error, "no such user") {
		t.Fatalf("refused alert events = %+v", ev)
	}
	ev = eventsFor(store, 2)
	if len(ev) != 1 || !ev[0].Delivered {
		t.Fatalf("delivered alert events = %+v", ev)
	}
	// A refusal parks without counting as a run problem, as a refused DM does.
	if sum.sent != 1 || sum.problem() != "" {
		t.Fatalf("summary = %s, problem %q", sum, sum.problem())
	}
}

func TestRunKeepsDailyLimitedAlertsActive(t *testing.T) {
	store := newFakeEvalStore(alertOn(1, "u1", DeliveryEmail))
	store.emails["u1"] = "u1@example.com"
	ed := &fakeDeliverer{kind: ChannelEmail, err: fmt.Errorf("mail: %w", ErrDailyLimit)}
	deps := evalDeps(store, &fakeDeliverer{}, 13)
	deps.Deliverers = append(deps.Deliverers, ed)
	sum := runEvaluation(context.Background(), deps, buylistOnly)

	st := store.states[1]
	if st.Status != StatusActive || !st.AboveArmed || !st.BelowArmed || st.LastFiredAt != nil || st.LastError != "daily email limit reached, will retry" {
		t.Fatalf("state = %+v", st)
	}
	ev := eventsFor(store, 1)
	if len(ev) != 1 || ev[0].Delivered || ev[0].Error == "" {
		t.Fatalf("events = %+v", ev)
	}
	if sum.skipped != 1 || sum.sent != 0 || sum.deferred != 1 || sum.problem() != "" {
		t.Fatalf("summary = %s, problem %q", sum, sum.problem())
	}
	if !strings.Contains(sum.String(), "1 deferred") {
		t.Fatalf("String omitted deferred: %s", sum)
	}
}

// TestRunCountsMailsAndDisabledChannels covers the three admin counters
// String adds beside the long-standing ones: a distinct message id per
// successful send, and channels a bounce or complaint disabled since the
// previous run, read through Since.
func TestRunCountsMailsAndDisabledChannels(t *testing.T) {
	store := newFakeEvalStore(alertOn(1, "u1", DeliveryEmail), alertOn(2, "u1", DeliveryEmail))
	store.emails["u1"] = "u1@example.com"
	store.disabledSince = 2
	ed := &fakeDeliverer{kind: ChannelEmail, messageID: "msg-1"}
	deps := evalDeps(store, &fakeDeliverer{}, 13)
	deps.Deliverers = append(deps.Deliverers, ed)
	deps.Since = func() time.Time { return evalNow.Add(-time.Hour) }
	sum := runEvaluation(context.Background(), deps, buylistOnly)

	// One digest covers both firings, so one provider id, not two.
	if sum.mails != 1 || sum.sent != 2 {
		t.Fatalf("mails = %d sent = %d, want one mail for two firings", sum.mails, sum.sent)
	}
	if sum.disabled != 2 || !store.disabledUntil.Equal(evalNow) || !sum.start.Equal(evalNow) {
		t.Fatalf("disabled = %d until %s start %s, want the store's count up to this run's start", sum.disabled, store.disabledUntil, sum.start)
	}
	if !strings.Contains(sum.String(), "1 mails") || !strings.Contains(sum.String(), "2 channels disabled") {
		t.Fatalf("String omitted mails or disabled: %s", sum)
	}

	// No Since, as before the service's first run completes, counts nothing.
	store2 := newFakeEvalStore(alertOn(3, "u2", DeliveryDiscord))
	deps2 := evalDeps(store2, &fakeDeliverer{}, 13)
	sum2 := runEvaluation(context.Background(), deps2, buylistOnly)
	if sum2.disabled != 0 || strings.Contains(sum2.String(), "disabled") {
		t.Fatalf("first run counted disabled channels: %s", sum2)
	}
}

// A tier that drops a channel parks its alerts in the same notice, once.
func TestRunParksDisallowedChannelInNotice(t *testing.T) {
	store := newFakeEvalStore(alertOn(1, "u1", DeliveryDiscord), alertOn(2, "u1", DeliveryEmail))
	store.emails["u1"] = "u1@example.com"
	dd := &fakeDeliverer{}
	ed := &fakeDeliverer{kind: ChannelEmail}
	deps := evalDeps(store, dd, 13)
	deps.Deliverers = append(deps.Deliverers, ed)
	deps.Channels = func(url.Values) []ChannelKind { return []ChannelKind{ChannelDiscord} }
	runEvaluation(context.Background(), deps, buylistOnly)

	if store.status[2] != StatusOverAllowance || !slices.Equal(store.allowed["u1"], []ChannelKind{ChannelDiscord}) {
		t.Fatalf("email alert status = %s, allowed = %v", store.status[2], store.allowed["u1"])
	}
	if len(dd.notices) != 1 || dd.noticeTo[0] != "d-u1" || strings.Count(dd.notices[0].Description, "Bolt LEA #161") != 1 ||
		!strings.Contains(dd.notices[0].Description, "delivery channel") {
		t.Fatalf("notices to %v:\n%v", dd.noticeTo, dd.notices)
	}
	if !slices.Equal(dd.ids(), []int64{1}) || len(ed.sent) != 0 {
		t.Fatalf("discord sent %v, email sent %v", dd.ids(), ed.ids())
	}
	// The allowance step leaves it parked, so the next run says nothing.
	runEvaluation(context.Background(), deps, buylistOnly)
	if len(dd.notices) != 1 || store.status[2] != StatusOverAllowance {
		t.Fatalf("second run: %d notices, status %s", len(dd.notices), store.status[2])
	}
}

// A tier without Alerts has no channels either; the allowance step parks
// with its own notice, not the channel one.
func TestRunTierWithoutAlertsSendsTheAlertsNotice(t *testing.T) {
	store := newFakeEvalStore(alertOn(1, "u1", DeliveryDiscord), alertOn(2, "u1", DeliveryEmail))
	store.emails["u1"] = "u1@example.com"
	dd := &fakeDeliverer{}
	deps := evalDeps(store, dd, 13)
	deps.Deliverers = append(deps.Deliverers, &fakeDeliverer{kind: ChannelEmail})
	deps.Values = func(string, string) url.Values { return url.Values{} }
	deps.Allowance = alertsMaxAllowance
	deps.Channels = func(url.Values) []ChannelKind { return nil }
	runEvaluation(context.Background(), deps, buylistOnly)

	if store.status[1] != StatusOverAllowance || store.status[2] != StatusOverAllowance || slices.Contains(store.steps, "channel:u1") {
		t.Fatalf("statuses %s %s, steps %v", store.status[1], store.status[2], store.steps)
	}
	if len(dd.notices) != 1 || !strings.Contains(dd.notices[0].Description, "no longer includes price alerts") ||
		strings.Contains(dd.notices[0].Description, "delivery channel") {
		t.Fatalf("notices %v", dd.notices)
	}
}

// The channel step runs before the allowance step, per user, so the
// allowance never ranks or restores a channel-parked alert.
func TestRunParksChannelsBeforeAllowance(t *testing.T) {
	store := newFakeEvalStore(alertOn(1, "u1", DeliveryDiscord), alertOn(2, "u2", DeliveryDiscord))
	runEvaluation(context.Background(), evalDeps(store, &fakeDeliverer{}, 11), buylistOnly)
	want := []string{"channel:u1", "allowance:u1", "channel:u2", "allowance:u2"}
	if !slices.Equal(store.steps, want) {
		t.Fatalf("steps = %v, want %v", store.steps, want)
	}
}

// An allowance-parked alert whose channel is dropped stays parked when
// room returns, and the notice does not repeat it.
func TestRunKeepsAllowanceParkedOffDisallowedChannel(t *testing.T) {
	email := alertOn(2, "u1", DeliveryEmail)
	email.Status = StatusOverAllowance
	store := newFakeEvalStore(alertOn(1, "u1", DeliveryDiscord), email)
	store.emails["u1"] = "u1@example.com"
	dd := &fakeDeliverer{}
	ed := &fakeDeliverer{kind: ChannelEmail}
	deps := evalDeps(store, dd, 13)
	deps.Deliverers = append(deps.Deliverers, ed)
	deps.Channels = func(url.Values) []ChannelKind { return []ChannelKind{ChannelDiscord} }
	runEvaluation(context.Background(), deps, buylistOnly)

	if store.status[2] != StatusOverAllowance || !store.chanParked[2] || len(ed.sent) != 0 || len(dd.notices) != 0 {
		t.Fatalf("status=%s chanParked=%v email sent=%v notices=%d", store.status[2], store.chanParked[2], ed.ids(), len(dd.notices))
	}
}

func TestRunWithoutDelivererLeavesAlertsAlone(t *testing.T) {
	store := newFakeEvalStore(alertOn(1, "u1", DeliveryEmail))
	store.emails["u1"] = "u1@example.com"
	sum := runEvaluation(context.Background(), evalDeps(store, &fakeDeliverer{}, 13), buylistOnly)
	if len(store.claims) != 0 || len(store.states) != 0 || len(store.events) != 0 {
		t.Fatalf("acted with no deliverer: claims=%v states=%+v events=%+v", store.claims, store.states, store.events)
	}
	if !strings.Contains(sum.problem(), "no email deliverer") || sum.skipped != 1 {
		t.Fatalf("summary = %s, problem %q", sum, sum.problem())
	}
}

func TestOthersOldestFirstCapped(t *testing.T) {
	var active []ActiveAlert
	for id := int64(1); id <= 14; id++ {
		active = append(active, alertOn(id, "u1", DeliveryDiscord))
	}
	active = append(active, alertOn(20, "u2", DeliveryDiscord))
	dg := &Digest{UserHash: "u1", Firings: []Firing{{Alert: active[13].Alert}}}
	got := othersFor(active, dg, map[int64]bool{12: true})
	var ids []int64
	for _, a := range got {
		ids = append(ids, a.ID)
	}
	// 14 fired and 12 stopped; the rest oldest (highest id) first, ten of them.
	if !slices.Equal(ids, []int64{13, 11, 10, 9, 8, 7, 6, 5, 4, 3}) {
		t.Fatalf("others = %v", ids)
	}
}

// The real Discord deliverer carries the park notice and the firing on one
// sender, to the channel's address, as the run's DMs did before.
func TestRunDiscordDelivererSendsNoticeAndFiring(t *testing.T) {
	older := activeAlert()
	newer := activeAlert()
	newer.ID = 8
	store := newFakeEvalStore(older, newer)
	sender := &fakeSender{}
	deps := evalDeps(store, &fakeDeliverer{}, 13)
	deps.Deliverers = []Deliverer{NewDiscordDeliverer(sender, 0)}
	deps.Allowance = func(url.Values) int { return 1 }
	runEvaluation(context.Background(), deps, buylistOnly)

	if !slices.Equal(sender.sent, []string{"d1", "d1"}) {
		t.Fatalf("sent = %v", sender.sent)
	}
	if sender.embeds[0].Title != "Price alerts parked" {
		t.Fatalf("first DM = %q, want the notice", sender.embeds[0].Title)
	}
	e := sender.embeds[1]
	if e.URL != "https://lorcana.mtgban.com/alerts" || !strings.Contains(e.Description, "https://lorcana.mtgban.com/go/b/CK/card-1") {
		t.Fatalf("links: url=%q\n%s", e.URL, e.Description)
	}
}
