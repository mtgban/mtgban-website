package alerts

import (
	"context"
	"database/sql"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/timeseries"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	if os.Getenv("USERSTATE_TEST") == "" {
		t.Skip("USERSTATE_TEST not set; skipping DB integration test")
	}
	cfg := timeseries.SQLConfig{
		Host: "127.0.0.1", Port: 5432, User: "mtgban",
		Password: "mtgban", DBName: "user_state", SSLMode: "disable",
	}
	// USERSTATE_TEST_HOST and USERSTATE_TEST_PORT point the test elsewhere.
	host := os.Getenv("USERSTATE_TEST_HOST")
	if host != "" {
		cfg.Host = host
	}
	port, err := strconv.Atoi(os.Getenv("USERSTATE_TEST_PORT"))
	if err == nil {
		cfg.Port = port
	}
	db, err := sql.Open("postgres", cfg.DSN())
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(db)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// freshUser returns a user hash unique to the test with no rows behind it.
func freshUser(t *testing.T, s *Store) string {
	t.Helper()
	h := "test-" + t.Name()
	clean := func() {
		_, _ = s.db.Exec(`DELETE FROM alerts WHERE user_hash = $1`, h)
		_, _ = s.db.Exec(`DELETE FROM alert_channels WHERE user_hash = $1`, h)
		_, _ = s.db.Exec(`DELETE FROM alert_contacts WHERE user_hash = $1`, h)
	}
	clean()
	t.Cleanup(clean)
	return h
}

// cleanUser clears a fixed, hand-picked user hash before and after a test
// that cannot use freshUser because it shares its hash with the brief's
// literal test code.
func cleanUser(t *testing.T, s *Store, h string) {
	t.Helper()
	clean := func() {
		_, _ = s.db.Exec(`DELETE FROM alerts WHERE user_hash = $1`, h)
		_, _ = s.db.Exec(`DELETE FROM alert_channels WHERE user_hash = $1`, h)
		_, _ = s.db.Exec(`DELETE FROM alert_contacts WHERE user_hash = $1`, h)
	}
	clean()
	t.Cleanup(clean)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestContactUpsertAndRead(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	ctx := context.Background()

	_, found, err := s.Contact(ctx, h)
	if err != nil || found {
		t.Fatalf("missing contact: found=%v err=%v", found, err)
	}
	err = s.UpsertContact(ctx, Contact{UserHash: h, DiscordKnown: true, DiscordUserID: "123", Tier: "Legacy"})
	if err != nil {
		t.Fatalf("UpsertContact: %v", err)
	}
	c, found, err := s.Contact(ctx, h)
	if err != nil || !found {
		t.Fatalf("Contact after upsert: found=%v err=%v", found, err)
	}
	if c.DiscordUserID != "123" || c.Tier != "Legacy" {
		t.Fatalf("unexpected contact %+v", c)
	}

	// A verified login that knows Discord is unlinked clears the id.
	err = s.UpsertContact(ctx, Contact{UserHash: h, DiscordKnown: true, Tier: "Vintage"})
	if err != nil {
		t.Fatalf("UpsertContact clear: %v", err)
	}
	c, _, _ = s.Contact(ctx, h)
	if c.DiscordUserID != "" || c.Tier != "Vintage" {
		t.Fatalf("unexpected contact after clear %+v", c)
	}
}

// TestUpsertContactUnknownDiscordKeepsExistingID covers a login whose
// Patreon answer had no opinion on the Discord id at all.
func TestUpsertContactUnknownDiscordKeepsExistingID(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	ctx := context.Background()

	err := s.UpsertContact(ctx, Contact{UserHash: h, DiscordKnown: true, DiscordUserID: "222", Tier: "Legacy"})
	if err != nil {
		t.Fatalf("seed UpsertContact: %v", err)
	}
	err = s.UpsertContact(ctx, Contact{UserHash: h, DiscordKnown: false, DiscordUserID: "999", Tier: "Modern"})
	if err != nil {
		t.Fatalf("UpsertContact unknown: %v", err)
	}
	c, _, _ := s.Contact(ctx, h)
	if c.DiscordUserID != "222" {
		t.Fatalf("unknown-discord login changed the discord id: %+v", c)
	}
	if c.Tier != "Modern" {
		t.Fatalf("tier should still update: %+v", c)
	}
}

// TestUpsertContactExplicitEmptyClearsWhenKnownAndVerified covers the third
// case: a verified login that knows Discord is unlinked (empty id) clears it.
func TestUpsertContactExplicitEmptyClearsWhenKnownAndVerified(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	ctx := context.Background()

	err := s.UpsertContact(ctx, Contact{UserHash: h, DiscordKnown: true, DiscordUserID: "333", Tier: "Legacy"})
	if err != nil {
		t.Fatalf("seed UpsertContact: %v", err)
	}
	err = s.UpsertContact(ctx, Contact{UserHash: h, DiscordKnown: true, DiscordUserID: "", Tier: "Legacy"})
	if err != nil {
		t.Fatalf("UpsertContact clear: %v", err)
	}
	c, _, _ := s.Contact(ctx, h)
	if c.DiscordUserID != "" {
		t.Fatalf("known, verified empty id should clear: %+v", c)
	}
}

func TestEnsureContactKeepsDiscordID(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	ctx := context.Background()

	err := s.EnsureContact(ctx, h, "Modern")
	if err != nil {
		t.Fatalf("EnsureContact new: %v", err)
	}
	err = s.UpsertContact(ctx, Contact{UserHash: h, DiscordKnown: true, DiscordUserID: "9", Tier: "Modern"})
	if err != nil {
		t.Fatalf("UpsertContact: %v", err)
	}
	err = s.EnsureContact(ctx, h, "Legacy")
	if err != nil {
		t.Fatalf("EnsureContact existing: %v", err)
	}
	c, _, _ := s.Contact(ctx, h)
	if c.DiscordUserID != "9" || c.Tier != "Modern" {
		t.Fatalf("EnsureContact must only insert, tier stays login's: %+v", c)
	}
}

// TestRefreshContactTierOnlyUpdatesExistingRows covers that RefreshContactTier
// never creates a row; it only moves the tier on one that already exists.
func TestRefreshContactTierOnlyUpdatesExistingRows(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	ctx := context.Background()

	err := s.RefreshContactTier(ctx, h, "Modern")
	if err != nil {
		t.Fatalf("RefreshContactTier unknown hash: %v", err)
	}
	_, found, _ := s.Contact(ctx, h)
	if found {
		t.Fatal("RefreshContactTier inserted a row for an unknown hash")
	}

	seedContact(t, s, h)
	before, _, _ := s.Contact(ctx, h)

	time.Sleep(10 * time.Millisecond)
	err = s.RefreshContactTier(ctx, h, "Vintage")
	if err != nil {
		t.Fatalf("RefreshContactTier: %v", err)
	}
	after, found, _ := s.Contact(ctx, h)
	if !found {
		t.Fatal("seeded contact missing after refresh")
	}
	if after.Tier != "Vintage" {
		t.Fatalf("tier = %q, want Vintage", after.Tier)
	}
	if !after.UpdatedAt.After(before.UpdatedAt) {
		t.Fatalf("updated_at not bumped: before=%v after=%v", before.UpdatedAt, after.UpdatedAt)
	}
}

func seedContact(t *testing.T, s *Store, h string) {
	t.Helper()
	err := s.UpsertContact(context.Background(), Contact{UserHash: h, DiscordUserID: "1", DiscordKnown: true, Tier: "Legacy"})
	if err != nil {
		t.Fatal(err)
	}
}

func sample(h string) Alert {
	return Alert{
		UserHash: h, Game: "magic", CardID: "card-1", Side: SideBuylist, Condition: "NM",
		Stores: []string{"CK"}, ReferencePrice: 10,
		Above: Threshold{Kind: KindAbs, Value: 12}, Below: Threshold{Kind: KindPct, Value: 15},
		Delivery: DeliveryDiscord, Card: Card{Name: "Bolt", Set: "LEA", Number: "161", Finish: "nonfoil"},
		AboveArmed: true, BelowArmed: true,
	}
}

func TestCreateAndUpdateWriteArmedStateAndOrigin(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()

	a := sample(h)
	a.BelowArmed, a.Origin = false, "https://lorcana.mtgban.com"
	created, err := s.Create(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if !created.AboveArmed || created.BelowArmed || created.Origin != "https://lorcana.mtgban.com" {
		t.Fatalf("Create armed above=%v below=%v origin=%q", created.AboveArmed, created.BelowArmed, created.Origin)
	}
	edit := created
	edit.AboveArmed, edit.BelowArmed, edit.Origin = false, true, "https://mtgban.com"
	ok, err := s.Update(ctx, edit)
	if err != nil || !ok {
		t.Fatalf("Update: ok=%v err=%v", ok, err)
	}
	got, _, _ := s.Get(ctx, created.ID, h)
	if got.AboveArmed || !got.BelowArmed || got.Origin != "https://mtgban.com" {
		t.Fatalf("Update armed above=%v below=%v origin=%q", got.AboveArmed, got.BelowArmed, got.Origin)
	}
}

func TestCreateListGetDelete(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()

	price := 11.0
	a := sample(h)
	a.CreatedPrice = &price
	created, err := s.Create(ctx, a)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == 0 || created.Status != StatusActive || !created.AboveArmed || !created.BelowArmed {
		t.Fatalf("unexpected created row %+v", created)
	}

	list, err := s.ListByUser(ctx, h, "magic")
	if err != nil || len(list) != 1 {
		t.Fatalf("ListByUser: n=%d err=%v", len(list), err)
	}
	got := list[0]
	if got.CardID != "card-1" || got.Stores[0] != "CK" || got.Above.Value != 12 || got.Below.Kind != KindPct || *got.CreatedPrice != 11 || got.Card.Name != "Bolt" {
		t.Fatalf("round trip lost fields: %+v", got)
	}
	other, _ := s.ListByUser(ctx, h, "lorcana")
	if len(other) != 0 {
		t.Fatal("another game sees the alert")
	}
	n, _ := s.CountByUser(ctx, h, "magic")
	if n != 1 {
		t.Fatalf("CountByUser = %d, want 1", n)
	}

	_, found, _ := s.Get(ctx, created.ID, "someone-else")
	if found {
		t.Fatal("Get answered for another user")
	}
	ok, _ := s.Delete(ctx, created.ID, "someone-else")
	if ok {
		t.Fatal("Delete worked for another user")
	}
	ok, err = s.Delete(ctx, created.ID, h)
	if err != nil || !ok {
		t.Fatalf("Delete: ok=%v err=%v", ok, err)
	}
}

func TestUpdateRearmsAndSetStatus(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()

	created, err := s.Create(ctx, sample(h))
	if err != nil {
		t.Fatal(err)
	}
	// Disarm through the evaluator's write, then edit: Update writes the
	// armed state it is handed.
	fired := time.Now()
	_, err = s.SetState(ctx, created.ID, created.UpdatedAt, State{Status: StatusActive, AboveArmed: false, BelowArmed: true, LastFiredAt: &fired})
	if err != nil {
		t.Fatal(err)
	}
	edit := created
	edit.Above = Threshold{Kind: KindAbs, Value: 20}
	edit.Stores = []string{"CK", "SCG"}
	ok, err := s.Update(ctx, edit)
	if err != nil || !ok {
		t.Fatalf("Update: ok=%v err=%v", ok, err)
	}
	got, _, _ := s.Get(ctx, created.ID, h)
	if got.Above.Value != 20 || len(got.Stores) != 2 || !got.AboveArmed {
		t.Fatalf("Update did not apply or re-arm: %+v", got)
	}

	ok, _ = s.SetStatus(ctx, created.ID, h, StatusPaused)
	if !ok {
		t.Fatal("SetStatus paused")
	}
	got, _, _ = s.Get(ctx, created.ID, h)
	if got.Status != StatusPaused {
		t.Fatalf("status = %s, want paused", got.Status)
	}
}

func TestEventsLastPerAlert(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	created, _ := s.Create(ctx, sample(h))

	for i, p := range []float64{12, 13} {
		e := Event{AlertID: created.ID, FiredAt: time.Now().Add(time.Duration(i) * time.Minute), Threshold: "above", Store: "CK", Price: p, Delivered: true}
		err := s.AddEvent(ctx, e)
		if err != nil {
			t.Fatal(err)
		}
	}
	last, err := s.LastEvents(ctx, []int64{created.ID})
	if err != nil || last[created.ID].Price != 13 {
		t.Fatalf("LastEvents = %+v err=%v", last, err)
	}
}

// TestReserveMailKeepsTheCeiling covers the mail ledger: it counts one
// user's mails in the last 24 hours, whatever happens to their alerts, a
// released reservation does not count, and concurrent reservations at the
// last slot let only one through.
func TestReserveMailKeepsTheCeiling(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	clean := func() {
		_, _ = s.db.Exec(`DELETE FROM alert_mails WHERE user_hash = $1 OR user_hash = $2`, h, h+"-other")
	}
	clean()
	t.Cleanup(clean)
	now := time.Now()
	reserve := func(user string, at time.Time) bool {
		t.Helper()
		_, ok, err := s.ReserveMail(ctx, user, at, 3)
		must(t, err)
		return ok
	}
	if !reserve(h, now.Add(-25*time.Hour)) || !reserve(h, now) || !reserve(h, now) {
		t.Fatal("reservations under the ceiling refused")
	}
	failed, ok, err := s.ReserveMail(ctx, h, now, 3)
	if err != nil || !ok {
		t.Fatalf("third mail in the day: %v %v", ok, err)
	}
	must(t, s.ReleaseMail(ctx, failed))
	// Deleting the user's alerts leaves the ledger as it was.
	a, err := s.Create(ctx, sample(h))
	must(t, err)
	_, err = s.Delete(ctx, a.ID, h)
	must(t, err)
	if !reserve(h, now) || reserve(h, now) {
		t.Fatal("ceiling of three in the day not kept")
	}
	if !reserve(h+"-other", now) {
		t.Fatal("another user's ledger is not this one's")
	}

	// A reservation racing another for the last slot waits for it, then
	// counts it: here the other holds the user's lock and takes the slot.
	_, err = s.db.Exec(`DELETE FROM alert_mails WHERE user_hash = $1`, h)
	must(t, err)
	reserve(h, now)
	reserve(h, now)
	other, err := s.db.BeginTx(ctx, nil)
	must(t, err)
	defer func() { _ = other.Rollback() }()
	_, err = other.Exec(`SELECT pg_advisory_xact_lock($1, hashtext($2))`, mailLockID, h)
	must(t, err)
	result := make(chan bool, 1)
	go func() {
		_, ok, err := s.ReserveMail(ctx, h, now, 3)
		result <- ok && err == nil
	}()
	select {
	case <-result:
		t.Fatal("reservation did not wait for the one holding the lock")
	case <-time.After(200 * time.Millisecond):
	}
	_, err = other.Exec(`INSERT INTO alert_mails (user_hash, sent_at) VALUES ($1, $2)`, h, now)
	must(t, err)
	must(t, other.Commit())
	if <-result {
		t.Fatal("both reservations took the last slot")
	}
}

// TestNewLedgerBackfillsTheDay covers the deploy that creates alert_mails:
// it starts with the last day's mails as alert events counted them, one
// per message id, and a later start adds nothing.
func TestNewLedgerBackfillsTheDay(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	a, err := s.Create(ctx, sample(h))
	must(t, err)
	now := time.Now()
	for _, e := range []Event{
		{AlertID: a.ID, FiredAt: now, Threshold: "above", Store: "CK", Price: 1, Delivered: true, MessageID: "m1"},
		{AlertID: a.ID, FiredAt: now, Threshold: "below", Store: "SCG", Price: 2, Delivered: true, MessageID: "m1"},
		{AlertID: a.ID, FiredAt: now, Threshold: "above", Store: "CK", Price: 3, Delivered: true, MessageID: "m2"},
		{AlertID: a.ID, FiredAt: now.Add(-25 * time.Hour), Threshold: "above", Store: "CK", Price: 4, Delivered: true, MessageID: "m0"},
		{AlertID: a.ID, FiredAt: now, Threshold: "above", Store: "CK", Price: 5, Delivered: false},
	} {
		must(t, s.AddEvent(ctx, e))
	}
	_, err = s.db.ExecContext(ctx, `DROP TABLE alert_mails`)
	must(t, err)
	count := func() int {
		t.Helper()
		var n int
		must(t, s.db.QueryRowContext(ctx, `SELECT count(*) FROM alert_mails WHERE user_hash = $1`, h).Scan(&n))
		return n
	}
	for range 2 {
		_, err = New(s.db)
		must(t, err)
		if n := count(); n != 2 {
			t.Fatalf("ledger holds %d of the user's mails, want 2", n)
		}
	}
}

func TestListActiveJoinsContact(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	a, _ := s.Create(ctx, sample(h))
	r := sample(h)
	r.Side = SideRetail
	_, _ = s.Create(ctx, r)
	paused, _ := s.Create(ctx, sample(h))
	_, _ = s.SetStatus(ctx, paused.ID, h, StatusPaused)

	active, err := s.ListActive(ctx, "magic", []Side{SideBuylist})
	if err != nil {
		t.Fatal(err)
	}
	var mine []ActiveAlert
	for _, x := range active {
		if x.UserHash == h {
			mine = append(mine, x)
		}
	}
	if len(mine) != 1 || mine[0].ID != a.ID || mine[0].Contact.DiscordUserID != "1" || mine[0].Contact.Tier != "Legacy" {
		t.Fatalf("active = %+v", mine)
	}
}

func TestSetStateSkipsPausedRows(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	a, _ := s.Create(ctx, sample(h))
	_, _ = s.SetStatus(ctx, a.ID, h, StatusPaused)
	paused, _, _ := s.Get(ctx, a.ID, h)
	ok, err := s.SetState(ctx, a.ID, paused.UpdatedAt, State{Status: StatusUnresolvable})
	if err != nil || ok {
		t.Fatalf("SetState touched a paused row: ok=%v err=%v", ok, err)
	}
}

func TestSetStateSkipsRowsEditedSinceListed(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	listed, _ := s.Create(ctx, sample(h))
	edit := listed
	edit.Above = Threshold{Kind: KindAbs, Value: 20}
	ok, err := s.Update(ctx, edit)
	if err != nil || !ok {
		t.Fatalf("Update: ok=%v err=%v", ok, err)
	}
	ok, err = s.SetState(ctx, listed.ID, listed.UpdatedAt, State{Status: StatusActive, AboveArmed: true, BelowArmed: true})
	if err != nil || ok {
		t.Fatalf("SetState overwrote an edit made after the listing: ok=%v err=%v", ok, err)
	}
}

func TestMarkOverAllowanceKeepsTheNewest(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	var ids []int64
	for i := 0; i < 3; i++ {
		a, _ := s.Create(ctx, sample(h))
		ids = append(ids, a.ID)
		time.Sleep(5 * time.Millisecond)
	}
	moved, err := s.MarkOverAllowance(ctx, h, "magic", 2)
	if err != nil || len(moved) != 1 || moved[0].ID != ids[0] || moved[0].Status != StatusOverAllowance ||
		moved[0].Card.Name != "Bolt" || moved[0].Side != SideBuylist || moved[0].Condition != "NM" {
		t.Fatalf("mark: moved=%+v err=%v", moved, err)
	}
	oldest, _, _ := s.Get(ctx, ids[0], h)
	newest, _, _ := s.Get(ctx, ids[2], h)
	if oldest.Status != StatusOverAllowance || newest.Status != StatusActive {
		t.Fatalf("oldest=%s newest=%s", oldest.Status, newest.Status)
	}
	moved, _ = s.MarkOverAllowance(ctx, h, "magic", 0)
	if len(moved) != 2 || moved[0].ID != ids[2] || moved[1].ID != ids[1] {
		t.Fatalf("park all: moved=%+v, want the two still active, newest first", moved)
	}
	moved, _ = s.MarkOverAllowance(ctx, h, "magic", 5)
	if len(moved) != 3 || moved[0].Status != StatusActive {
		t.Fatalf("restore: moved=%+v, want all three back", moved)
	}
	oldest, _, _ = s.Get(ctx, ids[0], h)
	if oldest.Status != StatusActive {
		t.Fatalf("not restored: %s", oldest.Status)
	}
}

func TestPruneEvents(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	a, _ := s.Create(ctx, sample(h))
	old := Event{AlertID: a.ID, FiredAt: time.Now().Add(-100 * 24 * time.Hour), Threshold: "above", Store: "CK", Price: 1, Delivered: true}
	_ = s.AddEvent(ctx, old)
	_ = s.AddEvent(ctx, Event{AlertID: a.ID, FiredAt: time.Now(), Threshold: "above", Store: "CK", Price: 2, Delivered: true})
	n, err := s.PruneEvents(ctx, time.Now().Add(-90*24*time.Hour))
	if err != nil || n < 1 {
		t.Fatalf("prune: n=%d err=%v", n, err)
	}
	last, _ := s.LastEvents(ctx, []int64{a.ID})
	if last[a.ID].Price != 2 {
		t.Fatalf("pruned the wrong row: %+v", last[a.ID])
	}
}

func TestUsersWithAlertsIncludesParked(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	a, _ := s.Create(ctx, sample(h))
	_, err := s.MarkOverAllowance(ctx, h, "magic", 0)
	if err != nil {
		t.Fatal(err)
	}
	got, _, _ := s.Get(ctx, a.ID, h)
	if got.Status != StatusOverAllowance {
		t.Fatalf("not parked: %s", got.Status)
	}
	find := func() (Contact, bool) {
		users, err := s.UsersWithAlerts(ctx, "magic")
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range users {
			if c.UserHash == h {
				return c, true
			}
		}
		return Contact{}, false
	}
	c, ok := find()
	if !ok || c.Tier != "Legacy" || c.DiscordUserID != "1" {
		t.Fatalf("parked user missing or wrong: %+v ok=%v", c, ok)
	}
	_, err = s.SetStatus(ctx, a.ID, h, StatusPaused)
	if err != nil {
		t.Fatal(err)
	}
	_, ok = find()
	if ok {
		t.Fatal("user with only a paused alert listed")
	}
	users, _ := s.UsersWithAlerts(ctx, "lorcana")
	for _, c := range users {
		if c.UserHash == h {
			t.Fatal("listed under another game")
		}
	}
}

// TestUsersWithAlertsAndListActiveCarryUpdatedAt covers the evaluator's
// staleness check: both queries must return the contact's login time.
func TestUsersWithAlertsAndListActiveCarryUpdatedAt(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	before, _, _ := s.Contact(ctx, h)
	if before.UpdatedAt.IsZero() {
		t.Fatal("seeded contact has a zero updated_at")
	}
	a, _ := s.Create(ctx, sample(h))

	users, err := s.UsersWithAlerts(ctx, "magic")
	if err != nil {
		t.Fatal(err)
	}
	var found Contact
	var ok bool
	for _, c := range users {
		if c.UserHash == h {
			found, ok = c, true
		}
	}
	if !ok || !found.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("UsersWithAlerts updated_at = %v, want %v (found=%v)", found.UpdatedAt, before.UpdatedAt, ok)
	}

	active, err := s.ListActive(ctx, "magic", []Side{SideBuylist})
	if err != nil {
		t.Fatal(err)
	}
	var row ActiveAlert
	ok = false
	for _, x := range active {
		if x.ID == a.ID {
			row, ok = x, true
		}
	}
	if !ok || !row.Contact.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("ListActive contact updated_at = %v, want %v (found=%v)", row.Contact.UpdatedAt, before.UpdatedAt, ok)
	}
}

func TestClaimFireComparesAndSets(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	a, _ := s.Create(ctx, sample(h))

	ok, err := s.ClaimFire(ctx, a.ID, a.UpdatedAt, false, true, false, true)
	if err != nil || ok {
		t.Fatalf("stale flags claimed: ok=%v err=%v", ok, err)
	}
	ok, err = s.ClaimFire(ctx, a.ID, a.UpdatedAt.Add(-time.Second), true, true, false, true)
	if err != nil || ok {
		t.Fatalf("stale updated_at claimed: ok=%v err=%v", ok, err)
	}
	got, _, _ := s.Get(ctx, a.ID, h)
	if !got.AboveArmed || !got.BelowArmed || got.LastFiredAt != nil {
		t.Fatalf("failed claim changed the row: %+v", got)
	}

	ok, err = s.ClaimFire(ctx, a.ID, a.UpdatedAt, true, true, false, true)
	if err != nil || !ok {
		t.Fatalf("matching claim refused: ok=%v err=%v", ok, err)
	}
	got, _, _ = s.Get(ctx, a.ID, h)
	if got.AboveArmed || !got.BelowArmed || got.LastFiredAt != nil {
		t.Fatalf("claim wrote %+v", got)
	}
	ok, _ = s.ClaimFire(ctx, a.ID, a.UpdatedAt, true, true, false, true)
	if ok {
		t.Fatal("second claim of the same crossing succeeded")
	}
}

func TestChannelsResolveUserOverPatreonAndSkipDisabled(t *testing.T) {
	s := testStore(t)
	cleanUser(t, s, "u1")
	ctx := context.Background()
	if err := s.UpsertContact(ctx, Contact{UserHash: "u1", Tier: "Legacy", DiscordKnown: true, DiscordUserID: "d1"}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	must(t, s.UpsertChannel(ctx, Channel{UserHash: "u1", Kind: ChannelEmail, Address: "ann@patreon.example", Source: SourcePatreon, VerifiedAt: &now}))
	ch, ok, err := s.ChannelFor(ctx, "u1", ChannelEmail)
	if err != nil || !ok || ch.Address != "ann@patreon.example" || ch.Source != SourcePatreon {
		t.Fatalf("patreon fallback: %+v %v %v", ch, ok, err)
	}
	must(t, s.UpsertChannel(ctx, Channel{UserHash: "u1", Kind: ChannelEmail, Address: "ann@other.example", Source: SourceUser}))
	ch, _, _ = s.ChannelFor(ctx, "u1", ChannelEmail)
	if ch.Source != SourcePatreon {
		t.Fatalf("unverified user row must not win: %+v", ch)
	}
	ok, err = s.SetChannelVerified(ctx, "u1", ChannelEmail, SourceUser, "ann@other.example", now)
	if err != nil || !ok {
		t.Fatalf("verify: %v %v", ok, err)
	}
	ch, _, _ = s.ChannelFor(ctx, "u1", ChannelEmail)
	if ch.Address != "ann@other.example" {
		t.Fatalf("verified user row must win: %+v", ch)
	}
	must(t, s.DisableChannel(ctx, "u1", ChannelEmail, SourceUser, "bounced", now))
	ch, _, _ = s.ChannelFor(ctx, "u1", ChannelEmail)
	if ch.Source != SourcePatreon {
		t.Fatalf("disabled user row must fall back: %+v", ch)
	}
	must(t, s.DisableChannel(ctx, "u1", ChannelEmail, SourcePatreon, "unsubscribed", now))
	if _, ok, _ := s.ChannelFor(ctx, "u1", ChannelEmail); ok {
		t.Fatal("both disabled must give none")
	}
	// Discord reads through the legacy column when no row exists.
	d, ok, _ := s.ChannelFor(ctx, "u1", ChannelDiscord)
	if !ok || d.Address != "d1" || d.VerifiedAt == nil {
		t.Fatalf("discord read-through: %+v %v", d, ok)
	}
	// An explicit, disabled discord row beats the legacy fallback: disabled means none.
	must(t, s.UpsertChannel(ctx, Channel{UserHash: "u1", Kind: ChannelDiscord, Address: "d1", Source: SourcePatreon, VerifiedAt: &now}))
	must(t, s.DisableChannel(ctx, "u1", ChannelDiscord, SourcePatreon, "opted out", now))
	if _, ok, _ := s.ChannelFor(ctx, "u1", ChannelDiscord); ok {
		t.Fatal("disabled discord row must not fall back to the legacy column")
	}
}

func TestChannelByAddressAndPrune(t *testing.T) {
	s := testStore(t)
	cleanUser(t, s, "u2")
	ctx := context.Background()
	must(t, s.UpsertContact(ctx, Contact{UserHash: "u2", Tier: "Legacy"}))
	must(t, s.UpsertChannel(ctx, Channel{UserHash: "u2", Kind: ChannelEmail, Address: "Bob@Example.com", Source: SourceUser}))
	rows, err := s.ChannelByAddress(ctx, ChannelEmail, "bob@example.com")
	if err != nil || len(rows) != 1 || rows[0].UserHash != "u2" {
		t.Fatalf("by address: %+v %v", rows, err)
	}
	n, err := s.PruneUnverifiedChannels(ctx, time.Now().Add(time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
	if rows, _ := s.ChannelByAddress(ctx, ChannelEmail, "bob@example.com"); len(rows) != 0 {
		t.Fatal("pruned row still there")
	}
}

func TestChannelsDisabledSince(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	now := time.Now()
	must(t, s.UpsertChannel(ctx, Channel{UserHash: h, Kind: ChannelEmail, Address: "d@example.com", Source: SourcePatreon}))

	before, after := now.Add(-time.Minute), now.Add(time.Minute)
	must(t, s.DisableChannel(ctx, h, ChannelEmail, SourcePatreon, "bounced", now))
	n, err := s.ChannelsDisabledSince(ctx, before, after)
	if err != nil || n != 1 {
		t.Fatalf("disabled since before: %d %v", n, err)
	}
	n, err = s.ChannelsDisabledSince(ctx, after, after.Add(time.Minute))
	if err != nil || n != 0 {
		t.Fatalf("disabled since after: %d %v", n, err)
	}
	n, err = s.ChannelsDisabledSince(ctx, before.Add(-time.Minute), before)
	if err != nil || n != 0 {
		t.Fatalf("disabled at or after until counted: %d %v", n, err)
	}

	_, err = s.EnableChannel(ctx, h, ChannelEmail, SourcePatreon)
	must(t, err)
	must(t, s.DisableChannel(ctx, h, ChannelEmail, SourcePatreon, "unsubscribed", now))
	n, err = s.ChannelsDisabledSince(ctx, before, after)
	if err != nil || n != 0 {
		t.Fatalf("a reason other than bounced/complained must not count: %d %v", n, err)
	}
}

// TestSetChannelVerifiedChecksAddressAndEnables covers the confirm link:
// it verifies only the address it was minted for, and clears a bounce.
func TestSetChannelVerifiedChecksAddressAndEnables(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	now := time.Now()
	must(t, s.UpsertChannel(ctx, Channel{UserHash: h, Kind: ChannelEmail, Address: "bob@example.com", Source: SourceUser}))
	must(t, s.DisableChannel(ctx, h, ChannelEmail, SourceUser, "bounced", now))
	ok, err := s.SetChannelVerified(ctx, h, ChannelEmail, SourceUser, "other@example.com", now)
	if err != nil || ok {
		t.Fatalf("stale address verified: %v %v", ok, err)
	}
	ok, err = s.SetChannelVerified(ctx, h, ChannelEmail, SourceUser, "Bob@Example.com", now)
	if err != nil || !ok {
		t.Fatalf("verify: %v %v", ok, err)
	}
	chans, err := s.Channels(ctx, h)
	if err != nil || len(chans) != 1 || !chans[0].Active() || chans[0].DisabledReason != "" {
		t.Fatalf("verified row: %+v err=%v", chans, err)
	}
}

// TestUpsertChannelNewAddressSurvivesThePrune covers an old verified row
// changed to a new address: it counts as new, so the prune keeps it.
func TestUpsertChannelNewAddressSurvivesThePrune(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	now := time.Now()
	must(t, s.UpsertChannel(ctx, Channel{UserHash: h, Kind: ChannelEmail, Address: "old@example.com", Source: SourceUser, VerifiedAt: &now}))
	_, err := s.db.ExecContext(ctx, `UPDATE alert_channels SET created_at = now() - interval '10 days' WHERE user_hash = $1`, h)
	must(t, err)
	must(t, s.UpsertChannel(ctx, Channel{UserHash: h, Kind: ChannelEmail, Address: "new@example.com", Source: SourceUser}))
	_, err = s.PruneUnverifiedChannels(ctx, now.Add(-unverifiedChannelMaxAge))
	must(t, err)
	chans, err := s.Channels(ctx, h)
	if err != nil || len(chans) != 1 || chans[0].Address != "new@example.com" || chans[0].VerifiedAt != nil {
		t.Fatalf("changed address pruned or still verified: %+v err=%v", chans, err)
	}
	// The same row left unverified past the age is pruned.
	_, err = s.db.ExecContext(ctx, `UPDATE alert_channels SET created_at = now() - interval '10 days' WHERE user_hash = $1`, h)
	must(t, err)
	_, err = s.PruneUnverifiedChannels(ctx, now.Add(-unverifiedChannelMaxAge))
	must(t, err)
	if chans, _ := s.Channels(ctx, h); len(chans) != 0 {
		t.Fatalf("stale unverified row kept: %+v", chans)
	}
}

// parkedEmailAlert creates an email alert parked undeliverable for reason.
func parkedEmailAlert(t *testing.T, s *Store, h, cardID, reason string) int64 {
	t.Helper()
	ctx := context.Background()
	a := sample(h)
	a.CardID, a.Delivery = cardID, DeliveryEmail
	created, err := s.Create(ctx, a)
	must(t, err)
	_, err = s.db.ExecContext(ctx, `UPDATE alerts SET status = 'undeliverable', last_error = $2 WHERE id = $1`, created.ID, reason)
	must(t, err)
	return created.ID
}

func alertStatus(t *testing.T, s *Store, h string, id int64) Status {
	t.Helper()
	a, ok, err := s.Get(context.Background(), id, h)
	if err != nil || !ok {
		t.Fatalf("get %d: %v %v", id, ok, err)
	}
	return a.Status
}

// TestEnableChannelRestoresParkedEmailAlerts covers Enable after an
// unsubscribe: alerts parked for the address come back, others stay.
func TestEnableChannelRestoresParkedEmailAlerts(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	now := time.Now()
	must(t, s.UpsertChannel(ctx, Channel{UserHash: h, Kind: ChannelEmail, Address: "pat@example.com", Source: SourcePatreon, VerifiedAt: &now}))
	must(t, s.DisableChannel(ctx, h, ChannelEmail, SourcePatreon, ReasonUnsubscribed, now))
	unsub := parkedEmailAlert(t, s, h, "card-1", ParkUnsubscribed)
	other := parkedEmailAlert(t, s, h, "card-2", "this address refused our mail")

	// A Discord enable leaves email alerts alone.
	_, err := s.EnableChannel(ctx, h, ChannelDiscord, SourcePatreon)
	must(t, err)
	if alertStatus(t, s, h, unsub) != StatusUndeliverable {
		t.Fatal("discord enable restored an email alert")
	}
	_, err = s.EnableChannel(ctx, h, ChannelEmail, SourcePatreon)
	must(t, err)
	if alertStatus(t, s, h, unsub) != StatusActive || alertStatus(t, s, h, other) != StatusUndeliverable {
		t.Fatalf("after enable: %s %s", alertStatus(t, s, h, unsub), alertStatus(t, s, h, other))
	}
}

// TestSetChannelVerifiedRestoresParkedEmailAlerts covers a first address
// confirmed after "no confirmed email address", and an unsubscribed row an
// old confirm link must not turn back on.
func TestSetChannelVerifiedRestoresParkedEmailAlerts(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	now := time.Now()
	must(t, s.UpsertChannel(ctx, Channel{UserHash: h, Kind: ChannelEmail, Address: "me@example.com", Source: SourceUser}))
	noAddr := parkedEmailAlert(t, s, h, "card-1", ParkNoAddress)
	ok, err := s.SetChannelVerified(ctx, h, ChannelEmail, SourceUser, "other@example.com", now)
	if err != nil || ok || alertStatus(t, s, h, noAddr) != StatusUndeliverable {
		t.Fatalf("unmatched confirm restored: %v %v", ok, err)
	}
	ok, err = s.SetChannelVerified(ctx, h, ChannelEmail, SourceUser, "me@example.com", now)
	if err != nil || !ok || alertStatus(t, s, h, noAddr) != StatusActive {
		t.Fatalf("confirm: %v %v status %s", ok, err, alertStatus(t, s, h, noAddr))
	}

	must(t, s.DisableChannel(ctx, h, ChannelEmail, SourceUser, ReasonUnsubscribed, now))
	unsub := parkedEmailAlert(t, s, h, "card-2", ParkUnsubscribed)
	ok, err = s.SetChannelVerified(ctx, h, ChannelEmail, SourceUser, "me@example.com", now)
	if err != nil || ok || alertStatus(t, s, h, unsub) != StatusUndeliverable {
		t.Fatalf("old confirm link undid an unsubscribe: %v %v", ok, err)
	}
}

// TestComplainedChannelStaysDisabled covers a row marked as spam: a later
// bounce or unsubscribe keeps the complaint and its time, and a confirm
// link no longer turns it back on.
func TestComplainedChannelStaysDisabled(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	first := time.Now().Add(-time.Hour).Truncate(time.Second)
	must(t, s.UpsertChannel(ctx, Channel{UserHash: h, Kind: ChannelEmail, Address: "me@example.com", Source: SourceUser, VerifiedAt: &first}))
	must(t, s.DisableChannel(ctx, h, ChannelEmail, SourceUser, ReasonComplained, first))
	parked := parkedEmailAlert(t, s, h, "card-1", ParkComplained)
	for _, reason := range []string{ReasonBounced, ReasonUnsubscribed} {
		must(t, s.DisableChannel(ctx, h, ChannelEmail, SourceUser, reason, time.Now()))
		chans, err := s.Channels(ctx, h)
		must(t, err)
		if chans[0].DisabledReason != ReasonComplained || chans[0].DisabledAt == nil || !chans[0].DisabledAt.Equal(first) {
			t.Fatalf("after %s: %+v", reason, chans[0])
		}
	}
	ok, err := s.SetChannelVerified(ctx, h, ChannelEmail, SourceUser, "me@example.com", time.Now())
	if err != nil || ok || alertStatus(t, s, h, parked) != StatusUndeliverable {
		t.Fatalf("confirm link undid a complaint: %v %v", ok, err)
	}
	// Enable refuses it too, whatever the caller read before.
	must(t, s.UpsertChannel(ctx, Channel{UserHash: h, Kind: ChannelEmail, Address: "pat@example.com", Source: SourcePatreon, VerifiedAt: &first}))
	must(t, s.DisableChannel(ctx, h, ChannelEmail, SourcePatreon, ReasonComplained, first))
	ok, err = s.EnableChannel(ctx, h, ChannelEmail, SourcePatreon)
	if err != nil || ok || alertStatus(t, s, h, parked) != StatusUndeliverable {
		t.Fatalf("enable undid a complaint: %v %v", ok, err)
	}
}

// TestConfirmMovesAVerifiedRowToItsReplacement covers a change of address:
// the verified row stays and shows its replacement as pending, another
// user asking for the same address takes nothing from this one, and only
// the requested address's link moves the row.
func TestConfirmMovesAVerifiedRowToItsReplacement(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	addr := "new-" + strings.ToLower(t.Name()) + "@example.com"
	clean := func() { _, _ = s.db.Exec(`DELETE FROM alert_confirm_sends WHERE address = $1`, addr) }
	clean()
	t.Cleanup(clean)
	now := time.Now()
	verified := now.Add(-4 * time.Hour)
	must(t, s.UpsertChannel(ctx, Channel{UserHash: h, Kind: ChannelEmail, Address: "old@example.com", Source: SourceUser, VerifiedAt: &verified}))
	claimed, err := s.ClaimConfirmSend(ctx, h, strings.ToUpper(addr), now.Add(-2*time.Hour), now.Add(-3*time.Hour))
	if err != nil || !claimed {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	claimed, err = s.ClaimConfirmSend(ctx, "someone-else", addr, now, now.Add(-time.Hour))
	if err != nil || !claimed {
		t.Fatalf("another user's claim an hour on: %v %v", claimed, err)
	}
	pending, ok, err := s.PendingEmail(ctx, h, time.Now().Add(-24*time.Hour))
	if err != nil || !ok || pending != addr {
		t.Fatalf("pending = %q %v %v", pending, ok, err)
	}

	ok, err = s.SetChannelVerified(ctx, h, ChannelEmail, SourceUser, "other@example.com", time.Now())
	if err != nil || ok {
		t.Fatalf("unrequested address verified: %v %v", ok, err)
	}
	// The working address's own link again changes nothing, and the
	// replacement's link stays good.
	ok, err = s.SetChannelVerified(ctx, h, ChannelEmail, SourceUser, "old@example.com", time.Now())
	if err != nil || !ok {
		t.Fatalf("working address confirmed again: %v %v", ok, err)
	}
	ok, err = s.SetChannelVerified(ctx, h, ChannelEmail, SourceUser, addr, time.Now())
	if err != nil || !ok {
		t.Fatalf("requested address: %v %v", ok, err)
	}
	chans, err := s.Channels(ctx, h)
	if err != nil || len(chans) != 1 || chans[0].Address != addr || !chans[0].Active() {
		t.Fatalf("row after the move: %+v %v", chans, err)
	}
	_, ok, err = s.PendingEmail(ctx, h, time.Now().Add(-24*time.Hour))
	if err != nil || ok {
		t.Fatalf("still pending after the move: %v %v", ok, err)
	}
}

// TestConfirmMovesOnlyOnTheCurrentRequest covers stale links: a request
// superseded by a newer one, or made before the row was last verified,
// moves nothing, and neither does any link once the row unsubscribed.
func TestConfirmMovesOnlyOnTheCurrentRequest(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	typo, right := "typo-"+strings.ToLower(t.Name())+"@example.com", "right-"+strings.ToLower(t.Name())+"@example.com"
	clean := func() { _, _ = s.db.Exec(`DELETE FROM alert_confirm_sends WHERE user_hash = $1`, h) }
	clean()
	t.Cleanup(clean)
	now := time.Now()
	verified := now.Add(-4 * time.Hour)
	must(t, s.UpsertChannel(ctx, Channel{UserHash: h, Kind: ChannelEmail, Address: "old@example.com", Source: SourceUser, VerifiedAt: &verified}))
	claim := func(addr string, at time.Time) {
		t.Helper()
		ok, err := s.ClaimConfirmSend(ctx, h, addr, at, at.Add(-time.Hour))
		if err != nil || !ok {
			t.Fatalf("claim %s: %v %v", addr, ok, err)
		}
	}
	claim(typo, now.Add(-3*time.Hour))
	claim(right, now.Add(-2*time.Hour))
	ok, err := s.SetChannelVerified(ctx, h, ChannelEmail, SourceUser, typo, now)
	if err != nil || ok {
		t.Fatalf("superseded link moved the row: %v %v", ok, err)
	}
	ok, err = s.SetChannelVerified(ctx, h, ChannelEmail, SourceUser, right, now)
	if err != nil || !ok {
		t.Fatalf("current link: %v %v", ok, err)
	}
	// The typo's link stays dead once the right address is verified.
	ok, err = s.SetChannelVerified(ctx, h, ChannelEmail, SourceUser, typo, now)
	if err != nil || ok {
		t.Fatalf("older link moved a newer verified row: %v %v", ok, err)
	}
	// An unsubscribed row does not move, even on the latest request.
	must(t, s.DisableChannel(ctx, h, ChannelEmail, SourceUser, ReasonUnsubscribed, now))
	claim(typo, now.Add(2*time.Hour))
	ok, err = s.SetChannelVerified(ctx, h, ChannelEmail, SourceUser, typo, now.Add(3*time.Hour))
	if err != nil || ok {
		t.Fatalf("link undid an unsubscribe: %v %v", ok, err)
	}
	chans, err := s.Channels(ctx, h)
	if err != nil || len(chans) != 1 || chans[0].Address != right || chans[0].DisabledReason != ReasonUnsubscribed {
		t.Fatalf("row after the refused links: %+v %v", chans, err)
	}
}

// TestFailedSendSupersedesNothing covers a request whose mail failed: the
// earlier address's link still moves the row, and that address, not the
// unsent one, shows as pending.
func TestFailedSendSupersedesNothing(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	sent, failed := "sent-"+strings.ToLower(t.Name())+"@example.com", "failed-"+strings.ToLower(t.Name())+"@example.com"
	clean := func() { _, _ = s.db.Exec(`DELETE FROM alert_confirm_sends WHERE user_hash = $1`, h) }
	clean()
	t.Cleanup(clean)
	now := time.Now().Truncate(time.Microsecond)
	verified := now.Add(-4 * time.Hour)
	must(t, s.UpsertChannel(ctx, Channel{UserHash: h, Kind: ChannelEmail, Address: "old@example.com", Source: SourceUser, VerifiedAt: &verified}))
	for _, c := range []struct {
		addr string
		at   time.Time
	}{{sent, now.Add(-3 * time.Hour)}, {failed, now.Add(-2 * time.Hour)}} {
		ok, err := s.ClaimConfirmSend(ctx, h, c.addr, c.at, c.at.Add(-time.Hour))
		if err != nil || !ok {
			t.Fatalf("claim %s: %v %v", c.addr, ok, err)
		}
	}
	must(t, s.ReleaseConfirmSend(ctx, h, failed, now.Add(-2*time.Hour)))
	pending, ok, err := s.PendingEmail(ctx, h, now.Add(-24*time.Hour))
	if err != nil || !ok || pending != sent {
		t.Fatalf("pending = %q %v %v, want the sent one", pending, ok, err)
	}
	ok, err = s.SetChannelVerified(ctx, h, ChannelEmail, SourceUser, sent, now)
	if err != nil || !ok {
		t.Fatalf("the sent address's link after a failed newer send: %v %v", ok, err)
	}
}

// TestClaimConfirmSendOncePerAddress covers the confirm throttle: one claim
// per address in the window, from anyone and in any case, freed only by its
// own release.
func TestClaimConfirmSendOncePerAddress(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	addr := "claim-" + strings.ToLower(t.Name()) + "@example.com"
	clean := func() { _, _ = s.db.Exec(`DELETE FROM alert_confirm_sends WHERE address = $1`, addr) }
	clean()
	t.Cleanup(clean)
	now := time.Now().Truncate(time.Microsecond)
	ok, err := s.ClaimConfirmSend(ctx, "uA", addr, now, now.Add(-time.Hour))
	if err != nil || !ok {
		t.Fatalf("first claim: %v %v", ok, err)
	}
	later := now.Add(time.Minute)
	ok, err = s.ClaimConfirmSend(ctx, "uB", strings.ToUpper(addr), later, later.Add(-time.Hour))
	if err != nil || ok {
		t.Fatalf("second claim in the hour: %v %v", ok, err)
	}
	must(t, s.ReleaseConfirmSend(ctx, "uA", addr, now.Add(time.Second)))
	must(t, s.ReleaseConfirmSend(ctx, "uB", addr, now))
	ok, _ = s.ClaimConfirmSend(ctx, "uB", addr, later, later.Add(-time.Hour))
	if ok {
		t.Fatal("another time's or user's release freed the claim")
	}
	must(t, s.ReleaseConfirmSend(ctx, "uA", addr, now))
	ok, err = s.ClaimConfirmSend(ctx, "uB", addr, later, later.Add(-time.Hour))
	if err != nil || !ok {
		t.Fatalf("claim after release: %v %v", ok, err)
	}
	ok, err = s.ClaimConfirmSend(ctx, "uA", addr, now.Add(2*time.Hour), now.Add(time.Hour))
	if err != nil || !ok {
		t.Fatalf("claim after the hour: %v %v", ok, err)
	}
}

// TestDisableAndParkSkipsAMovedRow covers a report about an address the
// row no longer holds: it disables and parks nothing.
func TestDisableAndParkSkipsAMovedRow(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	now := time.Now()
	must(t, s.UpsertChannel(ctx, Channel{UserHash: h, Kind: ChannelEmail, Address: "new@example.com", Source: SourceUser, VerifiedAt: &now}))
	a := sample(h)
	a.Delivery = DeliveryEmail
	created, err := s.Create(ctx, a)
	must(t, err)
	ok, err := s.DisableAndPark(ctx, h, ChannelEmail, SourceUser, "old@example.com", ReasonBounced, ParkBounced, now)
	if err != nil || ok || alertStatus(t, s, h, created.ID) != StatusActive {
		t.Fatalf("old address disabled the new one: %v %v", ok, err)
	}
	ok, err = s.DisableAndPark(ctx, h, ChannelEmail, SourceUser, "NEW@example.com", ReasonBounced, ParkBounced, now)
	if err != nil || !ok || alertStatus(t, s, h, created.ID) != StatusUndeliverable {
		t.Fatalf("own address: %v %v", ok, err)
	}
}

// TestDisableAndParkWaitsForAConfirm covers a bounce on the user's Patreon
// address landing while a confirm verifies their own one: the park waits
// for the confirm and then sees the new address working.
func TestDisableAndParkWaitsForAConfirm(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	now := time.Now()
	must(t, s.UpsertChannel(ctx, Channel{UserHash: h, Kind: ChannelEmail, Address: "pat@example.com", Source: SourcePatreon, VerifiedAt: &now}))
	must(t, s.UpsertChannel(ctx, Channel{UserHash: h, Kind: ChannelEmail, Address: "mine@example.com", Source: SourceUser}))
	a := sample(h)
	a.Delivery = DeliveryEmail
	created, err := s.Create(ctx, a)
	must(t, err)

	// The confirm, mid-way: it holds the user's lock and has verified the row.
	confirm, err := s.db.BeginTx(ctx, nil)
	must(t, err)
	defer func() { _ = confirm.Rollback() }()
	must(t, lockUser(ctx, confirm, h))
	_, err = confirm.ExecContext(ctx, `UPDATE alert_channels SET verified_at = now() WHERE user_hash = $1 AND source = 'user'`, h)
	must(t, err)
	result := make(chan error, 1)
	go func() {
		_, err := s.DisableAndPark(ctx, h, ChannelEmail, SourcePatreon, "pat@example.com", ReasonBounced, ParkBounced, now)
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("park did not wait for the confirm: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	must(t, confirm.Commit())
	must(t, <-result)
	if st := alertStatus(t, s, h, created.ID); st != StatusActive {
		t.Fatalf("alert %s with a working address", st)
	}
}

// TestStageEmailWaitsForAConfirm covers a new address entered while the
// pending one is being confirmed: the write waits for the confirm, then
// keeps the address it verified rather than overwrite it.
func TestStageEmailWaitsForAConfirm(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	clean := func() { _, _ = s.db.Exec(`DELETE FROM alert_confirm_sends WHERE user_hash = $1`, h) }
	clean()
	t.Cleanup(clean)
	must(t, s.UpsertChannel(ctx, Channel{UserHash: h, Kind: ChannelEmail, Address: "a@example.com", Source: SourceUser}))

	// The confirm, mid-way: it holds the user's lock and has verified the row.
	confirm, err := s.db.BeginTx(ctx, nil)
	must(t, err)
	defer func() { _ = confirm.Rollback() }()
	must(t, lockUser(ctx, confirm, h))
	_, err = confirm.ExecContext(ctx, `UPDATE alert_channels SET verified_at = now() WHERE user_hash = $1 AND source = 'user'`, h)
	must(t, err)
	result := make(chan error, 1)
	go func() {
		_, err := s.StageEmail(ctx, h, "b@example.com", time.Now(), time.Now().Add(-time.Hour))
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("stage did not wait for the confirm: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	must(t, confirm.Commit())
	must(t, <-result)
	chans, err := s.Channels(ctx, h)
	if err != nil || len(chans) != 1 || chans[0].Address != "a@example.com" || !chans[0].Active() {
		t.Fatalf("row after the stage: %+v %v", chans, err)
	}
	// With nothing working, the row takes the new address at once.
	must(t, s.DisableChannel(ctx, h, ChannelEmail, SourceUser, ReasonBounced, time.Now()))
	claimed, err := s.StageEmail(ctx, h, "b@example.com", time.Now().Add(2*time.Hour), time.Now().Add(time.Hour))
	if err != nil || !claimed {
		t.Fatalf("stage over a bounced row: %v %v", claimed, err)
	}
	chans, err = s.Channels(ctx, h)
	if err != nil || len(chans) != 1 || chans[0].Address != "b@example.com" || chans[0].VerifiedAt != nil {
		t.Fatalf("row after staging over a bounced one: %+v %v", chans, err)
	}
}

// TestParkForNoAddressWaitsForAConfirm covers the evaluator parking an
// email alert for want of an address while a confirm verifies one: the
// park waits for the confirm and then leaves the alert active.
func TestParkForNoAddressWaitsForAConfirm(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	must(t, s.UpsertChannel(ctx, Channel{UserHash: h, Kind: ChannelEmail, Address: "mine@example.com", Source: SourceUser}))
	a := sample(h)
	a.Delivery = DeliveryEmail
	created, err := s.Create(ctx, a)
	must(t, err)

	confirm, err := s.db.BeginTx(ctx, nil)
	must(t, err)
	defer func() { _ = confirm.Rollback() }()
	must(t, lockUser(ctx, confirm, h))
	_, err = confirm.ExecContext(ctx, `UPDATE alert_channels SET verified_at = now() WHERE user_hash = $1 AND source = 'user'`, h)
	must(t, err)
	result := make(chan error, 1)
	go func() {
		_, err := s.ParkForNoAddress(ctx, h, created.ID, created.UpdatedAt, State{Status: StatusUndeliverable, AboveArmed: true, BelowArmed: true, LastError: ParkNoAddress})
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("park did not wait for the confirm: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	must(t, confirm.Commit())
	must(t, <-result)
	if st := alertStatus(t, s, h, created.ID); st != StatusActive {
		t.Fatalf("alert %s with a working address", st)
	}
	// With no address at all, the alert is parked.
	must(t, s.DeleteChannel(ctx, h, ChannelEmail, SourceUser))
	parked, err := s.ParkForNoAddress(ctx, h, created.ID, created.UpdatedAt, State{Status: StatusUndeliverable, AboveArmed: true, BelowArmed: true, LastError: ParkNoAddress})
	if err != nil || !parked || alertStatus(t, s, h, created.ID) != StatusUndeliverable {
		t.Fatalf("park with no address: %v %v", parked, err)
	}
}

// TestUnsubscribeEmailIsOneStep covers the unsubscribe link: it waits for
// another channel write of the user's, then disables every working email
// row, a complaint kept, and parks the email alerts together.
func TestUnsubscribeEmailIsOneStep(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	now := time.Now()
	must(t, s.UpsertChannel(ctx, Channel{UserHash: h, Kind: ChannelEmail, Address: "pat@example.com", Source: SourcePatreon, VerifiedAt: &now}))
	must(t, s.UpsertChannel(ctx, Channel{UserHash: h, Kind: ChannelEmail, Address: "mine@example.com", Source: SourceUser, VerifiedAt: &now}))
	must(t, s.DisableChannel(ctx, h, ChannelEmail, SourceUser, ReasonComplained, now))
	a := sample(h)
	a.Delivery = DeliveryEmail
	created, err := s.Create(ctx, a)
	must(t, err)

	enable, err := s.db.BeginTx(ctx, nil)
	must(t, err)
	defer func() { _ = enable.Rollback() }()
	must(t, lockUser(ctx, enable, h))
	result := make(chan error, 1)
	go func() { result <- s.UnsubscribeEmail(ctx, h, now) }()
	select {
	case err := <-result:
		t.Fatalf("unsubscribe did not wait: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	must(t, enable.Commit())
	must(t, <-result)
	chans, err := s.Channels(ctx, h)
	must(t, err)
	for _, c := range chans {
		want := ReasonUnsubscribed
		if c.Source == SourceUser {
			want = ReasonComplained
		}
		if c.DisabledAt == nil || c.DisabledReason != want {
			t.Fatalf("row after unsubscribe: %+v", c)
		}
	}
	if st := alertStatus(t, s, h, created.ID); st != StatusUndeliverable {
		t.Fatalf("alert %s after unsubscribe", st)
	}
}

// TestUnsubscribeAfterAStagedAddress covers an unsubscribe landing after a
// new address was claimed and staged: neither that address's link nor a
// replacement's moves or verifies an unsubscribed row.
func TestUnsubscribeAfterAStagedAddress(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	clean := func() { _, _ = s.db.Exec(`DELETE FROM alert_confirm_sends WHERE user_hash = $1`, h) }
	clean()
	t.Cleanup(clean)
	now := time.Now()
	for _, tc := range []struct {
		name    string
		working bool
	}{{"pending row", false}, {"working row", true}} {
		_, err := s.db.ExecContext(ctx, `DELETE FROM alert_channels WHERE user_hash = $1`, h)
		must(t, err)
		clean()
		if tc.working {
			verified := now.Add(-time.Hour)
			must(t, s.UpsertChannel(ctx, Channel{UserHash: h, Kind: ChannelEmail, Address: "old@example.com", Source: SourceUser, VerifiedAt: &verified}))
		}
		claimed, err := s.StageEmail(ctx, h, "new@example.com", now, now.Add(-time.Hour))
		if err != nil || !claimed {
			t.Fatalf("%s: stage: %v %v", tc.name, claimed, err)
		}
		must(t, s.UnsubscribeEmail(ctx, h, now))
		ok, err := s.SetChannelVerified(ctx, h, ChannelEmail, SourceUser, "new@example.com", now.Add(time.Minute))
		if err != nil || ok {
			t.Fatalf("%s: link undid the unsubscribe: %v %v", tc.name, ok, err)
		}
	}
}

// TestStageEmailClaimsAndStagesTogether covers the claim moving with the
// row: while another write holds the user's lock, neither happens.
func TestStageEmailClaimsAndStagesTogether(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	addr := "together-" + strings.ToLower(t.Name()) + "@example.com"
	clean := func() { _, _ = s.db.Exec(`DELETE FROM alert_confirm_sends WHERE address = $1`, addr) }
	clean()
	t.Cleanup(clean)
	other, err := s.db.BeginTx(ctx, nil)
	must(t, err)
	defer func() { _ = other.Rollback() }()
	must(t, lockUser(ctx, other, h))
	result := make(chan error, 1)
	go func() {
		_, err := s.StageEmail(ctx, h, addr, time.Now(), time.Now().Add(-time.Hour))
		result <- err
	}()
	time.Sleep(200 * time.Millisecond)
	var claims int
	must(t, s.db.QueryRowContext(ctx, `SELECT count(*) FROM alert_confirm_sends WHERE address = $1`, addr).Scan(&claims))
	if claims != 0 {
		t.Fatal("claimed while another write held the user's lock")
	}
	must(t, other.Commit())
	must(t, <-result)
	must(t, s.db.QueryRowContext(ctx, `SELECT count(*) FROM alert_confirm_sends WHERE address = $1`, addr).Scan(&claims))
	chans, err := s.Channels(ctx, h)
	if err != nil || claims != 1 || len(chans) != 1 || chans[0].Address != addr {
		t.Fatalf("after the stage: %d claims, rows %+v %v", claims, chans, err)
	}
}

// TestUpsertChannelCaseInsensitiveAddressKeepsVerified covers that
// resubmitting the same address in a different case is not treated as a
// changed address, so it does not clear verified_at.
func TestUpsertChannelCaseInsensitiveAddressKeepsVerified(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()
	now := time.Now()
	must(t, s.UpsertChannel(ctx, Channel{UserHash: h, Kind: ChannelEmail, Address: "Bob@Example.com", Source: SourceUser, VerifiedAt: &now}))
	must(t, s.UpsertChannel(ctx, Channel{UserHash: h, Kind: ChannelEmail, Address: "bob@example.com", Source: SourceUser}))
	chans, err := s.Channels(ctx, h)
	if err != nil || len(chans) != 1 || chans[0].VerifiedAt == nil {
		t.Fatalf("case-insensitive re-upsert cleared verified_at: %+v err=%v", chans, err)
	}
}

// TestMarkChannelDisallowedParksAndRestores covers a user with a discord
// alert and an email alert: dropping email from the tier's allowed
// channels parks only that alert, and restoring the channel restores it.
func TestMarkChannelDisallowedParksAndRestores(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()

	discordAlert := sample(h)
	created1, err := s.Create(ctx, discordAlert)
	must(t, err)
	emailAlert := sample(h)
	emailAlert.Delivery = DeliveryEmail
	created2, err := s.Create(ctx, emailAlert)
	must(t, err)

	moved, err := s.MarkChannelDisallowed(ctx, h, "magic", []ChannelKind{ChannelDiscord})
	must(t, err)
	if len(moved) != 1 || moved[0].ID != created2.ID || moved[0].Status != StatusOverAllowance {
		t.Fatalf("park: moved=%+v", moved)
	}
	got, _, _ := s.Get(ctx, created2.ID, h)
	if got.Status != StatusOverAllowance || got.LastError != "channel not in your tier" {
		t.Fatalf("email alert not parked: %+v", got)
	}
	gotDiscord, _, _ := s.Get(ctx, created1.ID, h)
	if gotDiscord.Status != StatusActive {
		t.Fatalf("discord alert touched: %+v", gotDiscord)
	}

	moved, err = s.MarkChannelDisallowed(ctx, h, "magic", []ChannelKind{ChannelDiscord, ChannelEmail})
	must(t, err)
	if len(moved) != 1 || moved[0].ID != created2.ID || moved[0].Status != StatusActive {
		t.Fatalf("restore: moved=%+v", moved)
	}
	got, _, _ = s.Get(ctx, created2.ID, h)
	if got.Status != StatusActive || got.LastError != "" {
		t.Fatalf("email alert not restored: %+v", got)
	}
}

// TestChannelParkSitsOutOfTheAllowance covers the two park steps together:
// a channel-parked alert is neither ranked nor restored by the allowance,
// and an allowance-parked one whose channel drops stays parked silently.
func TestChannelParkSitsOutOfTheAllowance(t *testing.T) {
	s := testStore(t)
	h := freshUser(t, s)
	seedContact(t, s, h)
	ctx := context.Background()

	// The email alert is the older, so an allowance of one parks it.
	emailAlert := sample(h)
	emailAlert.Delivery = DeliveryEmail
	email, err := s.Create(ctx, emailAlert)
	must(t, err)
	time.Sleep(5 * time.Millisecond)
	discord, err := s.Create(ctx, sample(h))
	must(t, err)

	moved, err := s.MarkChannelDisallowed(ctx, h, "magic", []ChannelKind{ChannelDiscord})
	must(t, err)
	if len(moved) != 1 || moved[0].ID != email.ID || moved[0].Status != StatusOverAllowance {
		t.Fatalf("channel park: moved=%+v", moved)
	}
	moved, err = s.MarkOverAllowance(ctx, h, "magic", 10)
	must(t, err)
	if len(moved) != 0 {
		t.Fatalf("allowance moved a channel-parked alert: %+v", moved)
	}
	got, _, _ := s.Get(ctx, email.ID, h)
	if got.Status != StatusOverAllowance || got.LastError != channelParkReason {
		t.Fatalf("email alert after the allowance: %+v", got)
	}

	moved, err = s.MarkChannelDisallowed(ctx, h, "magic", []ChannelKind{ChannelDiscord, ChannelEmail})
	must(t, err)
	if len(moved) != 1 || moved[0].ID != email.ID || moved[0].Status != StatusActive {
		t.Fatalf("channel restore: moved=%+v", moved)
	}
	moved, err = s.MarkOverAllowance(ctx, h, "magic", 1)
	must(t, err)
	if len(moved) != 1 || moved[0].ID != email.ID || moved[0].Status != StatusOverAllowance {
		t.Fatalf("allowance park: moved=%+v", moved)
	}
	got, _, _ = s.Get(ctx, email.ID, h)
	if got.Status != StatusOverAllowance || got.LastError == channelParkReason {
		t.Fatalf("allowance-parked email alert: %+v", got)
	}
	kept, _, _ := s.Get(ctx, discord.ID, h)
	if kept.Status != StatusActive {
		t.Fatalf("newer discord alert: %+v", kept)
	}

	// Its channel dropped while parked for the allowance: re-marked for the
	// channel without a report, and room returning does not restore it.
	moved, err = s.MarkChannelDisallowed(ctx, h, "magic", []ChannelKind{ChannelDiscord})
	must(t, err)
	if len(moved) != 0 {
		t.Fatalf("re-mark reported a move: %+v", moved)
	}
	moved, err = s.MarkOverAllowance(ctx, h, "magic", 10)
	must(t, err)
	if len(moved) != 0 {
		t.Fatalf("allowance restored a disallowed channel: %+v", moved)
	}
	got, _, _ = s.Get(ctx, email.ID, h)
	if got.Status != StatusOverAllowance || got.LastError != channelParkReason {
		t.Fatalf("email alert after the re-mark: %+v", got)
	}
}
