package alerts

import (
	"context"
	"database/sql"
	"os"
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
		_, _ = s.db.Exec(`DELETE FROM alert_contacts WHERE user_hash = $1`, h)
	}
	clean()
	t.Cleanup(clean)
	return h
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
