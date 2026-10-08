package observability

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// testInstance keeps these rows apart from real ones; testClient's cleanup
// deletes them.
const testInstance = "__test__popular"

func voteClient(t *testing.T) *Client {
	t.Helper()
	c := testClient(t)
	t.Cleanup(func() {
		_, _ = c.db.Exec("DELETE FROM search_votes WHERE instance = $1", testInstance)
	})
	return c
}

func countVotes(t *testing.T, c *Client, userHash string) int {
	t.Helper()
	var n int
	err := c.db.QueryRow("SELECT count(*) FROM search_votes WHERE instance = $1 AND user_hash = $2", testInstance, userHash).Scan(&n)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func TestIntegrationSearchVoteOncePerUserKeyDay(t *testing.T) {
	c := voteClient(t)
	ctx := context.Background()
	day := time.Now().UTC()
	u := HashVisitor("a@b.com")
	for i := 0; i < 3; i++ {
		if err := c.RecordSearchVote(ctx, testInstance, "card:Black Lotus", u, day, "black lotus", 30); err != nil {
			t.Fatalf("RecordSearchVote: %v", err)
		}
	}
	if n := countVotes(t, c, u); n != 1 {
		t.Fatalf("rows = %d, want 1", n)
	}
}

func TestIntegrationSearchVoteDailyBudget(t *testing.T) {
	c := voteClient(t)
	ctx := context.Background()
	day := time.Now().UTC()
	u := HashVisitor("busy@b.com")
	for i := 0; i < 31; i++ {
		key := "card:" + string(rune('A'+i%26)) + string(rune('a'+i/26))
		if err := c.RecordSearchVote(ctx, testInstance, key, u, day, key, 30); err != nil {
			t.Fatalf("RecordSearchVote %d: %v", i, err)
		}
	}
	if n := countVotes(t, c, u); n != 30 {
		t.Fatalf("rows = %d, want 30", n)
	}
}

// TestIntegrationSearchVoteBudgetUnderConcurrency fires the votes at once:
// the budget must hold when no vote sees the others' rows.
func TestIntegrationSearchVoteBudgetUnderConcurrency(t *testing.T) {
	c := voteClient(t)
	ctx := context.Background()
	day := time.Now().UTC()
	u := HashVisitor("racer@b.com")
	var wg sync.WaitGroup
	errs := make(chan error, 60)
	for i := range 60 {
		wg.Go(func() {
			key := fmt.Sprintf("card:race%02d", i)
			errs <- c.RecordSearchVote(ctx, testInstance, key, u, day, key, 30)
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("RecordSearchVote: %v", err)
		}
	}
	if n := countVotes(t, c, u); n != 30 {
		t.Fatalf("rows = %d, want 30", n)
	}
}

func TestIntegrationTopSearchesRanksDistinctUsers(t *testing.T) {
	c := voteClient(t)
	ctx := context.Background()
	now := time.Now().UTC()
	old := now.AddDate(0, 0, -20)
	users := []string{HashVisitor("1@t"), HashVisitor("2@t"), HashVisitor("3@t"), HashVisitor("4@t")}
	vote := func(key, query, user string, day time.Time) {
		t.Helper()
		if err := c.RecordSearchVote(ctx, testInstance, key, user, day, query, 30); err != nil {
			t.Fatalf("RecordSearchVote: %v", err)
		}
	}
	// Z: 4 users, none recent. X: 3 users, all recent, mixed spelling.
	// W: 3 users, one recent. Y: 2 users, below the minimum.
	for _, u := range users {
		vote("card:Z", "z", u, old)
	}
	vote("card:X", "Black Lotus", users[0], now)
	vote("card:X", "Black Lotus", users[1], now)
	vote("card:X", "black lotus", users[2], now)
	vote("card:W", "w", users[0], now)
	vote("card:W", "w", users[1], old)
	vote("card:W", "w", users[2], old)
	vote("card:Y", "y", users[0], now)
	vote("card:Y", "y", users[1], now)

	ranks, err := c.TopSearches(ctx, testInstance, now.AddDate(0, 0, -30), now.AddDate(0, 0, -7), 3, 24)
	if err != nil {
		t.Fatalf("TopSearches: %v", err)
	}
	var keys []string
	for _, r := range ranks {
		keys = append(keys, r.Key)
	}
	want := []string{"card:Z", "card:X", "card:W"}
	if len(keys) != len(want) {
		t.Fatalf("keys = %v, want %v", keys, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("keys = %v, want %v", keys, want)
		}
	}
	if ranks[0].Users != 4 || ranks[0].RecentUsers != 0 {
		t.Fatalf("Z = %+v, want 4 users, 0 recent", ranks[0])
	}
	if ranks[1].Query != "Black Lotus" || ranks[1].RecentUsers != 3 {
		t.Fatalf("X = %+v, want modal spelling Black Lotus and 3 recent", ranks[1])
	}
}

func TestIntegrationPruneSearchVotes(t *testing.T) {
	c := voteClient(t)
	ctx := context.Background()
	now := time.Now().UTC()
	u := HashVisitor("old@b.com")
	if err := c.RecordSearchVote(ctx, testInstance, "card:Old", u, now.AddDate(0, 0, -100), "old", 30); err != nil {
		t.Fatalf("RecordSearchVote: %v", err)
	}
	if err := c.RecordSearchVote(ctx, testInstance, "card:New", u, now, "new", 30); err != nil {
		t.Fatalf("RecordSearchVote: %v", err)
	}
	// Another instance's old vote is that deployment's to prune.
	const otherInstance = testInstance + "_other"
	t.Cleanup(func() {
		_, _ = c.db.Exec("DELETE FROM search_votes WHERE instance = $1", otherInstance)
	})
	if err := c.RecordSearchVote(ctx, otherInstance, "card:Old", u, now.AddDate(0, 0, -100), "old", 30); err != nil {
		t.Fatalf("RecordSearchVote: %v", err)
	}
	if _, err := c.PruneSearchVotes(ctx, testInstance, now.AddDate(0, 0, -90)); err != nil {
		t.Fatalf("PruneSearchVotes: %v", err)
	}
	if n := countVotes(t, c, u); n != 1 {
		t.Fatalf("rows after prune = %d, want 1", n)
	}
	var other int
	if err := c.db.QueryRow("SELECT count(*) FROM search_votes WHERE instance = $1", otherInstance).Scan(&other); err != nil {
		t.Fatalf("count: %v", err)
	}
	if other != 1 {
		t.Fatalf("other instance's rows after prune = %d, want 1", other)
	}
}

// The window's totals count what the ranking saw: every vote, each user
// and each key once, from the window start on.
func TestIntegrationSearchVoteTotalsCountTheWindow(t *testing.T) {
	c := voteClient(t)
	ctx := context.Background()
	today := time.Now().UTC()
	old := today.AddDate(0, 0, -10)
	a, b := HashVisitor("a@b.com"), HashVisitor("c@d.com")
	for _, v := range []struct {
		key, user string
		day       time.Time
	}{
		{"card:Black Lotus", a, today},
		{"card:Black Lotus", b, today},
		{"set:LEA", a, today},
		{"card:Mox Pearl", a, old},
	} {
		if err := c.RecordSearchVote(ctx, testInstance, v.key, v.user, v.day, v.key, 30); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	got, err := c.SearchVoteTotals(ctx, testInstance, today.AddDate(0, 0, -6))
	if err != nil {
		t.Fatal(err)
	}
	if want := (SearchVoteTotals{Votes: 3, Users: 2, Keys: 2}); got != want {
		t.Errorf("last 7 days: %+v, want %+v", got, want)
	}
	got, err = c.SearchVoteTotals(ctx, testInstance, old)
	if err != nil {
		t.Fatal(err)
	}
	if want := (SearchVoteTotals{Votes: 4, Users: 2, Keys: 3}); got != want {
		t.Errorf("since the old vote: %+v, want %+v", got, want)
	}
}
