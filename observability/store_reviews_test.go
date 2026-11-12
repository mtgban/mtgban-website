package observability

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestReviewSchemaIsTheSpecs(t *testing.T) {
	joined := strings.Join(featureStatements, "\n")
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS feature_reviews",
		"PRIMARY KEY (instance, name, value, scope)",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("feature schema lacks %q", want)
		}
	}
	if strings.Contains(joined, "author") || strings.Contains(joined, "email") {
		t.Error("a review stores no author")
	}
}

func TestSetReviewRefusesBadInput(t *testing.T) {
	c := &Client{}
	ctx := context.Background()
	ok := Review{Instance: "magic", Name: "search.sort", Value: "alpha", Verdict: "keep"}
	for name, r := range map[string]Review{
		"no instance":  {Name: ok.Name, Verdict: "keep"},
		"no name":      {Instance: "magic", Verdict: "keep"},
		"bad verdict":  {Instance: "magic", Name: ok.Name, Verdict: "maybe"},
		"long note":    {Instance: "magic", Name: ok.Name, Verdict: "keep", Note: strings.Repeat("é", 201)},
		"invalid utf8": {Instance: "magic", Name: ok.Name, Verdict: "keep", Note: "a\xffb"},
	} {
		if err := c.SetReview(ctx, r); err == nil {
			t.Errorf("%s: saved", name)
		}
	}
}

func TestValidVerdict(t *testing.T) {
	for _, v := range []string{"keep", "remove", "watch"} {
		if !ValidVerdict(v) {
			t.Errorf("%q is refused", v)
		}
	}
	for _, v := range []string{"", "Keep", "maybe"} {
		if ValidVerdict(v) {
			t.Errorf("%q is accepted", v)
		}
	}
}

func TestCleanReviewNote(t *testing.T) {
	long := strings.Repeat("é", ReviewNoteMax+5)
	if got := CleanReviewNote(long); got != strings.Repeat("é", ReviewNoteMax) {
		t.Errorf("a long note is cut to %d runes, want %d", utf8.RuneCountInString(got), ReviewNoteMax)
	}
	got := CleanReviewNote("a\xffb")
	if !utf8.ValidString(got) || got != "a�b" {
		t.Errorf("invalid UTF-8 cleans to %q", got)
	}
	// Cleaning comes before the cut, so the result is never over the cap.
	if n := utf8.RuneCountInString(CleanReviewNote(strings.Repeat("\xffa", ReviewNoteMax))); n != ReviewNoteMax {
		t.Errorf("cleaned and cut note has %d runes", n)
	}
	if err := checkReview(Review{Instance: "i", Name: "n", Verdict: "keep", Note: CleanReviewNote(long + "\xff")}); err != nil {
		t.Errorf("a cleaned note is refused: %v", err)
	}
}

// reviewClient is a testClient whose review rows for the given instances are deleted on cleanup.
func reviewClient(t *testing.T, instances ...string) *Client {
	t.Helper()
	c := testClient(t)
	t.Cleanup(func() {
		for _, inst := range instances {
			_, _ = c.db.Exec("DELETE FROM feature_reviews WHERE instance = $1", inst)
		}
	})
	return c
}

func setReview(t *testing.T, c *Client, r Review) {
	t.Helper()
	if err := c.SetReview(context.Background(), r); err != nil {
		t.Fatal(err)
	}
}

func reviews(t *testing.T, c *Client, instance string) []Review {
	t.Helper()
	got, err := c.Reviews(context.Background(), instance)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestReviewRoundTrip(t *testing.T) {
	inst := "test-" + t.Name()
	c := reviewClient(t, inst)
	note := strings.Repeat("é", ReviewNoteMax)
	setReview(t, c, Review{Instance: inst, Name: "search.sort", Scope: "page", Value: "alpha", Verdict: "keep", Note: note})
	got := reviews(t, c, inst)
	if len(got) != 1 {
		t.Fatalf("%d reviews, want 1", len(got))
	}
	r := got[0]
	if r.Instance != inst || r.Name != "search.sort" || r.Scope != "page" || r.Value != "alpha" {
		t.Errorf("key %+v", r)
	}
	if r.Verdict != "keep" || r.Note != note || r.UpdatedAt.IsZero() {
		t.Errorf("verdict %q, note of %d runes, updated %v", r.Verdict, utf8.RuneCountInString(r.Note), r.UpdatedAt)
	}
}

func TestSetReviewReplaces(t *testing.T) {
	inst := "test-" + t.Name()
	c := reviewClient(t, inst)
	setReview(t, c, Review{Instance: inst, Name: "search.sort", Value: "alpha", Verdict: "keep", Note: "first"})
	setReview(t, c, Review{Instance: inst, Name: "search.sort", Value: "alpha", Verdict: "watch", Note: "second"})
	got := reviews(t, c, inst)
	if len(got) != 1 || got[0].Verdict != "watch" || got[0].Note != "second" {
		t.Fatalf("got %+v, want one watch row noted second", got)
	}
}

func TestReviewsAreKeptApartByInstanceAndKey(t *testing.T) {
	a, b := "test-"+t.Name()+"-a", "test-"+t.Name()+"-b"
	c := reviewClient(t, a, b)
	setReview(t, c, Review{Instance: a, Name: "search.sort", Value: "alpha", Verdict: "keep"})
	setReview(t, c, Review{Instance: a, Name: "search.sort", Value: "price", Verdict: "remove"})
	setReview(t, c, Review{Instance: b, Name: "search.sort", Value: "alpha", Verdict: "watch"})
	got := reviews(t, c, a)
	if len(got) != 2 {
		t.Fatalf("%d reviews under a, want 2", len(got))
	}
	// Ordered by name, scope, value.
	if got[0].Value != "alpha" || got[0].Verdict != "keep" || got[1].Value != "price" || got[1].Verdict != "remove" {
		t.Errorf("a's reviews %+v", got)
	}
	for _, r := range got {
		if r.Instance != a {
			t.Errorf("Reviews(a) returned %+v", r)
		}
	}
	if got := reviews(t, c, b); len(got) != 1 || got[0].Verdict != "watch" {
		t.Errorf("b's reviews %+v", got)
	}
}

func TestDeleteReview(t *testing.T) {
	inst := "test-" + t.Name()
	c := reviewClient(t, inst)
	ctx := context.Background()
	// Scope and value differ, so swapping them in the delete misses the row.
	setReview(t, c, Review{Instance: inst, Name: "search.sort", Scope: "sc", Value: "va", Verdict: "keep"})
	setReview(t, c, Review{Instance: inst, Name: "search.sort", Scope: "va", Value: "sc", Verdict: "remove"})
	if err := c.DeleteReview(ctx, inst, "search.sort", "sc", "va"); err != nil {
		t.Fatal(err)
	}
	got := reviews(t, c, inst)
	if len(got) != 1 || got[0].Scope != "va" || got[0].Value != "sc" {
		t.Fatalf("after the delete %+v, want only scope va value sc", got)
	}
	if err := c.DeleteReview(ctx, inst, "search.sort", "sc", "va"); err != nil {
		t.Errorf("deleting a missing key: %v", err)
	}
}

// Reviews reads at most ReviewsMax marks of its instance.
func TestReviewsAreBounded(t *testing.T) {
	inst := "test-" + t.Name()
	c := reviewClient(t, inst)
	if _, err := c.db.Exec(`INSERT INTO feature_reviews (instance, name, value, scope, verdict, note)
SELECT $1, 'n.' || lpad(g::text, 5, '0'), '', '', 'keep', '' FROM generate_series(1, $2) g`, inst, ReviewsMax+1); err != nil {
		t.Fatal(err)
	}
	got := reviews(t, c, inst)
	if len(got) != ReviewsMax || got[0].Name != "n.00001" {
		t.Errorf("%d reviews, first %+v; want %d from n.00001", len(got), got[0], ReviewsMax)
	}
}
