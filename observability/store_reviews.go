package observability

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Review is an admin's mark on one metric key of one instance.
type Review struct {
	Instance, Name, Value, Scope string
	Verdict, Note                string // Verdict is keep, remove or watch
	UpdatedAt                    time.Time
}

// ReviewNoteMax is the most characters (runes) a review note holds.
const ReviewNoteMax = 200

// ValidVerdict reports whether v is a verdict a review may carry: keep, remove or watch.
func ValidVerdict(v string) bool {
	switch v {
	case "keep", "remove", "watch":
		return true
	}
	return false
}

// CleanReviewNote replaces invalid UTF-8 and cuts the note to ReviewNoteMax runes, never mid-rune.
func CleanReviewNote(note string) string {
	note = strings.ToValidUTF8(note, "�")
	if utf8.RuneCountInString(note) <= ReviewNoteMax {
		return note
	}
	return string([]rune(note)[:ReviewNoteMax])
}

// checkReview refuses a review the table must not hold; a note must already be clean.
func checkReview(r Review) error {
	switch {
	case r.Instance == "":
		return errors.New("observability: review has no instance")
	case r.Name == "":
		return errors.New("observability: review has no name")
	case !ValidVerdict(r.Verdict):
		return errors.New("observability: review verdict is not keep, remove or watch")
	case !utf8.ValidString(r.Note):
		return errors.New("observability: review note is not valid UTF-8")
	case utf8.RuneCountInString(r.Note) > ReviewNoteMax:
		return fmt.Errorf("observability: review note is over %d characters", ReviewNoteMax)
	}
	return nil
}

// ReviewsMax is the most review marks Reviews returns, well above any real count.
const ReviewsMax = 5000

// Reviews lists the instance's review marks ordered by name, scope and value, at most ReviewsMax.
func (c *Client) Reviews(ctx context.Context, instance string) ([]Review, error) {
	rows, err := c.db.QueryContext(ctx, `SELECT instance, name, value, scope, verdict, note, updated_at
FROM feature_reviews WHERE instance = $1 ORDER BY name, scope, value LIMIT $2`, instance, ReviewsMax)
	if err != nil {
		return nil, fmt.Errorf("observability: reviews: %w", err)
	}
	defer rows.Close()
	var out []Review
	for rows.Next() {
		var r Review
		if err := rows.Scan(&r.Instance, &r.Name, &r.Value, &r.Scope, &r.Verdict, &r.Note, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("observability: reviews: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: reviews: %w", err)
	}
	return out, nil
}

// SetReview saves the review, replacing the verdict and note of the same key; a bad review is refused unsent.
func (c *Client) SetReview(ctx context.Context, r Review) error {
	if err := checkReview(r); err != nil {
		return err
	}
	const q = `INSERT INTO feature_reviews (instance, name, value, scope, verdict, note)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (instance, name, value, scope) DO UPDATE SET verdict = EXCLUDED.verdict, note = EXCLUDED.note, updated_at = now()`
	if _, err := c.db.ExecContext(ctx, q, r.Instance, r.Name, r.Value, r.Scope, r.Verdict, r.Note); err != nil {
		return fmt.Errorf("observability: set review: %w", err)
	}
	return nil
}

// DeleteReview removes one key's review; a key with none is not an error.
func (c *Client) DeleteReview(ctx context.Context, instance, name, scope, value string) error {
	// Parameters follow the primary key's order: instance, name, value, scope.
	const q = `DELETE FROM feature_reviews WHERE instance = $1 AND name = $2 AND value = $3 AND scope = $4`
	if _, err := c.db.ExecContext(ctx, q, instance, name, value, scope); err != nil {
		return fmt.Errorf("observability: delete review: %w", err)
	}
	return nil
}
