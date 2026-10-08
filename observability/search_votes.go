package observability

import (
	"context"
	"time"
)

// SearchRank is one ranked search key: distinct users in the window, in the
// recent window, and its most common spelling.
type SearchRank struct {
	Key         string
	Query       string
	Users       int
	RecentUsers int
}

// RecordSearchVote stores one user's vote for key on day. A repeat is a
// no-op, and a user already at budget distinct keys that day adds nothing.
// A lock per instance, user and day makes the budget hold under concurrency.
func (c *Client) RecordSearchVote(ctx context.Context, instance, key, userHash string, day time.Time, query string, budget int) error {
	const lock = `SELECT pg_advisory_xact_lock(hashtext($1::text || '|' || $2::text || '|' || $3::text))`
	const q = `INSERT INTO search_votes (instance, key, user_hash, day, query)
SELECT $1, $2, $3, $4::date, $5
WHERE (SELECT count(*) FROM search_votes WHERE instance = $1 AND user_hash = $3 AND day = $4::date) < $6
ON CONFLICT DO NOTHING`
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() // no-op after Commit
	if _, err := tx.ExecContext(ctx, lock, instance, userHash, sqlDate(day)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, q, instance, key, userHash, sqlDate(day), query, budget); err != nil {
		return err
	}
	return tx.Commit()
}

// sqlDate is t's UTC calendar date, as a date parameter takes it.
func sqlDate(t time.Time) string {
	return t.UTC().Format("2006-01-02")
}

// TopSearches ranks one instance's keys by distinct users since the window
// start, recent users breaking ties, keeping those with at least minUsers.
func (c *Client) TopSearches(ctx context.Context, instance string, since, recentSince time.Time, minUsers, limit int) ([]SearchRank, error) {
	const q = `SELECT key,
       count(DISTINCT user_hash)                                AS users,
       count(DISTINCT user_hash) FILTER (WHERE day >= $3::date) AS recent_users,
       mode() WITHIN GROUP (ORDER BY query)                     AS query
FROM search_votes
WHERE instance = $1 AND day >= $2::date
GROUP BY key
HAVING count(DISTINCT user_hash) >= $4
ORDER BY users DESC, recent_users DESC, key
LIMIT $5`
	rows, err := c.db.QueryContext(ctx, q, instance, sqlDate(since), sqlDate(recentSince), minUsers, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SearchRank
	for rows.Next() {
		var r SearchRank
		if err := rows.Scan(&r.Key, &r.Users, &r.RecentUsers, &r.Query); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// PruneSearchVotes deletes one instance's votes from days before the cutoff.
func (c *Client) PruneSearchVotes(ctx context.Context, instance string, before time.Time) (int64, error) {
	res, err := c.db.ExecContext(ctx, `DELETE FROM search_votes WHERE instance = $1 AND day < $2::date`, instance, sqlDate(before))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
