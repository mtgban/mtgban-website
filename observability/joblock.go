package observability

import (
	"context"
	"errors"
	"fmt"
)

// jobLockClass namespaces job locks; internal/alerts takes 7264617 to 7264619.
const jobLockClass = 7264620

// WithJobLock runs fn while holding key's transaction-level lock, or returns false if another holder has it.
// PgBouncer's idle_transaction_timeout must stay 0, its default, for the lock to hold.
// The pool needs at least 2 connections: one holds the lock while fn works on another.
func (c *Client) WithJobLock(ctx context.Context, key string, fn func(context.Context) error) (ran bool, err error) {
	// 0 is no limit; a limit of 1 would leave fn waiting for the connection the lock holds.
	if limit := c.db.Stats().MaxOpenConnections; limit > 0 && limit < 2 {
		return false, fmt.Errorf("observability: job lock %s needs a pool of 2 connections, this one allows %d", key, limit)
	}
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	// Rolling back releases the lock.
	defer func() { _ = tx.Rollback() }()
	var held bool
	if err := tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock($1, hashtext($2::text))`, jobLockClass, key).Scan(&held); err != nil {
		return false, err
	}
	if !held {
		return false, nil
	}
	// The lock transaction sits idle while fn works on the pool.
	if _, err := tx.ExecContext(ctx, `SELECT set_config('idle_in_transaction_session_timeout', '0', true)`); err != nil {
		return false, err
	}
	err = fn(ctx)
	// An ended context rolls the lock transaction back too; that is the deadline, not a lost lock.
	if ctxErr := ctx.Err(); ctxErr != nil {
		if errors.Is(err, ctxErr) {
			return true, err
		}
		return true, errors.Join(err, ctxErr)
	}
	// A lock whose connection died during fn was released while fn still ran.
	if _, lost := tx.ExecContext(ctx, `SELECT 1`); lost != nil {
		return true, errors.Join(err, fmt.Errorf("job lock lost during the run: %w", lost))
	}
	return true, err
}
