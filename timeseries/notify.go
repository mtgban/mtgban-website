package timeseries

import "context"

// Notify sends a Postgres NOTIFY on the channel with the payload attached,
// waking every session currently listening on it (LISTEN, or lib/pq's
// Listener). NOTIFY carries no queue: a session that is not connected when
// the notify commits never sees it, so listeners must treat a reconnect as
// "reload everything" rather than wait for missed messages.
//
// It runs on a read-only client too: unlike the upsert methods, it stores
// nothing — it is how a deployment that only reads prices still signals its
// peers over the shared database.
func (c *Client) Notify(ctx context.Context, channel, payload string) error {
	_, err := c.db.ExecContext(ctx, "SELECT pg_notify($1, $2)", channel, payload)
	return err
}
