package observability

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	featureColumns = 10    // parameters per row
	maxParams      = 65535 // Postgres bind parameter limit
)

var _ CounterStore = (*Client)(nil)

// UpsertMinutes adds rows to the minute's counts. Keys must be unique and sorted.
func (c *Client) UpsertMinutes(ctx context.Context, minute time.Time, rows []Row) error {
	if len(rows) == 0 {
		return nil
	}
	if len(rows)*featureColumns > maxParams {
		return fmt.Errorf("observability: %d rows exceed the parameter limit", len(rows))
	}
	var sb strings.Builder
	sb.WriteString("INSERT INTO feature_events (ts, instance, tier, device, signed, is_bot, scope, name, value, n) VALUES ")
	args := make([]any, 0, len(rows)*featureColumns)
	ts := minute.UTC()
	for i, r := range rows {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteByte('(')
		for j := 0; j < featureColumns; j++ {
			if j > 0 {
				sb.WriteByte(',')
			}
			sb.WriteByte('$')
			sb.WriteString(strconv.Itoa(i*featureColumns + j + 1))
		}
		sb.WriteByte(')')
		args = append(args, ts, r.Instance, r.Tier, r.Device, r.Signed, r.Bot, r.Scope, r.Name, r.Value, r.N)
	}
	sb.WriteString(" ON CONFLICT (ts, instance, tier, device, signed, is_bot, scope, name, value) DO UPDATE SET n = feature_events.n + EXCLUDED.n")
	if _, err := c.db.ExecContext(ctx, sb.String(), args...); err != nil {
		return fmt.Errorf("observability: upsert minutes: %w", err)
	}
	return nil
}
