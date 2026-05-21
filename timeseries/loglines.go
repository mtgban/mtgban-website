package timeseries

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// LogLine is one captured line of stdout/stderr (or a synthetic source).
type LogLine struct {
	Timestamp time.Time
	Host      string
	Source    string // "stdout" | "stderr" | other
	Message   string
}

const logLinesSchema = `
CREATE TABLE IF NOT EXISTS log_lines (
    id      BIGSERIAL PRIMARY KEY,
    ts      TIMESTAMPTZ NOT NULL DEFAULT now(),
    host    TEXT NOT NULL,
    source  TEXT NOT NULL,
    message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_log_lines_ts ON log_lines (ts DESC);
CREATE INDEX IF NOT EXISTS idx_log_lines_host_ts ON log_lines (host, ts DESC);
`

// EnsureLogLinesSchema creates the log_lines table if missing. No-op on
// read-only clients.
func (c *Client) EnsureLogLinesSchema(ctx context.Context) error {
	if c.readOnly {
		return nil
	}
	_, err := c.db.ExecContext(ctx, logLinesSchema)
	return err
}

// InsertLogLines writes a batch of log lines in a single multi-value INSERT.
// Empty batches are a no-op. No-op on read-only clients.
func (c *Client) InsertLogLines(ctx context.Context, lines []LogLine) error {
	if c.readOnly || len(lines) == 0 {
		return nil
	}

	const colsPerLine = 4
	maxBatch := 65535 / colsPerLine
	if len(lines) > maxBatch {
		// Recurse to keep parameter count under Postgres's 65535 cap.
		mid := len(lines) / 2
		if err := c.InsertLogLines(ctx, lines[:mid]); err != nil {
			return err
		}
		return c.InsertLogLines(ctx, lines[mid:])
	}

	var sb strings.Builder
	sb.WriteString(`INSERT INTO log_lines (ts, host, source, message) VALUES `)
	args := make([]any, 0, len(lines)*colsPerLine)
	for i, l := range lines {
		if i > 0 {
			sb.WriteByte(',')
		}
		offset := i * colsPerLine
		fmt.Fprintf(&sb, "($%d,$%d,$%d,$%d)", offset+1, offset+2, offset+3, offset+4)
		args = append(args, l.Timestamp, l.Host, l.Source, l.Message)
	}

	_, err := c.db.ExecContext(ctx, sb.String(), args...)
	return err
}

// PruneLogLines deletes log_lines older than the given cutoff. Returns rows
// deleted. No-op on read-only clients.
func (c *Client) PruneLogLines(ctx context.Context, olderThan time.Time) (int64, error) {
	if c.readOnly {
		return 0, nil
	}
	res, err := c.db.ExecContext(ctx, `DELETE FROM log_lines WHERE ts < $1`, olderThan)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}
