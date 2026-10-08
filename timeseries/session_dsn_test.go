package timeseries

import (
	"context"
	"strings"
	"testing"
)

// SessionDSN reaches Postgres on DirectPort when a pooler sits on Port, and
// is DSN itself when nothing says otherwise.
func TestSessionDSN(t *testing.T) {
	cfg := SQLConfig{Host: "db", Port: 6432, User: "u", DBName: "prices"}
	if got, want := cfg.SessionDSN(), cfg.DSN(); got != want {
		t.Errorf("no direct_port: SessionDSN %q, want DSN %q", got, want)
	}
	cfg.DirectPort = 5432
	if got := cfg.SessionDSN(); !strings.Contains(got, "port=5432") || cfg.DSN() == got {
		t.Errorf("direct_port 5432: SessionDSN %q, DSN %q", got, cfg.DSN())
	}
	if !strings.Contains(cfg.DSN(), "port=6432") {
		t.Errorf("direct_port moved the pooled DSN: %q", cfg.DSN())
	}
}

// TestAdvisoryLockSessionLive takes the lock over the session DSN: a second
// client is refused while it is held and gets it once it is released.
func TestAdvisoryLockSessionLive(t *testing.T) {
	cfg := liveConfig(t)
	cfg.DirectPort = cfg.Port
	a, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	b, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	const key = 0x5e55_1011
	ctx := context.Background()
	acquired, release, err := a.TryAdvisoryLock(ctx, key)
	if err != nil || !acquired {
		t.Fatalf("first lock: acquired %v, err %v", acquired, err)
	}
	again, _, err := b.TryAdvisoryLock(ctx, key)
	if err != nil || again {
		t.Fatalf("second client while held: acquired %v, err %v", again, err)
	}
	release()
	after, releaseAfter, err := b.TryAdvisoryLock(ctx, key)
	if err != nil || !after {
		t.Fatalf("second client after release: acquired %v, err %v", after, err)
	}
	releaseAfter()
}
