package timeseries

import (
	"context"
	"testing"
	"time"

	"github.com/lib/pq"
)

// TestNotifyLive round-trips a notification through a real Postgres: Notify
// on the Client's pool, receive on a lib/pq Listener holding its own
// connection - the exact split the website's access reload uses.
//
// Like the other live tests it is skipped unless TCGLIVE_HOST is set. The
// sentinel channel has no listeners in production, so the notify is invisible
// to real deployments.
func TestNotifyLive(t *testing.T) {
	cfg := liveConfig(t)
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	const channel = "timeseries_notify_live_test"
	listener := pq.NewListener(cfg.DSN(), 10*time.Second, time.Minute, nil)
	t.Cleanup(func() { _ = listener.Close() })
	err = listener.Listen(channel)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	err = c.Notify(context.Background(), channel, "sender-instance")
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}

	deadline := time.After(10 * time.Second)
	for {
		select {
		case n := <-listener.Notify:
			// nil is the listener reporting a (re)connect, not a message.
			if n == nil {
				continue
			}
			if n.Channel != channel || n.Extra != "sender-instance" {
				t.Fatalf("got notification %q on %q, want %q on %q",
					n.Extra, n.Channel, "sender-instance", channel)
			}
			return
		case <-deadline:
			t.Fatal("notification never arrived")
		}
	}
}
