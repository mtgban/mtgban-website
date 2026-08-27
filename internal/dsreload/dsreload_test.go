package dsreload

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestSecondReloadIsRefused keeps a second load from being built beside the
// one already running. Each costs several times the memory the site settles
// at, so two at once is what the process cannot spare.
func TestSecondReloadIsRefused(t *testing.T) {
	var tracker Tracker
	release := make(chan struct{})
	started := make(chan struct{})

	if !tracker.Start("first", "ds", func() error {
		close(started)
		<-release
		return nil
	}) {
		t.Fatal("the first reload did not start")
	}
	<-started

	if tracker.Start("second", "ds", func() error {
		t.Error("the second reload ran while the first was still going")
		return nil
	}) {
		t.Error("the second reload reported that it started")
	}

	if state := tracker.Status(); !state.Running || state.Source != "first" {
		t.Errorf("status = %+v, want the first still running", state)
	}

	close(release)
	waitFor(t, &tracker)

	if !tracker.Start("third", "ds", func() error { return nil }) {
		t.Error("a reload was refused after the running one finished")
	}
	waitFor(t, &tracker)
}

// TestReloadRecordsWhyItFailed pins the failure onto the status the admin
// page reads, since the caller is answered before the load is done and has
// nowhere else to learn of it.
func TestReloadRecordsWhyItFailed(t *testing.T) {
	var tracker Tracker
	tracker.Start("api", "ds", func() error { return errors.New("bucket said no") })
	waitFor(t, &tracker)

	state := tracker.Status()
	if state.Err != "bucket said no" {
		t.Errorf("Err = %q, want the error the load returned", state.Err)
	}
	if state.EndedAt.IsZero() {
		t.Error("EndedAt was never stamped")
	}
}

// TestPanicIsRecoveredNotFatal is the one that matters for moving the load
// off the request. net/http recovers a panic in a handler and drops that one
// connection; on a goroutine of its own an unrecovered panic takes the whole
// process with it.
func TestPanicIsRecoveredNotFatal(t *testing.T) {
	var tracker Tracker
	tracker.Start("api", "ds", func() error { panic("datastore is half a file") })
	waitFor(t, &tracker)

	state := tracker.Status()
	if !strings.Contains(state.Err, "datastore is half a file") {
		t.Errorf("Err = %q, want it to name the panic", state.Err)
	}
	if strings.Contains(state.Err, "goroutine") {
		t.Errorf("Err = %q, want the stack left in the log", state.Err)
	}
	if state.Running {
		t.Error("still marked running after a panic")
	}
}

// TestSucceededReloadClearsTheLastError guards the page against showing the
// previous failure once a later load has gone through.
func TestSucceededReloadClearsTheLastError(t *testing.T) {
	var tracker Tracker
	tracker.Start("api", "ds", func() error { return errors.New("bucket said no") })
	waitFor(t, &tracker)
	tracker.Start("admin", "ds", func() error { return nil })
	waitFor(t, &tracker)

	if state := tracker.Status(); state.Err != "" || state.Running {
		t.Errorf("status = %+v, want a finished reload with no error", state)
	}
}

// TestElapsedCounts answers for both a running reload and a finished one.
func TestElapsedCounts(t *testing.T) {
	var zero State
	if zero.Elapsed() != 0 {
		t.Errorf("a reload that never ran reports %v", zero.Elapsed())
	}
	running := State{Running: true, StartedAt: time.Now().Add(-90 * time.Second)}
	if running.Elapsed() < 89*time.Second {
		t.Errorf("a running reload reports %v, want about 90s", running.Elapsed())
	}
	done := State{StartedAt: time.Now().Add(-2 * time.Minute), EndedAt: time.Now().Add(-time.Minute)}
	if done.Elapsed() != time.Minute {
		t.Errorf("a finished reload reports %v, want 1m", done.Elapsed())
	}
}

func waitFor(t *testing.T, tracker *Tracker) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !tracker.Status().Running {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the reload never finished")
}
