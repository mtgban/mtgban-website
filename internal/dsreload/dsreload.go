// Package dsreload runs one datastore reload at a time and remembers what it
// did, so a caller answered before the load finished can still be told.
package dsreload

import (
	"fmt"
	"log"
	"runtime/debug"
	"sync"
	"time"
)

// State is what a reload is doing, or what the last one did.
type State struct {
	Running   bool
	Source    string
	Path      string
	StartedAt time.Time
	EndedAt   time.Time
	Err       string
	// Queued is set while another reload waits for this one to end.
	Queued bool
}

// Elapsed answers how long the reload ran, or has been running.
func (s State) Elapsed() time.Duration {
	if s.StartedAt.IsZero() {
		return 0
	}
	if s.Running {
		return time.Since(s.StartedAt).Round(time.Second)
	}
	return s.EndedAt.Sub(s.StartedAt).Round(time.Second)
}

// Tracker owns the one reload that may be under way, and the one that may
// wait for it.
type Tracker struct {
	mutex sync.Mutex
	state State
	next  *queued
}

// queued is a reload asked for while another ran.
type queued struct {
	source, path string
	work         func() error
}

// Start loads in the background and reports whether this call is the one that
// started it.
//
// Loading builds a second datastore beside the one still being served, so a
// reload costs several times the memory the site settles at. A request that
// arrives while one is running is queued to run once it ends rather than
// stacking a third copy on top: the running one may have read the datastore
// before the caller published a new one. A later request replaces the queued
// one, so at most one waits.
//
// The work runs on a goroutine of its own, where a panic would take the whole
// process down rather than the one connection net/http recovers. It is
// recovered here and recorded as the reason the reload failed, so a load that
// cannot finish says so instead of restarting the server.
func (t *Tracker) Start(source, path string, work func() error) bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	if t.state.Running {
		t.next = &queued{source: source, path: path, work: work}
		return false
	}
	t.run(source, path, work)
	return true
}

// run starts work. Callers must hold t.mutex.
func (t *Tracker) run(source, path string, work func() error) {
	t.state = State{
		Running:   true,
		Source:    source,
		Path:      path,
		StartedAt: time.Now(),
	}
	go func() {
		err := func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					// The stack goes to the log; the caller gets the one
					// line it can show without becoming a stack trace.
					log.Printf("datastore reload panicked: %v\n%s", r, debug.Stack())
					err = fmt.Errorf("panic: %v", r)
				}
			}()
			return work()
		}()
		t.finish(err)
	}()
}

// finish records how the running reload ended, and starts the queued one.
func (t *Tracker) finish(err error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.state.Running = false
	t.state.EndedAt = time.Now()
	t.state.Err = ""
	if err != nil {
		t.state.Err = err.Error()
	}
	next := t.next
	if next == nil {
		return
	}
	t.next = nil
	if err != nil {
		// The queued run replaces this state, and with it the failure.
		log.Printf("datastore reload from %s failed: %v", t.state.Source, err)
	}
	t.run(next.source, next.path, next.work)
}

// Status answers what the current or last reload did.
func (t *Tracker) Status() State {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	state := t.state
	state.Queued = t.next != nil
	return state
}
