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

// Tracker owns the one reload that may be under way.
type Tracker struct {
	mutex sync.Mutex
	state State
}

// Start loads in the background and reports whether this call is the one that
// started it.
//
// Loading builds a second datastore beside the one still being served, so a
// reload costs several times the memory the site settles at. A request that
// arrives while one is running is answered by the running one rather than
// stacking a third copy on top.
//
// The work runs on a goroutine of its own, where a panic would take the whole
// process down rather than the one connection net/http recovers. It is
// recovered here and recorded as the reason the reload failed, so a load that
// cannot finish says so instead of restarting the server.
func (t *Tracker) Start(source, path string, work func() error) bool {
	t.mutex.Lock()
	if t.state.Running {
		t.mutex.Unlock()
		return false
	}
	t.state = State{
		Running:   true,
		Source:    source,
		Path:      path,
		StartedAt: time.Now(),
	}
	t.mutex.Unlock()

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

	return true
}

func (t *Tracker) finish(err error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.state.Running = false
	t.state.EndedAt = time.Now()
	t.state.Err = ""
	if err != nil {
		t.state.Err = err.Error()
	}
}

// Status answers what the current or last reload did.
func (t *Tracker) Status() State {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.state
}
