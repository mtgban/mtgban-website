package offlineapi

import (
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

func TestRequestRefreshDoesNotBlock(t *testing.T) {
	s := &Service{refreshSignal: make(chan struct{}, 1)}
	// No reader drains the channel; extra sends must not block.
	for i := 0; i < 100; i++ {
		s.RequestRefresh()
	}
}

// A refresh that panics is recovered on its own, not with the loop around
// it, so the refresher still serves the next request.
func TestRefresherOutlivesAPanickingRefresh(t *testing.T) {
	prev := refreshDebounce
	refreshDebounce = time.Millisecond
	t.Cleanup(func() { refreshDebounce = prev })

	s := NewService(Deps{
		Datastore: func() (*mtgmatcher.Backend, time.Time) { panic("no datastore") },
	})
	recoveredRuns := make(chan any)
	s.StartRefresher(func(_ string, fn func()) func() {
		return func() {
			defer func() { recoveredRuns <- recover() }()
			fn()
		}
	})

	for run := 1; run <= 2; run++ {
		s.RequestRefresh()
		select {
		case p := <-recoveredRuns:
			if p == nil {
				t.Fatalf("refresh %d did not panic", run)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("refresh %d never ran", run)
		}
	}
}
