package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func stubGAFetch(t *testing.T, fetch func(string) ([]string, error)) {
	t.Helper()
	prevFetch, prevAPI := gaFetch, Config.Api
	t.Cleanup(func() { gaFetch, Config.Api = prevFetch, prevAPI })
	gaFetch = fetch
	Config.Api = map[string]string{"github_action_token": "test-token"}
}

// The poll answers with both states, and asks for them at the same time: run
// back to back these were the two round trips that used to precede the page.
func TestRunningWorkflowsQueriesStatesConcurrently(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	stubGAFetch(t, func(state string) ([]string, error) {
		started <- struct{}{}
		<-release // no call may finish before both have begun
		return []string{state}, nil
	})

	done := make(chan []string, 1)
	go func() { done <- runningWorkflows() }()

	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("the two states are still queried one after the other")
		}
	}
	close(release)

	got := <-done
	if len(got) != 2 {
		t.Errorf("running = %v, want one entry per state", got)
	}
}

// A failing state is logged and skipped: the dashboard keeps the rows it has.
func TestRunningWorkflowsToleratesFailure(t *testing.T) {
	stubGAFetch(t, func(state string) ([]string, error) {
		if state == "queued" {
			return nil, errors.New("github unreachable")
		}
		return []string{state}, nil
	})

	got := runningWorkflows()
	if len(got) != 1 || got[0] != "in_progress" {
		t.Errorf("running = %v, want just the state that answered", got)
	}
}

func TestRunningWorkflowsSkipsWithoutToken(t *testing.T) {
	var calls int32
	stubGAFetch(t, func(state string) ([]string, error) {
		atomic.AddInt32(&calls, 1)
		return []string{state}, nil
	})
	Config.Api = map[string]string{}

	if got := runningWorkflows(); got != nil {
		t.Errorf("running = %v, want nil", got)
	}
	if n := atomic.LoadInt32(&calls); n != 0 {
		t.Errorf("made %d calls without a token, want none", n)
	}
}

// The endpoint the page polls: json, uncached, and shaped as the script reads it.
func TestServeRunningWorkflows(t *testing.T) {
	stubGAFetch(t, func(state string) ([]string, error) {
		return []string{state + "-scraper"}, nil
	})

	w := httptest.NewRecorder()
	serveRunningWorkflows(w)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("cache-control = %q, want no-store", cc)
	}
	var payload struct {
		Running []string `json:"running"`
	}
	if err := json.NewDecoder(w.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(payload.Running) != 2 {
		t.Errorf("running = %v, want both states", payload.Running)
	}
}
