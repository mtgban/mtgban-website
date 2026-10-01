package alerts

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// liveService is a Service with a store, so its methods act; nothing in
// these tests reaches the database.
func liveService(deps EvalDeps) *Service {
	return NewService(&Store{}, deps, APIDeps{})
}

func TestRequestEvaluateCoalesces(t *testing.T) {
	s := liveService(EvalDeps{})

	// Never blocks, whatever the queue holds.
	for i := 0; i < 5; i++ {
		s.RequestEvaluate(SideRetail)
		s.RequestEvaluate(SideBuylist)
	}
	sides := s.takePending()
	if len(sides) != 2 {
		t.Fatalf("pending sides = %v", sides)
	}
	got := s.takePending()
	if len(got) != 0 {
		t.Fatalf("second take = %v", got)
	}
	select {
	case <-s.signal:
	default:
		t.Fatal("no signal queued")
	}
	select {
	case <-s.signal:
		t.Fatal("a burst queued more than one signal")
	default:
	}
}

func TestRunPendingWaitsUntilReady(t *testing.T) {
	store := newFakeEvalStore(activeAlert())
	sender := &fakeSender{}
	deps := evalDeps(store, sender, 13)
	s := liveService(deps)
	s.RequestEvaluate(SideBuylist)

	deps.Ready = func() bool { return false }
	s.runPending(context.Background(), deps)
	if store.calls != 0 || len(sender.sent) != 0 {
		t.Fatalf("not-ready run touched the store (%d calls) or sent %v", store.calls, sender.sent)
	}

	deps.Ready = func() bool { return true }
	s.runPending(context.Background(), deps)
	if len(sender.sent) != 1 {
		t.Fatalf("queued side did not survive to the ready run: sent=%v", sender.sent)
	}
	got := s.takePending()
	if len(got) != 0 {
		t.Fatalf("ready run left sides queued: %v", got)
	}
}

func TestServicePrunesAtMostHourly(t *testing.T) {
	s := liveService(EvalDeps{})
	if !s.pruneDue(evalNow) || s.pruneDue(evalNow.Add(59*time.Minute)) {
		t.Fatal("prune due twice inside the hour")
	}
	if !s.pruneDue(evalNow.Add(61 * time.Minute)) {
		t.Fatal("prune not due after the hour")
	}
}

func TestStartEvaluatorRunsThroughTracked(t *testing.T) {
	store := newFakeEvalStore(activeAlert())
	sender := &fakeSender{}
	deps := evalDeps(store, sender, 13)
	deps.Debounce = time.Millisecond
	bound := 0
	deps.PerRun = func(d EvalDeps) EvalDeps {
		bound++
		return d
	}
	s := liveService(deps)
	done := make(chan struct{}, 1)
	s.StartEvaluator(func(fn func()) func() {
		return func() {
			fn()
			done <- struct{}{}
		}
	})
	s.RequestEvaluate(SideBuylist)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop never ran")
	}
	if len(sender.sent) != 1 {
		t.Fatalf("sent = %v", sender.sent)
	}
	if bound != 1 {
		t.Fatalf("PerRun bound %d times, want once per run", bound)
	}
}

func TestNilStoreServiceIsANoOp(t *testing.T) {
	for name, s := range map[string]*Service{"nil store": NewService(nil, EvalDeps{}, APIDeps{}), "nil service": nil} {
		t.Run(name, func(t *testing.T) {
			for i := 0; i < 3; i++ {
				s.RequestEvaluate(SideRetail, SideBuylist)
			}
			s.StartEvaluator(func(func()) func() {
				t.Fatal("StartEvaluator wrapped a run with no store")
				return nil
			})
			if s != nil && (len(s.pending) != 0 || len(s.signal) != 0) {
				t.Fatalf("no-op service queued: pending=%v signal=%d", s.pending, len(s.signal))
			}
		})
	}
}

// listFailStore fails ListActive, as a dropped database would.
type listFailStore struct{ *fakeEvalStore }

func (listFailStore) ListActive(context.Context, string, []Side) ([]ActiveAlert, error) {
	return nil, errors.New("connection refused")
}

func TestRunPendingReports(t *testing.T) {
	type report struct{ summary, problem string }
	run := func(store EvalStore, price float64, ready bool, sendErr error) report {
		var got []report
		deps := evalDeps(newFakeEvalStore(activeAlert()), &fakeSender{err: sendErr}, price)
		deps.Store = store
		deps.Ready = func() bool { return ready }
		deps.Report = func(summary, problem string) { got = append(got, report{summary, problem}) }
		s := liveService(deps)
		s.RequestEvaluate(SideBuylist)
		s.runPending(context.Background(), deps)
		if len(got) != 1 {
			t.Fatalf("reports = %+v, want one", got)
		}
		return got[0]
	}

	r := run(listFailStore{newFakeEvalStore(activeAlert())}, 13, true, nil)
	if !strings.Contains(r.problem, "connection refused") {
		t.Fatalf("store error not reported as the problem: %+v", r)
	}
	r = run(newFakeEvalStore(activeAlert()), 11, true, nil)
	if r.problem != "" || r.summary != "1 users, 1 active, 0 sent, 0 skipped" {
		t.Fatalf("quiet run: %+v", r)
	}
	r = run(newFakeEvalStore(activeAlert()), 13, false, nil)
	if r.problem != "" || r.summary != "waiting for the datastore and prices" {
		t.Fatalf("not-ready run: %+v", r)
	}
	r = run(newFakeEvalStore(activeAlert()), 13, true, errors.New("gateway timeout"))
	if !strings.Contains(r.problem, "gateway timeout") || r.summary != "1 users, 1 active, 0 sent, 0 skipped" {
		t.Fatalf("failed send counted as sent or not reported: %+v", r)
	}
	r = run(newFakeEvalStore(activeAlert()), 13, true, nil)
	if r.problem != "" || r.summary != "1 users, 1 active, 1 sent, 0 skipped" {
		t.Fatalf("delivered run: %+v", r)
	}
}

func TestPendingIsSortedAndNilWhenUnavailable(t *testing.T) {
	s := liveService(EvalDeps{})
	s.RequestEvaluate(SideRetail, SideBuylist)
	got := s.Pending()
	if !slices.Equal(got, []Side{SideBuylist, SideRetail}) {
		t.Fatalf("Pending = %v", got)
	}
	got = s.Pending()
	if len(got) != 2 {
		t.Fatalf("Pending consumed the queue: %v", got)
	}
	var none *Service
	if none.Pending() != nil || NewService(nil, EvalDeps{}, APIDeps{}).Pending() != nil {
		t.Fatal("an unavailable service has sides pending")
	}
}

func TestSetStoreBuildsTheLimiterOnce(t *testing.T) {
	s := NewService(nil, EvalDeps{}, APIDeps{})
	if s.api.deps.Limiter != nil {
		t.Fatal("a service with no store built a limiter")
	}
	s.SetStore(&Store{})
	first := s.api.deps.Limiter
	if first == nil {
		t.Fatal("SetStore built no limiter")
	}
	s.SetStore(nil)
	s.SetStore(&Store{})
	if s.api.deps.Limiter != first {
		t.Fatal("a second SetStore built a second limiter")
	}
}
