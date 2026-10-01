package alerts

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/mtgban/mtgban-website/internal/debounce"
	"github.com/mtgban/mtgban-website/ratelimit"
)

// Defaults NewService applies to the deps it is handed when they are zero.
const (
	defaultDebounce   = 30 * time.Second
	defaultRunTimeout = 5 * time.Minute
	defaultSendPace   = 250 * time.Millisecond
)

// The API's per-user request rate and burst.
const (
	apiRate  = 10
	apiBurst = 5
)

// Service owns the price alerts evaluator: the sides waiting for a run and
// the debounced loop that runs them, and the HTTP API. A nil Store means
// alerts are unavailable: the evaluator is a no-op and the API answers 503.
type Service struct {
	store *Store
	deps  EvalDeps
	api   *API
	// signal wakes the loop; buffered so RequestEvaluate never blocks and
	// bursts coalesce.
	signal chan struct{}
	// mu guards pending and lastPrune.
	mu        sync.Mutex
	pending   map[Side]bool
	lastPrune time.Time
}

// NewService constructs a Service evaluating store's alerts with deps and
// serving them through an API on apiDeps, whose Store defaults to store.
func NewService(store *Store, deps EvalDeps, apiDeps APIDeps) *Service {
	s := &Service{store: store, signal: make(chan struct{}, 1)}
	if apiDeps.Store == nil && store != nil {
		apiDeps.Store = store
	}
	if apiDeps.Limiter == nil && store != nil {
		apiDeps.Limiter = ratelimit.NewLimiter(apiRate, apiBurst)
	}
	s.api = NewAPI(apiDeps)
	if deps.Store == nil && store != nil {
		deps.Store = store
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Debounce == 0 {
		deps.Debounce = defaultDebounce
	}
	if deps.RunTimeout == 0 {
		deps.RunTimeout = defaultRunTimeout
	}
	if deps.Pace == 0 {
		deps.Pace = defaultSendPace
	}
	if deps.PruneDue == nil {
		deps.PruneDue = s.pruneDue
	}
	s.deps = deps
	return s
}

// Store is the alerts store, nil when alerts are unavailable.
func (s *Service) Store() *Store {
	if s == nil {
		return nil
	}
	return s.store
}

// SetStore replaces the store the evaluator and the API carry, and gives
// the API its limiter on the first non-nil one. Unsynchronized: safe only
// because openDBs runs before any request, load or evaluator goroutine.
func (s *Service) SetStore(store *Store) {
	s.store = store
	s.deps.Store, s.api.deps.Store = nil, nil
	if store != nil {
		s.deps.Store, s.api.deps.Store = store, store
		if s.api.deps.Limiter == nil {
			s.api.deps.Limiter = ratelimit.NewLimiter(apiRate, apiBurst)
		}
	}
}

// API is the HTTP API; a nil Service's answers 503 to every request.
func (s *Service) API() *API {
	if s == nil {
		return nil
	}
	return s.api
}

// unavailable is a Service with no store, nil included.
func (s *Service) unavailable() bool {
	return s == nil || s.store == nil
}

// RequestEvaluate notes that sides' prices changed and pokes the loop.
// Non-blocking; safe to call while holding a caller's lock.
func (s *Service) RequestEvaluate(sides ...Side) {
	if s.unavailable() {
		return
	}
	s.mu.Lock()
	if s.pending == nil {
		s.pending = map[Side]bool{}
	}
	for _, side := range sides {
		s.pending[side] = true
	}
	s.mu.Unlock()
	select {
	case s.signal <- struct{}{}:
	default:
	}
}

// Pending is the sides waiting for a run, sorted; nil when alerts are
// unavailable or nothing is waiting.
func (s *Service) Pending() []Side {
	if s.unavailable() {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Side
	for side := range s.pending {
		out = append(out, side)
	}
	slices.Sort(out)
	return out
}

// takePending returns and clears the sides that changed.
func (s *Service) takePending() []Side {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Side
	for side := range s.pending {
		out = append(out, side)
	}
	s.pending = nil
	return out
}

// pruneDue says whether an hour has passed since the last prune, and
// if so records now as the last one.
func (s *Service) pruneDue(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.lastPrune.IsZero() && now.Sub(s.lastPrune) < pruneEvery {
		return false
	}
	s.lastPrune = now
	return true
}

// StartEvaluator runs the debounced loop in a goroutine of its own. Each
// run goes through tracked, which the caller supplies to record it and
// recover a panic, so one that panics leaves the loop serving the next.
func (s *Service) StartEvaluator(tracked func(fn func()) func()) {
	if s.unavailable() {
		return
	}
	go debounce.Loop(s.signal, s.deps.Debounce, tracked(s.run))
}

// run is one debounced evaluation, bound to the live data.
func (s *Service) run() {
	deps := s.deps
	if deps.PerRun != nil {
		deps = deps.PerRun(deps)
	}
	ctx, cancel := context.WithTimeout(context.Background(), deps.RunTimeout)
	defer cancel()
	s.runPending(ctx, deps)
}

// runPending evaluates the pending sides once the data is in; until then
// the sides stay queued for the install that completes it.
func (s *Service) runPending(ctx context.Context, deps EvalDeps) {
	if deps.Ready != nil && !deps.Ready() {
		deps.logf("alerts: not ready, waiting for the datastore and prices")
		deps.report("waiting for the datastore and prices", "")
		return
	}
	sides := s.takePending()
	if len(sides) == 0 {
		deps.report("no prices changed", "")
		return
	}
	sum := runEvaluation(ctx, deps, sides)
	deps.report(sum.String(), sum.problem())
}
