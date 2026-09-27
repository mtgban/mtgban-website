package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestSitesServeIndependentDatastores checks that a handler needing no
// scrapers or templates answers from the site it is called on, never the
// other one's: two sites each publish their own fixture, and each is then
// asked for the other's card, set and name.
func TestSitesServeIndependentDatastores(t *testing.T) {
	withSigMode(t, true, false)

	siteA := newSite()
	siteA.ds.Store(siteA.newDatastore(fixtureBackend("FIXTUREA", "Fixture Edition Alpha", "2020-01-01",
		[][2]string{{"Fixture Card Alpha", "1"}}), time.Now()))

	siteB := newSite()
	siteB.ds.Store(siteB.newDatastore(fixtureBackend("FIXTUREB", "Fixture Edition Beta", "2021-06-15",
		[][2]string{{"Fixture Card Beta", "1"}}), time.Now()))

	t.Run("RawCardAPI", func(t *testing.T) {
		rec := httptest.NewRecorder()
		siteA.RawCardAPI(rec, httptest.NewRequest(http.MethodGet, "/api/mtgmatcher/raw/FIXTUREA-1", nil))
		if rec.Code != http.StatusOK {
			t.Errorf("site A for its own card FIXTUREA-1 = %d, want %d", rec.Code, http.StatusOK)
		}

		rec = httptest.NewRecorder()
		siteB.RawCardAPI(rec, httptest.NewRequest(http.MethodGet, "/api/mtgmatcher/raw/FIXTUREA-1", nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("site B for site A's card FIXTUREA-1 = %d, want %d", rec.Code, http.StatusNotFound)
		}
	})

	t.Run("palette Sets", func(t *testing.T) {
		rec := httptest.NewRecorder()
		siteA.palette.Sets(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		bodyA := rec.Body.String()
		if !strings.Contains(bodyA, "FIXTUREA") || strings.Contains(bodyA, "FIXTUREB") {
			t.Errorf("site A's sets = %s, want FIXTUREA only", bodyA)
		}

		rec = httptest.NewRecorder()
		siteB.palette.Sets(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		bodyB := rec.Body.String()
		if !strings.Contains(bodyB, "FIXTUREB") || strings.Contains(bodyB, "FIXTUREA") {
			t.Errorf("site B's sets = %s, want FIXTUREB only", bodyB)
		}
	})

	t.Run("SuggestAPI", func(t *testing.T) {
		q := "/api/suggest?q=" + url.QueryEscape("Fixture Card Alpha")

		rec := httptest.NewRecorder()
		siteA.SuggestAPI(rec, httptest.NewRequest(http.MethodGet, q, nil))
		if !suggestedTheName(t, rec.Body.Bytes()) {
			t.Errorf("site A did not suggest its own card: %s", rec.Body)
		}

		rec = httptest.NewRecorder()
		siteB.SuggestAPI(rec, httptest.NewRequest(http.MethodGet, q, nil))
		if suggestedTheName(t, rec.Body.Bytes()) {
			t.Errorf("site B suggested site A's card: %s", rec.Body)
		}
	})
}

// suggestedTheName reports whether a SuggestAPI response carries a real
// match rather than the empty-suggestions placeholder: the query itself is
// always echoed back as the response's first element, matched or not, so
// the body has to be decoded rather than searched for the queried name.
func suggestedTheName(t *testing.T, body []byte) bool {
	t.Helper()
	var decoded []any
	err := json.Unmarshal(body, &decoded)
	if err != nil {
		t.Fatalf("SuggestAPI response is not json: %v (%s)", err, body)
	}
	if len(decoded) < 2 {
		return false
	}
	suggestions, ok := decoded[1].([]any)
	if !ok || len(suggestions) == 0 {
		return false
	}
	name, ok := suggestions[0].(string)
	return ok && name != ""
}

// TestSiteDoesNotPinAReplacedDatastore checks that once a site stops serving
// a datastore, nothing it holds keeps that datastore's backend reachable: A
// is served, then replaced by B, and the site outlives the check.
func TestSiteDoesNotPinAReplacedDatastore(t *testing.T) {
	withSigMode(t, true, false)

	s := newSite()
	cleaned := make(chan struct{})

	func() {
		// A's backend is referenced only from here and from the site.
		backendA := fixtureBackend("FIXTUREA", "Fixture Edition Alpha", "2020-01-01",
			[][2]string{{"Fixture Card Alpha", "1"}})
		runtime.AddCleanup(backendA, func(done chan struct{}) { close(done) }, cleaned)
		s.ds.Store(s.newDatastore(backendA, time.Now()))
		exerciseSite(s, "FIXTUREA-1", "Fixture Card Alpha")

		s.ds.Store(s.newDatastore(fixtureBackend("FIXTUREB", "Fixture Edition Beta", "2021-06-15",
			[][2]string{{"Fixture Card Beta", "1"}}), time.Now()))
		exerciseSite(s, "FIXTUREB-1", "Fixture Card Beta")
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		select {
		case <-cleaned:
			return
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("fixture A's backend was never collected: something still pins it")
		}
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
		// A site collected with what it holds would hide a pin.
		runtime.KeepAlive(s)
	}
}

// exerciseSite serves a card, a suggestion, the palette sets and an offline
// manifest refresh from the site's current datastore.
func exerciseSite(s *site, cardID, name string) {
	s.RawCardAPI(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/mtgmatcher/raw/"+cardID, nil))
	s.SuggestAPI(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/suggest?q="+url.QueryEscape(name), nil))
	s.palette.Sets(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	s.offline.RefreshManifest()
}

// TestSiteConcurrentPublishAndReadDontRace hammers one site's read side while
// another goroutine keeps replacing its datastore, so that a handler mutating
// the backend's shared data in place, which every other reader sees too,
// shows up as a race under -race rather than passing quietly.
func TestSiteConcurrentPublishAndReadDontRace(t *testing.T) {
	withSigMode(t, true, false)

	s := newSite()
	dsA := s.newDatastore(fixtureBackend("FIXTUREA", "Fixture Edition Alpha", "2020-01-01",
		[][2]string{{"Fixture Card Alpha", "1"}}), time.Now())
	dsB := s.newDatastore(fixtureBackend("FIXTUREB", "Fixture Edition Beta", "2021-06-15",
		[][2]string{{"Fixture Card Beta", "1"}}), time.Now())
	s.ds.Store(dsA)

	deadline := time.Now().Add(750 * time.Millisecond)
	var wg sync.WaitGroup

	wg.Go(func() {
		toggle := false
		for time.Now().Before(deadline) {
			if toggle {
				s.ds.Store(dsA)
			} else {
				s.ds.Store(dsB)
			}
			toggle = !toggle
		}
	})

	const readers = 8
	for i := 0; i < readers; i++ {
		wg.Go(func() {
			for time.Now().Before(deadline) {
				rec := httptest.NewRecorder()
				s.RawCardAPI(rec, httptest.NewRequest(http.MethodGet, "/api/mtgmatcher/raw/FIXTUREA-1", nil))

				rec = httptest.NewRecorder()
				s.SuggestAPI(rec, httptest.NewRequest(http.MethodGet, "/api/suggest?q=Fixture", nil))

				rec = httptest.NewRecorder()
				s.palette.Sets(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			}
		})
	}

	wg.Wait()
}
