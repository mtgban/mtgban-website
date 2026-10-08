package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/observability"
)

type fakeVoteStore struct {
	calls []fakeVote
	err   error
}

type fakeVote struct {
	instance, key, userHash, query string
	budget                         int
}

func (f *fakeVoteStore) RecordSearchVote(_ context.Context, instance, key, userHash string, _ time.Time, query string, budget int) error {
	f.calls = append(f.calls, fakeVote{instance, key, userHash, query, budget})
	return f.err
}

func voteRequest(method, sig, q string) *http.Request {
	var body string
	if q != "" {
		body = url.Values{"q": {q}}.Encode()
	}
	r := httptest.NewRequest(method, "/api/popular/vote", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if sig != "" {
		r.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sig})
	}
	return r
}

func TestPopularVoteAPIRefusesCrossSite(t *testing.T) {
	withSigMode(t, true, false)
	s := newSite()
	w := httptest.NewRecorder()
	r := voteRequest(http.MethodPost, devSig("a@b.com", "Legacy"), "x")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	s.PopularVoteAPI(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-site = %d, want 403", w.Code)
	}
}

func TestPopularVoteAPIRefusesGet(t *testing.T) {
	withSigMode(t, true, false)
	s := newSite()
	w := httptest.NewRecorder()
	s.PopularVoteAPI(w, voteRequest(http.MethodGet, devSig("a@b.com", "Legacy"), "x"))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d, want 405", w.Code)
	}
}

func TestPopularVoteAPIRefusesAnonymous(t *testing.T) {
	withSigMode(t, true, false)
	s := newSite()
	w := httptest.NewRecorder()
	s.PopularVoteAPI(w, voteRequest(http.MethodPost, "", "x"))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous = %d, want 401", w.Code)
	}
}

func TestPopularVoteAPIWithoutStoreIsANoop(t *testing.T) {
	withSigMode(t, true, false)
	s := newSite()
	w := httptest.NewRecorder()
	s.PopularVoteAPI(w, voteRequest(http.MethodPost, devSig("a@b.com", "Legacy"), "x"))
	if w.Code != http.StatusNoContent {
		t.Fatalf("no store = %d, want 204", w.Code)
	}
}

func TestPopularVoteAPIRecordsTheResolvedKey(t *testing.T) {
	skipWithoutDatastore(t)
	withSigMode(t, true, false)
	prevInstance := observabilityInstance
	observabilityInstance = "test-instance"
	t.Cleanup(func() { observabilityInstance = prevInstance })
	s := newSite()
	s.ds.Store(currentDatastore())
	store := &fakeVoteStore{}
	s.popularVotes = store

	w := httptest.NewRecorder()
	s.PopularVoteAPI(w, voteRequest(http.MethodPost, devSig("vote@b.com", "Legacy"), "black lotus"))
	if w.Code != http.StatusNoContent {
		t.Fatalf("vote = %d, want 204", w.Code)
	}
	if len(store.calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(store.calls))
	}
	got := store.calls[0]
	want := fakeVote{
		instance: observabilityInstance, key: "card:Black Lotus",
		userHash: observability.HashVisitor("vote@b.com"), query: "black lotus", budget: popularDailyBudget,
	}
	if got != want {
		t.Fatalf("vote = %+v, want %+v", got, want)
	}

	// A query that finds nothing records nothing.
	w = httptest.NewRecorder()
	s.PopularVoteAPI(w, voteRequest(http.MethodPost, devSig("vote@b.com", "Legacy"), "zzzz no such card zzzz"))
	if w.Code != http.StatusNoContent || len(store.calls) != 1 {
		t.Fatalf("no results: code %d, calls %d, want 204 and 1", w.Code, len(store.calls))
	}

	// An empty query records nothing.
	w = httptest.NewRecorder()
	s.PopularVoteAPI(w, voteRequest(http.MethodPost, devSig("vote@b.com", "Legacy"), ""))
	if w.Code != http.StatusNoContent || len(store.calls) != 1 {
		t.Fatalf("empty: code %d, calls %d, want 204 and 1", w.Code, len(store.calls))
	}
}

// ambiguousQuery is a typed prefix whose results span several card names in
// the loaded datastore. Chosen at run time: "lotus" was one until a token
// named Lotus made it an exact match.
func ambiguousQuery(t *testing.T, ds *datastore) string {
	t.Helper()
	for _, q := range []string{"bolt", "lotus", "dragon", "angel", "goblin"} {
		uuids, err := searchAndFilter(ds, parseSearchOptionsNG(ds.backend, q, nil, nil, nil))
		if err != nil {
			continue
		}
		names := map[string]struct{}{}
		for _, id := range uuids {
			if co, err := ds.backend.GetUUID(id); err == nil {
				names[co.Name] = struct{}{}
			}
		}
		if len(names) > 1 {
			return q
		}
	}
	t.Skip("no prefix spans several names in this datastore")
	return ""
}

// TestPopularVoteAPIResolvesOnlyUnambiguousQueries covers F1 (a query whose
// results span several card names votes for none of them) and F2 (a bare
// rarity filter can never yield a key, so it is refused before searching).
func TestPopularVoteAPIResolvesOnlyUnambiguousQueries(t *testing.T) {
	skipWithoutDatastore(t)
	withSigMode(t, true, false)
	s := newSite()
	s.ds.Store(currentDatastore())
	store := &fakeVoteStore{}
	s.popularVotes = store
	email := "vote-shape@b.com"
	sig := devSig(email, "Legacy")

	post := func(q string) int {
		w := httptest.NewRecorder()
		s.PopularVoteAPI(w, voteRequest(http.MethodPost, sig, q))
		return w.Code
	}

	// A prefix that widens across several card names cannot vote for
	// whichever one sorts first.
	prefix := ambiguousQuery(t, s.datastore())
	if code := post(prefix); code != http.StatusNoContent {
		t.Fatalf("%s: code %d, want 204", prefix, code)
	}
	if len(store.calls) != 0 {
		t.Fatalf("%s: calls = %d, want 0", prefix, len(store.calls))
	}

	// An exact name still resolves, even though the prefix did not.
	if code := post("black lotus"); code != http.StatusNoContent {
		t.Fatalf("black lotus: code %d, want 204", code)
	}
	if len(store.calls) != 1 || store.calls[0].key != "card:Black Lotus" {
		t.Fatalf("black lotus: calls = %+v, want one card:Black Lotus", store.calls)
	}

	// A bare rarity filter has no shape that can ever yield a key.
	if code := post("r:mythic"); code != http.StatusNoContent {
		t.Fatalf("r:mythic: code %d, want 204", code)
	}
	if len(store.calls) != 1 {
		t.Fatalf("r:mythic: calls = %d, want 1", len(store.calls))
	}

	// A single edition filter still resolves to a set key.
	if code := post("s:LEA"); code != http.StatusNoContent {
		t.Fatalf("s:LEA: code %d, want 204", code)
	}
	if len(store.calls) != 2 || store.calls[1].key != "set:LEA" {
		t.Fatalf("s:LEA: calls = %+v, want a second call with set:LEA", store.calls)
	}
}

func TestPopularVoteAPILogsAStoreError(t *testing.T) {
	skipWithoutDatastore(t)
	withSigMode(t, true, false)
	s := newSite()
	s.ds.Store(currentDatastore())
	store := &fakeVoteStore{err: errors.New("db down")}
	s.popularVotes = store

	var logged bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(prev)

	w := httptest.NewRecorder()
	s.PopularVoteAPI(w, voteRequest(http.MethodPost, devSig("vote-err@b.com", "Legacy"), "black lotus"))
	if w.Code != http.StatusNoContent {
		t.Fatalf("store error = %d, want 204", w.Code)
	}
	if len(store.calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(store.calls))
	}
	if !strings.Contains(logged.String(), "record vote") {
		t.Fatalf("log = %q, want it to mention record vote", logged.String())
	}
}
