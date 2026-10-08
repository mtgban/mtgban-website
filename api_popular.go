package main

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/mtgban/mtgban-website/observability"
	"github.com/mtgban/mtgban-website/ratelimit"
)

// popularVoteStore is where a search vote goes; *observability.Client is one.
type popularVoteStore interface {
	RecordSearchVote(ctx context.Context, instance, key, userHash string, day time.Time, query string, budget int) error
}

// popularVoteLimiter throttles the vote endpoint per signed-in email; one
// beacon per page load never needs more than this.
var popularVoteLimiter = ratelimit.NewLimiter(1, 5)

// PopularVoteAPI records a typed search that found results as one vote
// for the landing strip. The client sends only the raw query; the key is
// resolved here, so a vote can only be for what was searched and found.
func (s *site) PopularVoteAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// A hostile page cannot auto-submit a vote from a signed-in visitor.
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	email := signedUserEmail(r)
	if email == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if !popularVoteLimiter.Allow(email) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	// Every path from here answers 204: the beacon is fire-and-forget.
	defer w.WriteHeader(http.StatusNoContent)
	if s.popularVotes == nil {
		return
	}
	q := strings.TrimSpace(r.FormValue("q"))
	if q == "" || len(q) > MaxSearchQueryLen {
		return
	}
	key := resolvePopularKey(s.datastore(), q)
	if key == "" {
		return
	}
	err := s.popularVotes.RecordSearchVote(r.Context(), observabilityInstance, key,
		observability.HashVisitor(email), time.Now().UTC(), q, popularDailyBudget)
	if err != nil {
		log.Println("popular: record vote:", err)
	}
}

// popularSearchModes are the parsed search modes a vote can ever resolve
// a key from: a plain name search. Anything else (hashing, mixed,
// scryfall, sealed) is refused before a search ever runs.
var popularSearchModes = map[string]bool{"": true, "any": true}

// resolvePopularKey runs the query as the search page would and names what
// it found; "" when the mode or shape can't yield a key, it found nothing,
// or the results span more than one card's name.
func resolvePopularKey(ds *datastore, q string) string {
	config := parseSearchOptionsNG(ds.backend, q, nil, nil, nil)
	if !popularSearchModes[config.SearchMode] || !popularKeyShape(config) {
		return ""
	}
	uuids, err := searchAndFilter(ds, config)
	if err != nil || len(uuids) == 0 {
		return ""
	}
	top, err := ds.backend.GetUUID(uuids[0])
	if err != nil {
		return ""
	}
	// A card-name query that spans several names (a widened prefix or
	// substring match) does not vote for whichever name sorts first.
	if config.CleanQuery != "" {
		for _, id := range uuids[1:] {
			co, err := ds.backend.GetUUID(id)
			if err != nil || co.Name != top.Name {
				return ""
			}
		}
	}
	return popularKey(config, GenericCard{Name: top.Name})
}
