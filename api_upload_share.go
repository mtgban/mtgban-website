package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/mtgban/mtgban-website/ratelimit"
	"github.com/mtgban/mtgban-website/userstate"
)

const (
	// uploadShareTTL is how long a shared upload's rows are kept.
	uploadShareTTL = 7 * 24 * time.Hour
	// uploadShareMaxBytes caps the body: the biggest upload packs under a
	// megabyte.
	uploadShareMaxBytes = 2 << 20
	// uploadShareMaxLive caps the unexpired shares one owner holds.
	uploadShareMaxLive = 50
	// uploadShareMissingMsg is what the uploader says for a dead link.
	uploadShareMissingMsg = "This shared upload has expired or does not exist"
)

// uploadShareLimiter throttles shares per email: one share every ten
// seconds, ten in a burst: clicks, not sync traffic.
var uploadShareLimiter = ratelimit.NewLimiter(rate.Every(10*time.Second), 10)

// uploadShareWriter is the one write the share API makes.
type uploadShareWriter interface {
	CreateUploadShare(ctx context.Context, emailHash, game, rows string, buylist bool, ttl time.Duration) (userstate.UploadShare, error)
	CountLiveUploadShares(ctx context.Context, emailHash string) (int, error)
}

// uploadShareStore is the userstate client as a writer, or a nil interface
// without one, so serveUploadShare's nil check holds.
func uploadShareStore() uploadShareWriter {
	if UserStateDB == nil {
		return nil
	}
	return UserStateDB
}

type uploadShareRequest struct {
	Rows    string `json:"rows"`
	Buylist bool   `json:"buylist"`
}

func writeShareJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeShareError(w http.ResponseWriter, status int, msg string) {
	writeShareJSON(w, status, map[string]string{"error": msg})
}

// validateShareRows checks the packed rows the page sends: at least one
// line, no more than the row cap, a card id in every first field and a
// known condition, or none, in every third.
func validateShareRows(rows string) error {
	rows = strings.TrimRight(rows, "\n")
	if rows == "" {
		return errors.New("no rows to share")
	}
	lines := strings.Split(rows, "\n")
	if len(lines) > MaxUploadTotalEntries {
		return fmt.Errorf("more than %d rows", MaxUploadTotalEntries)
	}
	for _, line := range lines {
		fields := strings.SplitN(line, "\t", 4)
		if fields[0] == "" {
			return errors.New("a row has no card id")
		}
		if len(fields) > 2 && !knownShareCondition(fields[2]) {
			return errors.New("a row has an unknown condition")
		}
	}
	return nil
}

// UploadShareAPI stores the rows of a results page under a short-lived
// key: POST /api/upload/share.
func UploadShareAPI(w http.ResponseWriter, r *http.Request) {
	serveUploadShare(w, r, uploadShareStore())
}

func serveUploadShare(w http.ResponseWriter, r *http.Request, store uploadShareWriter) {
	w.Header().Set("Cache-Control", "private, no-store")
	if r.Method != http.MethodPost {
		writeShareError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// The cookie rides cross-site requests; a custom header needs a CORS
	// preflight that another site's page cannot pass.
	if r.Header.Get("X-Requested-With") != "fetch" {
		writeShareError(w, http.StatusForbidden, "same-origin only")
		return
	}
	sig := verifiedRequestSignature(r)
	email := GetParamFromSig(sig, "UserEmail")
	devOpen := DevMode && !SigCheck
	if email == "" && !devOpen {
		writeShareError(w, http.StatusUnauthorized, "not signed in")
		return
	}
	granted, _ := strconv.ParseBool(GetParamFromSig(sig, "Upload"))
	if !granted && !devOpen {
		writeShareError(w, http.StatusForbidden, "upload not granted")
		return
	}
	if !uploadShareLimiter.Allow(email) {
		writeShareError(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	if store == nil {
		writeShareError(w, http.StatusServiceUnavailable, "sharing unavailable")
		return
	}
	var body uploadShareRequest
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, uploadShareMaxBytes)).Decode(&body)
	if err != nil {
		writeShareError(w, http.StatusBadRequest, "bad request")
		return
	}
	if err := validateShareRows(body.Rows); err != nil {
		writeShareError(w, http.StatusBadRequest, err.Error())
		return
	}
	owner := userstate.HashEmail(userStateIdentity(email))
	live, err := store.CountLiveUploadShares(r.Context(), owner)
	if err != nil {
		log.Printf("upload share: count failed for %.10s: %v", owner, err)
		writeShareError(w, http.StatusServiceUnavailable, "sharing unavailable")
		return
	}
	if live >= uploadShareMaxLive {
		writeShareError(w, http.StatusTooManyRequests, "too many shares")
		return
	}
	share, err := store.CreateUploadShare(r.Context(), owner, string(Config().Game), body.Rows, body.Buylist, uploadShareTTL)
	if err != nil {
		log.Printf("upload share: create failed for %.10s: %v", owner, err)
		writeShareError(w, http.StatusServiceUnavailable, "sharing unavailable")
		return
	}
	writeShareJSON(w, http.StatusCreated, map[string]string{
		"key":     share.Key,
		"url":     "/upload?share=" + share.Key,
		"expires": share.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// pruneUploadShares deletes expired shares; nothing to do without a client.
func pruneUploadShares() {
	if UserStateDB == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	n, err := UserStateDB.PruneUploadShares(ctx)
	if err != nil {
		log.Println("upload shares: prune:", err)
		backgroundJobs.Report(jobUploadShares, "", err.Error())
		return
	}
	backgroundJobs.Report(jobUploadShares, fmt.Sprintf("%d pruned", n), "")
}
