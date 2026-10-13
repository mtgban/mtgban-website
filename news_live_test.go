package main

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/timeseries"
)

// TestNewspaperReadCostLive measures what each report costs to serve: it reads
// the live editions from the configured newspaper database, read-only, requests
// every page of each report through the handler as JSON and CSV, and prints a
// markdown table of the sums for docs/api-v2-newspaper.md. Skipped unless asked for:
//
//	NEWSPAPER_LIVE=1 NEWSPAPER_LIVE_CONFIG=config.json go test -run TestNewspaperReadCostLive -v
func TestNewspaperReadCostLive(t *testing.T) {
	if os.Getenv("NEWSPAPER_LIVE") != "1" {
		t.Skip("NEWSPAPER_LIVE not set; skipping the live newspaper cost test")
	}
	skipWithoutDatastore(t)
	path := cmp.Or(os.Getenv("NEWSPAPER_LIVE_CONFIG"), "config.json")
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var cfg struct {
		SQLConfig *timeseries.SQLConfig `json:"new_newspaper_sql_config"`
	}
	err = json.Unmarshal(blob, &cfg)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if cfg.SQLConfig == nil {
		t.Fatalf("%s has no new_newspaper_sql_config", path)
	}
	db, err := cfg.SQLConfig.OpenDB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	// One connection, so the read-only setting covers every query below.
	db.SetMaxOpenConns(1)
	_, err = db.Exec("SET default_transaction_read_only = on")
	if err != nil {
		t.Fatal(err)
	}

	withConfigCopy(t)
	Config().Game = DefaultGame
	withSigMode(t, true, false)
	prevDB, prevSkip := NewNewspaperDB, SkipNewspaper
	prevPages, prevUpdate := newspaperPagesPtr.Load(), lastNewspaperUpdatePtr.Load()
	t.Cleanup(func() {
		NewNewspaperDB, SkipNewspaper = prevDB, prevSkip
		newspaperPagesPtr.Store(prevPages)
		lastNewspaperUpdatePtr.Store(prevUpdate)
	})
	NewNewspaperDB, SkipNewspaper = db, false

	// newspaperRow logs a dropped row through LogPages["Newspaper"], nil
	// under tests unless a page logger is set here.
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	savedLogger := LogPages["Newspaper"]
	t.Cleanup(func() { LogPages["Newspaper"] = savedLogger })
	var logged bytes.Buffer
	LogPages["Newspaper"] = log.New(&logged, "", 0)

	b := backend()
	game := gameMap[Config().Game]
	pages := slices.Clone(newspaperPagesInitial)
	dropped := map[string]int{}
	for i := range pages {
		if pages[i].Query == "" || !pages[i].shown() {
			continue
		}
		query := strings.ReplaceAll(pages[i].Query, "__GAME__", game) + " ORDER BY ranking ASC;"
		start := time.Now()
		before := logged.Len()
		results, err := getResults(b, db, query)
		if err != nil {
			t.Fatalf("%s: %v", pages[i].Option, err)
		}
		dropped[pages[i].Option] = strings.Count(logged.String()[before:], "\n")
		t.Logf("%s: %d rows read in %v", pages[i].Option, len(results), time.Since(start).Round(time.Millisecond))
		pages[i].Results = results
		pages[i].AvailableEditions, pages[i].PossibleFinish = newspaperFilterValues(results)
	}
	newspaperPagesPtr.Store(&pages)
	SetLastNewspaperUpdate(time.Now())

	fmt.Println("| report | rows | JSON bytes | JSON gzip | CSV bytes | CSV gzip | JSON ms | CSV ms |")
	fmt.Println("|---|---|---|---|---|---|---|---|")
	for _, page := range newsReports() {
		jsonSize, jsonGzip, jsonTime := newsLiveSum(t, "/api/v2/newspaper/"+page.Option+".json")
		csvSize, csvGzip, csvTime := newsLiveSum(t, "/api/v2/newspaper/"+page.Option+".csv")
		fmt.Printf("| %s | %d | %d | %d | %d | %d | %.1f | %.1f |\n", page.Option, len(page.Results),
			jsonSize, jsonGzip, csvSize, csvGzip,
			float64(jsonTime.Microseconds())/1000, float64(csvTime.Microseconds())/1000)
	}

	fmt.Print("dropped (failed match):")
	for _, page := range newsReports() {
		fmt.Printf(" %s=%d", page.Option, dropped[page.Option])
	}
	fmt.Println()
}

// newsLiveSum requests every page of a report in one format and sums the
// bytes, the gzipped bytes and the handler time; the first page names the count.
func newsLiveSum(t *testing.T, target string) (size, gzipped int, elapsed time.Duration) {
	t.Helper()
	pages := 1
	for n := 1; n <= pages; n++ {
		rec, took := newsLiveGet(t, target+"?page="+strconv.Itoa(n))
		if n == 1 {
			pages = newsLivePages(t, target, rec)
		}
		size += rec.Body.Len()
		gzipped += gzipSize(rec.Body.Bytes())
		elapsed += took
	}
	return size, gzipped, elapsed
}

// newsLivePages reads a first page's page count: X-MTGBAN-Pages on CSV, meta.pages on JSON.
func newsLivePages(t *testing.T, target string, rec *httptest.ResponseRecorder) int {
	t.Helper()
	var pages int
	if h := rec.Header().Get("X-MTGBAN-Pages"); h != "" {
		pages, _ = strconv.Atoi(h)
	} else {
		var out struct {
			Meta struct {
				Pages int `json:"pages"`
			} `json:"meta"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		pages = out.Meta.Pages
	}
	if pages < 1 {
		t.Fatalf("%s: no page count on the first page", target)
	}
	return pages
}

// newsLiveGet serves one request through the handler and times it.
func newsLiveGet(t *testing.T, target string) (*httptest.ResponseRecorder, time.Duration) {
	t.Helper()
	rec := httptest.NewRecorder()
	start := time.Now()
	testSite.NewspaperAPI(rec, httptest.NewRequest(http.MethodGet, target, nil))
	elapsed := time.Since(start)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status %d: %s", target, rec.Code, rec.Body.String())
	}
	return rec, elapsed
}

// gzipSize is a body's size gzipped at the default level.
func gzipSize(body []byte) int {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(body)
	zw.Close()
	return buf.Len()
}
