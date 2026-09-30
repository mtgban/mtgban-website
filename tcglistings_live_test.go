package main

import (
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"

	"github.com/mtgban/mtgban-website/timeseries"
)

// TestTCGListingsLive runs the listings load against the newspaper's real
// tables for Magic and checks three printings against their raw rows: one
// whose listings were all stored, one the under-$1 limit cut short, and a
// valuable foil its bulk nonfoil crowded out. Read-only, and skipped unless
// pointed at a config with a new_newspaper_sql_config:
//
//	LISTINGSLIVE_CONFIG=config.json go test -run TestTCGListingsLive -v
func TestTCGListingsLive(t *testing.T) {
	path := os.Getenv("LISTINGSLIVE_CONFIG")
	if path == "" {
		t.Skip("LISTINGSLIVE_CONFIG not set; skipping the live TCGplayer listings test")
	}
	skipWithoutDatastore(t)
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

	prevDB, prevGame, prevSkip, prevListings := NewNewspaperDB, Config().Game, SkipNewspaper, tcgListingsPtr.Load()
	t.Cleanup(func() {
		NewNewspaperDB, Config().Game, SkipNewspaper = prevDB, prevGame, prevSkip
		tcgListingsPtr.Store(prevListings)
	})
	NewNewspaperDB, Config().Game, SkipNewspaper = db, DefaultGame, false
	tcgListingsPtr.Store(nil)

	start := time.Now()
	testSite.loadTCGListings()
	snap := tcgListingsPtr.Load()
	if snap == nil {
		t.Fatal("no listings loaded")
	}
	t.Logf("loaded %d printings from %s in %v", len(snap.Cards), snap.Date.Format(time.DateOnly), time.Since(start).Round(time.Second))

	var day time.Time
	err = db.QueryRow(tcgListingsDayQuery, gameMap[DefaultGame]).Scan(&day)
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Date.Equal(day) {
		t.Errorf("loaded %v, the newest finished scrape is %v", snap.Date, day)
	}

	b := testSite.backend()
	for _, tc := range []struct {
		productID int64
		printing  string
		capped    bool
	}{
		{4208, "Normal", false},  // Phelddagrif, Alliances
		{631816, "Normal", true}, // Coeurl, Final Fantasy
		{9525, "Foil", true},     // Metamorphic Wurm, Odyssey
	} {
		cardID, err := b.Match(&mtgmatcher.InputCard{
			ID:     strconv.FormatInt(tc.productID, 10),
			Finish: tc.printing,
			Foil:   tc.printing != "Normal",
		})
		if err != nil {
			t.Errorf("%d %s: %v", tc.productID, tc.printing, err)
			continue
		}
		got := snap.Cards[cardID]
		if got == nil {
			t.Errorf("%d %s: not loaded", tc.productID, tc.printing)
			continue
		}

		var want tcgListings
		var stored int
		rows, err := db.Query(`
			SELECT condition, count(DISTINCT seller_id), count(*), sum(quantity), max(direct_inventory)
			  FROM tcgplayersellerproductlistingmodel
			 WHERE product_id = $1 AND date = $2 AND printing = $3
			 GROUP BY 1`, tc.productID, day, tc.printing)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var condition string
			var sellers, listings, copies, direct int
			err := rows.Scan(&condition, &sellers, &listings, &copies, &direct)
			if err != nil {
				t.Fatal(err)
			}
			stored += listings
			grade, found := tcgGradeByName[condition]
			if found {
				want.Sellers[grade], want.Copies[grade], want.Direct[grade] = int32(sellers), int32(copies), int32(direct)
			}
		}
		rows.Close()
		var reported int
		err = db.QueryRow(`SELECT quantity_sellers FROM tcgplayerproductpricesmodel WHERE product_id = $1 AND date = $2 AND variant = $3`,
			tc.productID, day, tc.printing).Scan(&reported)
		if err != nil {
			t.Fatal(err)
		}
		want.Total = int32(stored)
		if reported-stored > tcgListingsSlack {
			want.Capped, want.Total = true, int32(reported)
		}
		if want.Capped != tc.capped {
			t.Logf("%d %s: capped is %v on %s, expected %v when this test was written", tc.productID, tc.printing, want.Capped, day.Format(time.DateOnly), tc.capped)
		}
		if *got != want {
			t.Errorf("%d %s: loaded %+v, raw rows say %+v (stored %d of %d)", tc.productID, tc.printing, *got, want, stored, reported)
		}
	}
}
