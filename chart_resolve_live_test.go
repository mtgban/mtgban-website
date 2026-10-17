package main

import (
	"context"
	"os"
	"slices"
	"strconv"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"

	"github.com/mtgban/mtgban-website/timeseries"
)

// The variants this test files: a language no Magic variant carries, and a
// TCGplayer category past every real one, so deleting them touches nothing
// else.
const (
	liveSentinelLanguage = "Sentinel"
	liveSentinelCategory = 8191
)

// A ban: id is resolved through the archive's variants table, so its label is
// checked against an archive: skipped unless TCGLIVE_HOST names one, like the
// timeseries live tests. It files sentinel variants and deletes them.
//
//	TCGLIVE_HOST=... TCGLIVE_PORT=... TCGLIVE_USER=... TCGLIVE_DBNAME=... \
//	ONEPIECE_PATH=... go test -run TestTargetFromBanIDLabelsThePrinting -v
func TestTargetFromBanIDLabelsThePrinting(t *testing.T) {
	cfg := liveArchiveConfig(t)
	client, err := timeseries.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	db, err := cfg.OpenDB()
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	prev := PricesArchiveDB
	t.Cleanup(func() { PricesArchiveDB = prev })
	PricesArchiveDB = client
	ctx := context.Background()

	t.Run("magic", func(t *testing.T) {
		skipWithoutDatastore(t)
		b := backend()
		uuid, foilID := foilPrintingOfOneCard(t, b)
		t.Cleanup(func() {
			_, err := db.ExecContext(ctx, `DELETE FROM variants WHERE mtgjson_uuid=$1 AND language=$2`, uuid, liveSentinelLanguage)
			if err != nil {
				t.Errorf("cleanup: %v", err)
			}
		})
		banID, err := client.ResolveMagicBanID(ctx, timeseries.MagicVariant{
			MtgjsonUUID: uuid, IsFoil: true, Language: liveSentinelLanguage,
		})
		if err != nil {
			t.Fatalf("ResolveMagicBanID: %v", err)
		}

		target, err := targetFromBanID(ctx, b, banID)
		if err != nil {
			t.Fatalf("targetFromBanID(%d): %v", banID, err)
		}
		co, err := b.GetUUID(foilID)
		if err != nil {
			t.Fatal(err)
		}
		if target.Label != co.String() || target.Name != co.Name || target.SearchID != foilID {
			t.Errorf("label/name/search id = %q/%q/%q, want %q/%q/%q",
				target.Label, target.Name, target.SearchID, co.String(), co.Name, foilID)
		}
	})

	t.Run("onepiece", func(t *testing.T) {
		b := openGameDatastore(t, "onepiece")
		pid, searchID := plainProduct(t, b)
		t.Cleanup(func() {
			_, err := db.ExecContext(ctx, `DELETE FROM variants WHERE tcgp_category_id=$1`, liveSentinelCategory)
			if err != nil {
				t.Errorf("cleanup: %v", err)
			}
		})
		banID, err := client.ResolveTCGBanID(ctx, timeseries.TCGVariant{
			CategoryID: liveSentinelCategory, ProductID: pid, SubType: "Normal",
		})
		if err != nil {
			t.Fatalf("ResolveTCGBanID: %v", err)
		}

		target, err := targetFromBanID(ctx, b, banID)
		if err != nil {
			t.Fatalf("targetFromBanID(%d): %v", banID, err)
		}
		co, err := b.GetUUID(searchID)
		if err != nil {
			t.Fatal(err)
		}
		if target.Label != co.String() || target.SearchID != searchID || target.BanID != banID {
			t.Errorf("label/search id/ban id = %q/%q/%d, want %q/%q/%d",
				target.Label, target.SearchID, target.BanID, co.String(), searchID, banID)
		}
	})
}

// liveArchiveConfig is the archive the TCGLIVE_* variables name, as the
// timeseries live tests read them, and skips the test when none is named.
func liveArchiveConfig(t *testing.T) timeseries.SQLConfig {
	t.Helper()
	host := os.Getenv("TCGLIVE_HOST")
	if host == "" {
		t.Skip("TCGLIVE_HOST not set; skipping live archive test")
	}
	port, _ := strconv.Atoi(os.Getenv("TCGLIVE_PORT"))
	if port == 0 {
		port = 5432
	}
	return timeseries.SQLConfig{
		Host:     host,
		Port:     port,
		User:     os.Getenv("TCGLIVE_USER"),
		Password: os.Getenv("TCGLIVE_PASSWORD"),
		DBName:   os.Getenv("TCGLIVE_DBNAME"),
		SSLMode:  os.Getenv("TCGLIVE_SSLMODE"),
	}
}

// foilPrintingOfOneCard finds a Magic printing whose foil has an id of its
// own: the printing's uuid and its foil's id.
func foilPrintingOfOneCard(t *testing.T, b *mtgmatcher.Backend) (string, string) {
	t.Helper()
	for _, uuid := range slices.Sorted(slices.Values(b.GetUUIDs())) {
		co, err := b.GetUUID(uuid)
		if err != nil || co.Sealed || co.Foil || co.Etched {
			continue
		}
		foilID := magicFinishSearchID(b, uuid, true, false)
		if foilID != uuid {
			return uuid, foilID
		}
	}
	t.Skip("no printing with a foil of its own")
	return "", ""
}

// plainProduct finds a TCGplayer product sold plain, and the id of the
// printing it is sold as.
func plainProduct(t *testing.T, b *mtgmatcher.Backend) (int, string) {
	t.Helper()
	for _, uuid := range slices.Sorted(slices.Values(b.GetUUIDs())) {
		co, err := b.GetUUID(uuid)
		if err != nil || co.Sealed {
			continue
		}
		pid, ok := tcgProductID(co)
		if !ok {
			continue
		}
		searchID := tcgFinishID(b, pid, "Normal")
		if searchID != "" {
			return pid, searchID
		}
	}
	t.Skip("no product sold plain")
	return 0, ""
}
