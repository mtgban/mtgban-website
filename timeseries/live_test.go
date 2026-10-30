package timeseries

import (
	"os"
	"strconv"
	"testing"
)

// liveConfig reads the live tests' database from the environment and skips
// the test when it is unset, so ordinary `go test` and CI never touch one.
//
// Run the live tests with, e.g.:
//
//	TCGLIVE_HOST=... TCGLIVE_PORT=5432 TCGLIVE_USER=... TCGLIVE_PASSWORD=... \
//	TCGLIVE_DBNAME=card_prices TCGLIVE_SSLMODE=require \
//	go test ./timeseries/ -run Live -v
//
// Cases that create or drop partitions run only with TCGLIVE_SCRATCH=1, which
// marks the database as a scratch one; without it they log that they skipped.
func liveConfig(t *testing.T) SQLConfig {
	t.Helper()
	host := os.Getenv("TCGLIVE_HOST")
	if host == "" {
		t.Skip("TCGLIVE_HOST not set; skipping live DB integration test")
	}
	port, _ := strconv.Atoi(os.Getenv("TCGLIVE_PORT"))
	if port == 0 {
		port = 5432
	}
	return SQLConfig{
		Host:     host,
		Port:     port,
		User:     os.Getenv("TCGLIVE_USER"),
		Password: os.Getenv("TCGLIVE_PASSWORD"),
		DBName:   os.Getenv("TCGLIVE_DBNAME"),
		SSLMode:  os.Getenv("TCGLIVE_SSLMODE"),
	}
}
