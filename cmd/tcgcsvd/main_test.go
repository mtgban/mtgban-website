package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	err := os.WriteFile(path, []byte(body), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// sql_config comes from the infrastructure file the config names, unless the
// config sets its own.
func TestLoadConfigReadsTheInfrastructureFile(t *testing.T) {
	dir := t.TempDir()
	infra := writeFile(t, dir, "infrastructure.json", `{"sql_config": {"dbname": "file_prices"}}`)
	games := `"tcgcsv_config": {"games": [{"category": 1}]}`

	path := writeFile(t, dir, "config.json", `{"infrastructure_path": "`+infra+`", `+games+`}`)
	cfg, err := loadConfig(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SQLConfig.DBName != "file_prices" {
		t.Errorf("sql_config %+v, want the infrastructure file's", cfg.SQLConfig)
	}

	path = writeFile(t, dir, "own.json", `{"infrastructure_path": "`+infra+`", "sql_config": {"dbname": "own_prices"}, `+games+`}`)
	cfg, err = loadConfig(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SQLConfig.DBName != "own_prices" {
		t.Errorf("sql_config %+v, want the config's own", cfg.SQLConfig)
	}
}

func TestStaleGames(t *testing.T) {
	now := time.Date(2026, 11, 26, 21, 20, 0, 0, time.UTC)
	day := func(d int) time.Time { return time.Date(2026, 11, d, 0, 0, 0, 0, time.UTC) }
	rows := []gameRow{
		{Name: "Pokemon", CategoryID: 3, Latest: day(25), Stored: true},         // 45h20m
		{Name: "Disney Lorcana", CategoryID: 71, Latest: day(24), Stored: true}, // 69h20m
		{Name: "Gundam Card Game", CategoryID: 86},                              // nothing stored
	}
	got := staleGames(rows, now, 50*time.Hour)
	want := []string{"Disney Lorcana (71): 2026-11-24", "Gundam Card Game (86): none"}
	if !slices.Equal(got, want) {
		t.Errorf("staleGames = %q, want %q", got, want)
	}
	if got := staleGames(rows, now, 0); len(got) != 0 {
		t.Errorf("staleAfter 0 = %q, want none", got)
	}
}
