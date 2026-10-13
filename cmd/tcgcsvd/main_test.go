package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
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
