package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/mtgban/mtgban-website/internal/infrastructure"
	"github.com/mtgban/mtgban-website/timeseries"
)

// withInfrastructureConfig points the config's infrastructure path at the
// given value for one test, restoring the config and the published file
// after.
func withInfrastructureConfig(t *testing.T, path string) {
	t.Helper()
	withConfigCopy(t)
	savedValue := infrastructurePtr.Load()
	t.Cleanup(func() { infrastructurePtr.Store(savedValue) })
	Config().InfrastructurePath = path
	Config().Config = infrastructure.Config{}
}

func writeInfrastructureFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "infrastructure.json")
	err := os.WriteFile(path, []byte(body), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// Infrastructure reads the infrastructure_path file, with the keys the
// config sets in place of the file's.
func TestInfrastructureReadsThePath(t *testing.T) {
	path := writeInfrastructureFile(t, `{
		"google_credentials": "file.json",
		"observability_config": {"dbname": "file_obs"}
	}`)
	withInfrastructureConfig(t, path)
	Config().ObservabilityConfig = &timeseries.SQLConfig{DBName: "own_obs"}

	err := loadInfrastructure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	infra := Infrastructure()
	if infra.GoogleCredentials != "file.json" {
		t.Errorf("google credentials %q, want the file's", infra.GoogleCredentials)
	}
	if infra.ObservabilityConfig.DBName != "own_obs" {
		t.Errorf("observability db %q, want the config's own", infra.ObservabilityConfig.DBName)
	}
}

// With no path configured the infrastructure is the config's own.
func TestInfrastructureWithoutAPathIsTheConfigs(t *testing.T) {
	withInfrastructureConfig(t, "")
	Config().GoogleCredentials = "own.json"

	err := loadInfrastructure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if Infrastructure().GoogleCredentials != "own.json" {
		t.Errorf("google credentials %q, want the config's own", Infrastructure().GoogleCredentials)
	}
}

// A configured path that cannot be read is an error, and the previously
// published file survives the failed reload.
func TestLoadInfrastructureKeepsTheValueOnError(t *testing.T) {
	path := writeInfrastructureFile(t, `{"google_credentials": "kept.json"}`)
	withInfrastructureConfig(t, path)
	err := loadInfrastructure(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	Config().InfrastructurePath = filepath.Join(t.TempDir(), "nope.json")
	err = loadInfrastructure(context.Background())
	if err == nil {
		t.Fatal("missing infrastructure path did not error")
	}
	if Infrastructure().GoogleCredentials != "kept.json" {
		t.Errorf("failed reload dropped the file: %+v", Infrastructure())
	}
}
