package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

// With no path configured a save refuses rather than reaching for a path that
// names no file.
func TestNoInfrastructurePathRefusesSave(t *testing.T) {
	withInfrastructureConfig(t, "")
	err := saveInfrastructure(context.Background(), infrastructure.Config{GoogleCredentials: "saved.json"})
	if err == nil {
		t.Error("save with no infrastructure path did not error")
	}
}

// A save writes the file and publishes it. (The peer notification is a no-op
// here: tests run without a price DB.)
func TestSaveInfrastructureWritesThePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "infrastructure.json")
	withInfrastructureConfig(t, path)

	err := saveInfrastructure(context.Background(), infrastructure.Config{GoogleCredentials: "saved.json"})
	if err != nil {
		t.Fatal(err)
	}
	if Infrastructure().GoogleCredentials != "saved.json" {
		t.Errorf("published file is not the saved one: %+v", Infrastructure())
	}

	infrastructurePtr.Store(nil)
	err = loadInfrastructure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if Infrastructure().GoogleCredentials != "saved.json" {
		t.Errorf("file holds %+v, want the saved value", infrastructureFile())
	}
}

// The Infrastructure tab offers Update, and an editable editor, only when
// there is a file to save to, and shows the file alone, not the keys this
// deployment's config overrides.
func TestAdminInfrastructureEditor(t *testing.T) {
	pv := PageVars{UserNav: &NavElem{Short: "b"}, AdminVars: AdminVars{ACLText: "{}"}}
	const update = `data-update-for="infrastructure"`
	readOnly := regexp.MustCompile(`formId: "infrastructureForm", readOnly:\s*true\s*}`)
	editable := regexp.MustCompile(`formId: "infrastructureForm", readOnly:\s*false\s*}`)

	withInfrastructureConfig(t, "")
	out := renderPage(t, "admin.html", false, pv)
	if strings.Contains(out, update) {
		t.Error("Update offered with no infrastructure path")
	}
	if !readOnly.MatchString(out) {
		t.Error("editor is editable with no infrastructure path")
	}

	path := writeInfrastructureFile(t, `{"google_credentials": "file.json"}`)
	Config().InfrastructurePath = path
	Config().GoogleCredentials = "own.json"
	err := loadInfrastructure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out = renderPage(t, "admin.html", false, pv)
	if !strings.Contains(out, update) {
		t.Error("Update not offered with an infrastructure path")
	}
	if !editable.MatchString(out) {
		t.Error("editor is read-only with an infrastructure path")
	}
	if !strings.Contains(out, "file.json") || strings.Contains(out, "own.json") {
		t.Error("the editor does not show the file alone")
	}
}

// postInfrastructureEditor posts body to the Infrastructure tab's editor and
// returns the page it fills.
func postInfrastructureEditor(body string) PageVars {
	form := url.Values{"infrastructureTextArea": {body}}
	r := httptest.NewRequest(http.MethodPost, "/admin?page=infrastructure", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var pv PageVars
	adminInfrastructureEditor(r, &pv)
	return pv
}

// The editor refuses an unknown key without writing anything, and saves and
// publishes a valid file.
func TestAdminInfrastructureEditorSaves(t *testing.T) {
	path := filepath.Join(t.TempDir(), "infrastructure.json")
	withInfrastructureConfig(t, path)

	pv := postInfrastructureEditor(`{"bucket_key": {}}`)
	if pv.WarningMessage == "" {
		t.Error("an unknown key was not refused")
	}
	_, err := os.Stat(path)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused save touched the file: %v", err)
	}

	pv = postInfrastructureEditor(`{"google_credentials": "saved.json"}`)
	if pv.InfoMessage == "" || pv.WarningMessage != "" {
		t.Errorf("a valid save reported %q / %q", pv.InfoMessage, pv.WarningMessage)
	}
	if infrastructureFile().GoogleCredentials != "saved.json" {
		t.Errorf("published file %+v, want the saved one", infrastructureFile())
	}
}
