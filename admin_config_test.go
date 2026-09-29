package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mtgban/simplecloud"
)

// saveConfigText submits text through the admin page's config editor.
func saveConfigText(text string) {
	form := url.Values{"textArea": {text}}
	req := httptest.NewRequest(http.MethodPost, "/admin", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	testSite.Admin(httptest.NewRecorder(), req)
}

// A config saved in the admin editor gets the defaults and a registry built
// from its datasets, as a reload does, but no overrides: its port and paths
// are the text's. Deleting "game" used to leave it empty, which panics the
// next newspaper refresh.
func TestAdminConfigSaveGetsDefaultsAndRegistry(t *testing.T) {
	path := withConfigFile(t)
	writeTestConfig(t, path, `{}`)
	err := loadVars("8081", "", "flag-acl.json", "flag-grants.json")
	if err != nil {
		t.Fatal(err)
	}
	// Render the page from disk, as the other admin tests do.
	withSigMode(t, true, false)

	// Nothing is at these, so the access files the save reloads fail to load
	// and the published ones stay.
	aclPath := filepath.Join(filepath.Dir(path), "acl.json")
	grantsPath := filepath.Join(filepath.Dir(path), "grants.json")
	saveConfigText(fmt.Sprintf(`{
		"port": "9000",
		"datastore_path": "saved.json.xz",
		"acl_path": %q,
		"patreon_grants_path": %q,
		"timeseries_config": {"datasets": [{"public_name": "TCGplayer Low", "provider": 1}]}
	}`, aclPath, grantsPath))

	if len(Config.TimeseriesConfig.Datasets) != 1 {
		t.Fatalf("datasets %+v: the save did not take", Config.TimeseriesConfig.Datasets)
	}
	for _, c := range []struct{ name, got, want string }{
		{"game, which the text left out", Config.Game, DefaultGame},
		{"default gateway", Config.APIGateway.URL, DefaultAPIGatewayURL},
		{"source path", Config.sourcePath, path},
		{"the text's port", Config.Port, "9000"},
		{"the text's datastore path", Config.DatastorePath, "saved.json.xz"},
		{"the text's acl path", Config.ACLPath, aclPath},
		{"the text's grants path", Config.PatreonGrantsPath, grantsPath},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
	if len(providerRegistry) != 1 {
		t.Errorf("registry %+v, want the saved dataset", providerRegistry)
	}

	// A text with an empty game and no port gets the defaults, not "" and
	// not the port that was live.
	saveConfigText(`{"game": ""}`)
	if Config.Game != DefaultGame || Config.Port != DefaultServerPort {
		t.Errorf("game %q, port %q, want %q and %q", Config.Game, Config.Port, DefaultGame, DefaultServerPort)
	}
}

// failCloseBucket takes whatever is written and fails at Close, as a B2
// upload that does not finalise does.
type failCloseBucket struct{ simplecloud.ReadWriter }

type failCloseWriter struct{}

func (failCloseWriter) Write(p []byte) (int, error) { return len(p), nil }
func (failCloseWriter) Close() error                { return errors.New("upload failed at close") }

func (failCloseBucket) NewWriter(context.Context, string) (io.WriteCloser, error) {
	return failCloseWriter{}, nil
}

// A save whose upload fails at Close has not happened: it must report the
// failure and leave the live config alone, not publish what the file never
// got while the editor says "Config updated".
func TestAdminConfigSaveFailingAtCloseChangesNothing(t *testing.T) {
	path := withConfigFile(t)
	writeTestConfig(t, path, `{"game": "lorcana"}`)
	err := loadVars("", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	ConfigBucket = failCloseBucket{ConfigBucket}

	var config ConfigType
	err = json.Unmarshal([]byte(`{"game": "onepiece"}`), &config)
	if err != nil {
		t.Fatal(err)
	}
	err = saveConfig(context.Background(), config)
	if err == nil || Config.Game != "lorcana" {
		t.Errorf("error %v, game %q: a save that failed at Close went live", err, Config.Game)
	}
}

var errWriteFailed = errors.New("upload failed at write")

// failWriteBucket opens every write on writer.
type failWriteBucket struct {
	simplecloud.ReadWriter
	writer *failWriteWriter
}

func (b failWriteBucket) NewWriter(context.Context, string) (io.WriteCloser, error) {
	return b.writer, nil
}

// failWriteWriter fails every write, and records whether the save then
// closed it, which commits what was written, or aborted it.
type failWriteWriter struct{ closed, aborted bool }

func (*failWriteWriter) Write([]byte) (int, error) { return 0, errWriteFailed }

func (w *failWriteWriter) Close() error {
	w.closed = true
	return nil
}

func (w *failWriteWriter) Abort() error {
	w.aborted = true
	return nil
}

// A save whose write fails must abort the upload, not close it: Close would
// commit a truncated config, which the next start cannot parse.
func TestAdminConfigSaveFailingAtWriteAborts(t *testing.T) {
	path := withConfigFile(t)
	writeTestConfig(t, path, `{"game": "lorcana"}`)
	err := loadVars("", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	writer := &failWriteWriter{}
	ConfigBucket = failWriteBucket{ConfigBucket, writer}

	err = saveConfig(context.Background(), ConfigType{Game: "onepiece"})
	if !errors.Is(err, errWriteFailed) || Config.Game != "lorcana" {
		t.Errorf("error %v, game %q: a save that failed at its write went live", err, Config.Game)
	}
	if !writer.aborted || writer.closed {
		t.Errorf("aborted %t, closed %t: a failed write must be aborted, never closed", writer.aborted, writer.closed)
	}
}
