package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mtgban/simplecloud"
)

// withConfigCopy publishes a copy of the live config for the test to change,
// and the config before it again when the test ends.
func withConfigCopy(t *testing.T) {
	t.Helper()
	saved := Config()
	config := *saved
	liveConfig.Store(&config)
	t.Cleanup(func() { liveConfig.Store(saved) })
}

// withAPIUserSecret publishes a config in which user holds secret, and the
// config before it again when the test ends.
func withAPIUserSecret(t *testing.T, user, secret string) {
	t.Helper()
	saved := Config()
	config := *saved
	config.APIUserSecrets = maps.Clone(saved.APIUserSecrets)
	if config.APIUserSecrets == nil {
		config.APIUserSecrets = map[string]string{}
	}
	config.APIUserSecrets[user] = secret
	liveConfig.Store(&config)
	t.Cleanup(func() { liveConfig.Store(saved) })
}

// A reload and an editor save each publish a new config while requests read
// the live one: API secrets, as apiGatewaySecret does, and any field, as
// every handler does, with no lock. -race reports a write into a config a
// request can see.
func TestConfigSwapDoesNotRaceReaders(t *testing.T) {
	path := withConfigFile(t)
	writeTestConfig(t, path, `{"api_user_secrets": {"gateway@mtgban.com": "a"}}`)
	err := loadVars("", "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var readers sync.WaitGroup
	defer readers.Wait()
	defer close(stop)
	for range 4 {
		readers.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
					apiGatewaySecret()
					_ = string(Config().Game) + Config().Port
					_ = len(Config().SearchRetailBlockList)
				}
			}
		})
	}

	for range 20 {
		err := reloadConfig()
		if err != nil {
			t.Fatal(err)
		}
		var config ConfigType
		err = json.Unmarshal([]byte(`{"api_user_secrets": {"gateway@mtgban.com": "b"}}`), &config)
		if err != nil {
			t.Fatal(err)
		}
		err = saveConfig(context.Background(), config)
		if err != nil {
			t.Fatal(err)
		}
	}
}

// heldBucket passes the config bucket through, but holds the first write
// opened on it: it closes opened, then waits for release.
type heldBucket struct {
	simplecloud.ReadWriter
	held    atomic.Bool
	opened  chan struct{}
	release chan struct{}
}

func (b *heldBucket) NewWriter(ctx context.Context, path string) (io.WriteCloser, error) {
	if b.held.CompareAndSwap(false, true) {
		close(b.opened)
		<-b.release
	}
	return b.ReadWriter.NewWriter(ctx, path)
}

// duringSave runs first up to its config write, and second while that write
// is held. Unless second waits for first, it finishes in between; if it does
// wait, the hold ends after half a second and second runs after first.
func duringSave(t *testing.T, first, second func() error) {
	t.Helper()
	held := &heldBucket{ReadWriter: ConfigBucket, opened: make(chan struct{}), release: make(chan struct{})}
	ConfigBucket = held

	firstErr := make(chan error, 1)
	go func() { firstErr <- first() }()
	select {
	case <-held.opened:
	case err := <-firstErr:
		t.Fatalf("returned before writing the config: %v", err)
	}

	secondErr := make(chan error, 1)
	go func() { secondErr <- second() }()
	var err error
	select {
	case err = <-secondErr:
		close(held.release)
	case <-time.After(500 * time.Millisecond):
		close(held.release)
		err = <-secondErr
	}
	if err != nil {
		t.Error(err)
	}
	err = <-firstErr
	if err != nil {
		t.Error(err)
	}
}

// savedSecrets reads back the API secrets the config file at path holds.
func savedSecrets(t *testing.T, path string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved ConfigType
	err = json.Unmarshal(data, &saved)
	if err != nil {
		t.Fatal(err)
	}
	return saved.APIUserSecrets
}

// A new key goes into the file, then into Config. A reload inside the key's
// save, or the key inside an editor save, must leave it in both.
func TestNewKeySurvivesAConfigReloadOrSave(t *testing.T) {
	const user = "new@example.com"
	newKey := func() error {
		_, err := generateAPIKey(context.Background(), user, 0)
		return err
	}
	save := func() error {
		var config ConfigType
		err := json.Unmarshal([]byte(`{"api_user_secrets": {"kept@example.com": "a"}}`), &config)
		if err != nil {
			return err
		}
		return saveConfig(context.Background(), config)
	}
	for _, c := range []struct {
		name          string
		first, second func() error
	}{
		{"a reload in the key's save", newKey, reloadConfig},
		{"the key in an editor save", save, newKey},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := withConfigFile(t)
			writeTestConfig(t, path, `{"api_user_secrets": {"kept@example.com": "a"}}`)
			err := loadVars("", "", "", "")
			if err != nil {
				t.Fatal(err)
			}

			duringSave(t, c.first, c.second)

			_, found := Config().APIUserSecrets[user]
			if !found {
				t.Errorf("api_user_secrets %v: the new key is gone", Config().APIUserSecrets)
			}
			saved := savedSecrets(t, path)
			_, found = saved[user]
			if !found {
				t.Errorf("the file's api_user_secrets %v: the new key is gone", saved)
			}
		})
	}
}

// A reload that waits on an editor save keeps the port and paths the save
// set. Kept from before it, they would show in the editor again, and its
// next save would write them back to the file.
func TestConfigReloadKeepsTheSavedPortAndPaths(t *testing.T) {
	path := withConfigFile(t)
	writeTestConfig(t, path, `{"port": "8080", "datastore_path": "old.json.xz"}`)
	err := loadVars("", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	save := func() error {
		var config ConfigType
		err := json.Unmarshal([]byte(`{"port": "8081", "datastore_path": "new.json.xz"}`), &config)
		if err != nil {
			return err
		}
		return saveConfig(context.Background(), config)
	}

	duringSave(t, save, reloadConfig)

	if Config().Port != "8081" || Config().DatastorePath != "new.json.xz" {
		t.Errorf("port %q, datastore path %q, want the saved 8081 and new.json.xz", Config().Port, Config().DatastorePath)
	}
}

// Two keys generated at once: each save encodes the secrets map, which the
// other key's write must not change under it, and the file keeps both.
func TestNewKeysAtOnceDoNotRace(t *testing.T) {
	path := withConfigFile(t)
	writeTestConfig(t, path, `{"api_user_secrets": {"kept@example.com": "a"}}`)
	err := loadVars("", "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	var admins sync.WaitGroup
	for i := range 2 {
		admins.Go(func() {
			for j := range 20 {
				_, err := generateAPIKey(context.Background(), fmt.Sprintf("admin%d-%d@example.com", i, j), 0)
				if err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	admins.Wait()

	saved := savedSecrets(t, path)
	if len(saved) != 41 || !maps.Equal(saved, Config().APIUserSecrets) {
		t.Errorf("%d secrets in the file, %d in Config, want the same 41", len(saved), len(Config().APIUserSecrets))
	}
}

// panicCloseBucket takes whatever is written and panics at Close.
type panicCloseBucket struct{ simplecloud.ReadWriter }

type panicCloseWriter struct{ failCloseWriter }

func (panicCloseWriter) Close() error { panic("upload failed at close") }

func (panicCloseBucket) NewWriter(context.Context, string) (io.WriteCloser, error) {
	return panicCloseWriter{}, nil
}

// A key whose save fails, by an error at Close or by a panic there, must be
// neither handed out nor kept: live but unsaved, it would verify only until
// the next reload, and the next request for the same user would find it and
// return a link with nothing saved.
func TestNewKeyWhoseSaveFailsIsNotKept(t *testing.T) {
	// newKey takes a panic for the error it stands for.
	newKey := func() (link string, err error) {
		defer func() {
			r := recover()
			if r != nil {
				err = fmt.Errorf("panic: %v", r)
			}
		}()
		return generateAPIKey(context.Background(), "new@example.com", 0)
	}
	for _, c := range []struct {
		name   string
		bucket simplecloud.ReadWriter
	}{
		{"an error at Close", failCloseBucket{}},
		{"a panic at Close", panicCloseBucket{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := withConfigFile(t)
			writeTestConfig(t, path, `{"api_user_secrets": {"kept@example.com": "a"}}`)
			err := loadVars("", "", "", "")
			if err != nil {
				t.Fatal(err)
			}
			ConfigBucket = c.bucket

			for range 2 {
				link, err := newKey()
				if err == nil || link != "" {
					t.Errorf("link %q, error %v: a key that was not saved was handed out", link, err)
				}
			}
			_, found := Config().APIUserSecrets["new@example.com"]
			if found {
				t.Error("the key that was not saved is live")
			}
			if !configMu.TryLock() {
				t.Fatal("configMu is still held")
			}
			configMu.Unlock()
		})
	}
}

// Every admin page view lists the API users and encodes the whole config for
// its editor, both from the secrets map a new key replaces.
func TestAdminPageDoesNotRaceNewKeys(t *testing.T) {
	path := withConfigFile(t)
	writeTestConfig(t, path, `{"api_user_secrets": {"kept@example.com": "a"}}`)
	err := loadVars("", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	// Render the page from disk, as the other admin tests do.
	withSigMode(t, true, false)

	stop := make(chan struct{})
	var admin sync.WaitGroup
	defer admin.Wait()
	defer close(stop)
	admin.Go(func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
				_, err := generateAPIKey(context.Background(), fmt.Sprintf("user%d@example.com", i), 0)
				if err != nil {
					t.Error(err)
					return
				}
			}
		}
	})
	for range 5 {
		rec := httptest.NewRecorder()
		testSite.Admin(rec, httptest.NewRequest(http.MethodGet, "/admin", nil))
		if rec.Code != http.StatusOK {
			t.Errorf("status %d", rec.Code)
			break
		}
	}
}

// stuckReadBucket holds the config's reads until release closes, as a bucket
// that stops answering does; entered closes on the first.
type stuckReadBucket struct {
	simplecloud.ReadWriter
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (b *stuckReadBucket) NewReader(ctx context.Context, path string) (io.ReadCloser, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return b.ReadWriter.NewReader(ctx, path)
}

// A reload holds configMu across its read of the config file, for up to
// configFileTimeout. The admin page reads the live config without taking
// it, so it still renders while that read hangs.
func TestAdminPageRendersWhileAConfigReadHangs(t *testing.T) {
	path := withConfigFile(t)
	writeTestConfig(t, path, `{"api_user_secrets": {"kept@example.com": "a"}}`)
	err := loadVars("", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	withSigMode(t, true, false)

	stuck := &stuckReadBucket{ReadWriter: ConfigBucket, entered: make(chan struct{}), release: make(chan struct{})}
	ConfigBucket = stuck
	reloaded := make(chan error, 1)
	go func() { reloaded <- reloadConfig() }()
	<-stuck.entered

	var render sync.WaitGroup
	rendered := make(chan int, 1)
	render.Go(func() {
		rec := httptest.NewRecorder()
		testSite.Admin(rec, httptest.NewRequest(http.MethodGet, "/admin", nil))
		rendered <- rec.Code
	})
	select {
	case code := <-rendered:
		if code != http.StatusOK {
			t.Errorf("status %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Error("the admin page still waits on the config read after 5s")
	}
	close(stuck.release)
	err = <-reloaded
	if err != nil {
		t.Error(err)
	}
	render.Wait()
}

// hungBucket opens the config file at once, but a read, or the Close that
// finishes a write, answers only once the context it was opened with is
// done, as B2's do when the bucket stops answering.
type hungBucket struct{}

func (hungBucket) NewReader(ctx context.Context, _ string) (io.ReadCloser, error) {
	return hungFile{ctx}, nil
}

func (hungBucket) NewWriter(ctx context.Context, _ string) (io.WriteCloser, error) {
	return hungFile{ctx}, nil
}

// hungFile is the config file as hungBucket opens it.
type hungFile struct{ ctx context.Context }

func (f hungFile) Read([]byte) (int, error) {
	<-f.ctx.Done()
	return 0, f.ctx.Err()
}

func (hungFile) Write(p []byte) (int, error) { return len(p), nil }

func (f hungFile) Close() error {
	<-f.ctx.Done()
	return f.ctx.Err()
}

// A reload or an editor save gives up on a bucket that stops answering after
// configFileTimeout, and leaves configMu to the next: synctest's fake clock
// runs the timeout at once.
func TestConfigFileIOGivesUp(t *testing.T) {
	for _, c := range []struct {
		name   string
		change func() error
	}{
		{"a reload", reloadConfig},
		{"an editor save", func() error { return saveConfig(context.Background(), ConfigType{}) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				withConfigFile(t)
				ConfigBucket = hungBucket{}

				err := c.change()
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Errorf("error %v, want the deadline's", err)
				}
				if !configMu.TryLock() {
					t.Fatal("configMu is still held")
				}
				configMu.Unlock()
			})
		})
	}
}
