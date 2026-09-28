package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mtgban/simplecloud"
)

// A reload and an editor save each swap Config whole while API requests look
// their secrets up, as apiGatewaySecret does, under apiUsersMutex. Unless the
// swap takes it too, -race reports the two.
func TestConfigSwapDoesNotRaceSecretLookups(t *testing.T) {
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

// A new key goes into Config, then into the file. A reload landing between
// the two replaced Config without it, and the key's save wrote that out; a
// key landing inside an editor save was overwritten in both by the save.
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

			_, found := Config.APIUserSecrets[user]
			if !found {
				t.Errorf("api_user_secrets %v: the new key is gone", Config.APIUserSecrets)
			}
			saved := savedSecrets(t, path)
			_, found = saved[user]
			if !found {
				t.Errorf("the file's api_user_secrets %v: the new key is gone", saved)
			}
		})
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
	if len(saved) != 41 || !maps.Equal(saved, Config.APIUserSecrets) {
		t.Errorf("%d secrets in the file, %d in Config, want the same 41", len(saved), len(Config.APIUserSecrets))
	}
}

// A key whose save fails, at Close included, must be neither handed out nor
// kept: live but unsaved, it verified only until the next reload, and a
// second request for the same user found it and returned a link unsaved.
func TestNewKeyWhoseSaveFailsIsNotKept(t *testing.T) {
	path := withConfigFile(t)
	writeTestConfig(t, path, `{"api_user_secrets": {"kept@example.com": "a"}}`)
	err := loadVars("", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	ConfigBucket = failCloseBucket{ConfigBucket}

	for range 2 {
		link, err := generateAPIKey(context.Background(), "new@example.com", 0)
		if err == nil || link != "" {
			t.Errorf("link %q, error %v: a key that was not saved was handed out", link, err)
		}
	}
	_, found := Config.APIUserSecrets["new@example.com"]
	if found {
		t.Error("the key that was not saved is live")
	}
}
