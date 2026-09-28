package main

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
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
