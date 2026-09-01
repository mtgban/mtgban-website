package main

import "testing"

// The config bucket's key pair is in the environment rather than the config
// file, so it can never be a bucket_keys entry — which is why it needs an
// answer of its own, ahead of the datastore fallback.
func TestBucketCredentials(t *testing.T) {
	saved := Config
	t.Cleanup(func() { Config = saved })

	Config.sourcePath = "b2://mtgban-config/pokemon/config.json"
	Config.Datastore.BucketAccessKey = "datastore-key"
	Config.Datastore.BucketSecretKey = "datastore-secret"
	Config.BucketKeys = map[string]BucketKey{
		"mtgban-images": {AccessKey: "images-key", AccessSecret: "images-secret"},
	}
	t.Setenv("BAN_CONFIG_KEY", "config-key")
	t.Setenv("BAN_CONFIG_SECRET", "config-secret")

	tests := []struct {
		name        string
		bucket      string
		key, secret string
	}{
		{"the config bucket, read with the pair the config itself was", "mtgban-config", "config-key", "config-secret"},
		{"a bucket_keys entry wins over both", "mtgban-images", "images-key", "images-secret"},
		{"anything else falls back to the datastore", "mtgban-dumps", "datastore-key", "datastore-secret"},
		{"an empty name is not the config bucket", "", "datastore-key", "datastore-secret"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, secret := bucketCredentials(test.bucket)
			if key != test.key || secret != test.secret {
				t.Errorf("got %q/%q, want %q/%q", key, secret, test.key, test.secret)
			}
		})
	}
}

// A local config path names no bucket, so nothing may match it — otherwise
// every bucket would be "the config bucket" and take the environment's pair.
func TestBucketCredentialsLocalConfig(t *testing.T) {
	saved := Config
	t.Cleanup(func() { Config = saved })

	Config.sourcePath = "config.json"
	Config.BucketKeys = nil
	Config.Datastore.BucketAccessKey = "datastore-key"
	Config.Datastore.BucketSecretKey = "datastore-secret"
	t.Setenv("BAN_CONFIG_KEY", "config-key")
	t.Setenv("BAN_CONFIG_SECRET", "config-secret")

	if name := configBucketName(); name != "" {
		t.Errorf("configBucketName() = %q, want empty for a local path", name)
	}
	key, _ := bucketCredentials("mtgban-config")
	if key != "datastore-key" {
		t.Errorf("got %q, want the datastore key", key)
	}
}
