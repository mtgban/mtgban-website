package main

import (
	"testing"

	"github.com/mtgban/mtgban-website/internal/infrastructure"
)

// The config bucket's key pair is in the environment rather than a file, so a
// bucket_keys entry for it is ignored. A bucket with neither gets no pair.
func TestBucketCredentials(t *testing.T) {
	withConfigCopy(t)

	Config().sourcePath = "b2://mtgban-config/pokemon/config.json"
	Config().BucketKeys = map[string]infrastructure.BucketKey{
		"mtgban-images": {AccessKey: "images-key", AccessSecret: "images-secret"},
		"mtgban-config": {AccessKey: "stale-key", AccessSecret: "stale-secret"},
	}
	t.Setenv("BAN_CONFIG_KEY", "config-key")
	t.Setenv("BAN_CONFIG_SECRET", "config-secret")

	tests := []struct {
		name        string
		bucket      string
		key, secret string
	}{
		{"the config bucket, read with the pair the config itself was", "mtgban-config", "config-key", "config-secret"},
		{"another bucket, read with its bucket_keys entry", "mtgban-images", "images-key", "images-secret"},
		{"anything else gets no pair", "mtgban-dumps", "", ""},
		{"an empty name is not the config bucket", "", "", ""},
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
	withConfigCopy(t)

	Config().sourcePath = "config.json"
	Config().BucketKeys = nil
	t.Setenv("BAN_CONFIG_KEY", "config-key")
	t.Setenv("BAN_CONFIG_SECRET", "config-secret")

	if name := configBucketName(); name != "" {
		t.Errorf("configBucketName() = %q, want empty for a local path", name)
	}
	key, _ := bucketCredentials("mtgban-config")
	if key != "" {
		t.Errorf("got %q, want no key", key)
	}
}
