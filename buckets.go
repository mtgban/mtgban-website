package main

import (
	"context"

	"github.com/mtgban/simplecloud"
)

// BucketKey is a B2 application key pair scoped to a single bucket, keyed by
// bucket name in Config.BucketKeys.
type BucketKey struct {
	AccessKey    string `json:"access_key"`
	AccessSecret string `json:"access_secret"`
}

// bucketCredentials returns the key pair for the named bucket: the matching
// bucket_keys entry when present, else the datastore pair.
func bucketCredentials(bucketName string) (string, string) {
	if creds, ok := Config.BucketKeys[bucketName]; ok {
		return creds.AccessKey, creds.AccessSecret
	}
	return Config.Datastore.BucketAccessKey, Config.Datastore.BucketSecretKey
}

// newB2ClientFor builds a B2 client for the named bucket with its credentials.
func newB2ClientFor(ctx context.Context, bucketName string) (*simplecloud.B2Bucket, error) {
	key, secret := bucketCredentials(bucketName)
	return simplecloud.NewB2Client(ctx, key, secret, bucketName)
}
