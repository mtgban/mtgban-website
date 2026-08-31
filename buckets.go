package main

import (
	"context"
	"io"

	"github.com/hashicorp/go-cleanhttp"
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

// bucketConcurrentReads is how many parallel range requests a B2 read uses.
// It is sized for the datastore, much the largest thing read this way; blazer
// only splits an object big enough to be worth splitting, so a small file
// costs nothing for it.
const bucketConcurrentReads = 20

// bucketResolver gives simplecloud.Open a B2 bucket built with the key pair
// this deployment holds for that bucket name, and leaves every other scheme to
// Open's own backends.
//
// A resolver rather than a WithB2Credentials pair because the credentials are
// chosen by bucket name, and nothing knows the bucket until Open has parsed
// the path - which is the whole point of handing it the path.
func bucketResolver(ctx context.Context, scheme, host string) (simplecloud.Reader, error) {
	if scheme != "b2" {
		return nil, nil
	}
	bucket, err := newB2ClientFor(ctx, host)
	if err != nil {
		return nil, err
	}
	bucket.ConcurrentDownloads = bucketConcurrentReads
	return bucket, nil
}

// openBucketPath opens a path for reading, whatever it names: a local file, a
// bucket URL, an https one. The scheme picks the backend, so a caller needs
// neither a bucket of its own nor an opinion about which one - it hands over
// the path it was configured with and reads what comes back.
func openBucketPath(ctx context.Context, path string) (io.ReadCloser, error) {
	return simplecloud.Open(ctx, path,
		simplecloud.WithResolver(bucketResolver),
		simplecloud.WithHTTPClient(cleanhttp.DefaultClient()))
}
