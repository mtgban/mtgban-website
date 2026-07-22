package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"

	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/mtgban/simplecloud"
)

// workerConfig is the minimal slice of the website config.json this binary
// needs; field names match main.go's ConfigType.
type workerConfig struct {
	DatastorePath string `json:"datastore_path"`
	Datastore     struct {
		BucketAccessKey string `json:"bucket_access_key"`
		BucketSecretKey string `json:"bucket_access_secret"`
	} `json:"datastore"`
	Offline struct {
		ImagesPath string `json:"images_path"`
	} `json:"offline"`
	BucketKeys map[string]struct {
		AccessKey    string `json:"access_key"`
		AccessSecret string `json:"access_secret"`
	} `json:"bucket_keys"`
}

// bucketCredentials returns the key pair for the named bucket: the matching
// bucket_keys entry when present, else the datastore pair.
func (cfg *workerConfig) bucketCredentials(bucketName string) (string, string) {
	if creds, ok := cfg.BucketKeys[bucketName]; ok {
		return creds.AccessKey, creds.AccessSecret
	}
	return cfg.Datastore.BucketAccessKey, cfg.Datastore.BucketSecretKey
}

func loadWorkerConfig(path string) (*workerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg workerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.DatastorePath == "" {
		return nil, errors.New("datastore_path not configured")
	}
	if cfg.Offline.ImagesPath == "" {
		return nil, errors.New("offline.images_path not configured")
	}
	if u, err := url.Parse(cfg.Offline.ImagesPath); err == nil && len(u.Scheme) == 1 {
		return nil, errors.New("offline.images_path: Windows absolute paths are broken by simplecloud v0.0.9 (drive letter stripped); use a relative path until the upstream fix lands")
	}
	return &cfg, nil
}

// newReadBucket mirrors the website's newReadBucket scheme switch.
func (cfg *workerConfig) newReadBucket(ctx context.Context, bucketPath string) (simplecloud.Reader, error) {
	u, err := url.Parse(bucketPath)
	if err != nil {
		return nil, err
	}
	switch {
	// A one letter scheme is a Windows drive path.
	case u.Scheme == "" || len(u.Scheme) == 1:
		return &simplecloud.FileBucket{}, nil
	case u.Scheme == "b2":
		key, secret := cfg.bucketCredentials(u.Host)
		b2Bucket, err := simplecloud.NewB2Client(ctx, key, secret, u.Host)
		if err != nil {
			return nil, err
		}
		b2Bucket.ConcurrentDownloads = 20
		return b2Bucket, nil
	case u.Scheme == "http" || u.Scheme == "https":
		return simplecloud.NewHTTPBucket(cleanhttp.DefaultClient(), bucketPath)
	}
	return nil, fmt.Errorf("unsupported path scheme %s", u.Scheme)
}

// newReadWriteBucket is the writable variant for the mirror tree.
func (cfg *workerConfig) newReadWriteBucket(ctx context.Context, bucketPath string) (simplecloud.ReadWriter, error) {
	u, err := url.Parse(bucketPath)
	if err != nil {
		return nil, err
	}
	switch {
	case u.Scheme == "" || len(u.Scheme) == 1:
		return &simplecloud.FileBucket{}, nil
	case u.Scheme == "b2":
		key, secret := cfg.bucketCredentials(u.Host)
		return simplecloud.NewB2Client(ctx, key, secret, u.Host)
	}
	return nil, fmt.Errorf("unsupported writable path scheme %s", u.Scheme)
}
