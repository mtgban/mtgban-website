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
		BucketAccessKey   string `json:"bucket_access_key"`
		BucketSecretKey   string `json:"bucket_access_secret"`
		OfflineImagesPath string `json:"offline_images_path"`
	} `json:"datastore"`
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
	if cfg.Datastore.OfflineImagesPath == "" {
		return nil, errors.New("datastore.offline_images_path not configured")
	}
	if u, err := url.Parse(cfg.Datastore.OfflineImagesPath); err == nil && len(u.Scheme) == 1 {
		return nil, errors.New("offline_images_path: Windows absolute paths are broken by simplecloud v0.0.9 (drive letter stripped); use a relative path until the upstream fix lands")
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
		b2Bucket, err := simplecloud.NewB2Client(ctx, cfg.Datastore.BucketAccessKey, cfg.Datastore.BucketSecretKey, u.Host)
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
		return simplecloud.NewB2Client(ctx, cfg.Datastore.BucketAccessKey, cfg.Datastore.BucketSecretKey, u.Host)
	}
	return nil, fmt.Errorf("unsupported writable path scheme %s", u.Scheme)
}
