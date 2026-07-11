package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/mtgban/mtgban-website/internal/bucketstore"
	"github.com/mtgban/simplecloud"
)

// The bucket client is cached because image requests are hot, unlike the
// per operation clients used by the rarely touched admin documents.
var (
	offlineImagesBucketMu   sync.Mutex
	offlineImagesBucketCur  simplecloud.ReadWriter
	offlineImagesBucketBase string
)

// offlineImagesBucket returns the bucket holding the mirrored image tree.
func offlineImagesBucket(ctx context.Context) (simplecloud.ReadWriter, error) {
	base := Config.Datastore.OfflineImagesPath
	if base == "" {
		return nil, errors.New("offline_images_path not configured")
	}

	offlineImagesBucketMu.Lock()
	defer offlineImagesBucketMu.Unlock()
	if offlineImagesBucketCur != nil && offlineImagesBucketBase == base {
		return offlineImagesBucketCur, nil
	}

	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	var bucket simplecloud.ReadWriter
	switch {
	// A one letter scheme is a Windows drive path; fail loud so misconfigured
	// Windows absolute paths (broken by simplecloud v0.0.9) are caught early.
	case len(u.Scheme) == 1:
		return nil, errors.New("offline_images_path: Windows absolute paths are broken by simplecloud v0.0.9 (drive letter stripped); use a relative path until the upstream fix lands")
	case u.Scheme == "":
		bucket = &simplecloud.FileBucket{}
	case u.Scheme == "b2":
		bucket, err = simplecloud.NewB2Client(ctx, Config.Datastore.BucketAccessKey, Config.Datastore.BucketSecretKey, u.Host)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported offline images path scheme: %s", u.Scheme)
	}
	offlineImagesBucketCur, offlineImagesBucketBase = bucket, base
	return bucket, nil
}

var offlineImagesManifestStore = &bucketstore.Store[ImagesManifest]{
	MissingOK: true,
	Bucket: func(ctx context.Context) (simplecloud.ReadWriter, string, error) {
		bucket, err := offlineImagesBucket(ctx)
		if err != nil {
			return nil, "", err
		}
		return bucket, joinBucketPath(Config.Datastore.OfflineImagesPath, "images-manifest.json"), nil
	},
}

// refreshOfflineImagesManifest reloads the worker written images manifest.
func refreshOfflineImagesManifest() {
	if Config.Datastore.OfflineImagesPath == "" {
		return
	}
	if err := offlineImagesManifestStore.Load(context.Background()); err != nil {
		log.Println("offline: images manifest load failed:", err)
	}
}

func openOfflineImageObject(ctx context.Context, dir, name string) (io.ReadCloser, error) {
	bucket, err := offlineImagesBucket(ctx)
	if err != nil {
		return nil, err
	}
	return simplecloud.InitReader(ctx, bucket, joinBucketPath(Config.Datastore.OfflineImagesPath, dir, name))
}

// etagMatches reports whether an If-None-Match header matches etag.
// Weak validators (W/"...") on the header side are accepted per RFC 7232 §3.2.
func etagMatches(header, etag string) bool {
	if strings.TrimSpace(header) == "*" {
		return true
	}
	for _, part := range strings.Split(header, ",") {
		p := strings.TrimPrefix(strings.TrimSpace(part), "W/")
		if p == etag {
			return true
		}
	}
	return false
}

// serveOfflineImage streams one mirrored image, webp first, jpg fallback.
func serveOfflineImage(w http.ResponseWriter, r *http.Request, rest string) {
	uuid := strings.TrimSuffix(rest, ".webp")
	if uuid == "" || uuid == rest || strings.ContainsAny(uuid, "/\\.%") {
		http.NotFound(w, r)
		return
	}

	for _, try := range []struct{ ext, mime string }{
		{"webp", "image/webp"},
		{"jpg", "image/jpeg"},
	} {
		reader, err := openOfflineImageObject(r.Context(), "images", uuid+"."+try.ext)
		if err != nil {
			continue
		}
		defer reader.Close()
		w.Header().Set("Content-Type", try.mime)
		w.Header().Set("Cache-Control", "private, max-age=604800")
		io.Copy(w, reader)
		return
	}
	http.NotFound(w, r)
}

// serveOfflineImageBundle streams the current per set zip with ETag support.
func serveOfflineImageBundle(w http.ResponseWriter, r *http.Request, rest string) {
	code := strings.TrimSuffix(rest, ".zip")
	if code == "" || code == rest || strings.ContainsAny(code, "/\\.%") {
		http.NotFound(w, r)
		return
	}

	info, found := offlineImagesManifestStore.Get()[code]
	if !found {
		http.NotFound(w, r)
		return
	}

	etag := `"` + info.Hash + `"`
	inm := r.Header.Get("If-None-Match")
	if inm != "" && etagMatches(inm, etag) {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}

	reader, err := openOfflineImageObject(r.Context(), "bundles", code+"-"+info.Hash+".zip")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer reader.Close()

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "private, max-age=300")
	io.Copy(w, reader)
}
