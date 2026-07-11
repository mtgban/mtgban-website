package offlineapi

import (
	"context"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/mtgban/simplecloud"
)

// refreshImagesManifest reloads the worker-written images manifest.
func (s *Service) refreshImagesManifest() {
	if !s.deps.ImagesPathConfigured() {
		return
	}
	if err := s.imagesStore.Load(context.Background()); err != nil {
		log.Println("offline: images manifest load failed:", err)
	}
}

func (s *Service) openImageObject(ctx context.Context, dir, name string) (io.ReadCloser, error) {
	bucket, base, err := s.deps.ImagesBucket(ctx)
	if err != nil {
		return nil, err
	}
	return simplecloud.InitReader(ctx, bucket, joinBucketPath(base, dir, name))
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

// serveImage streams one mirrored image, webp first, jpg fallback.
func (s *Service) serveImage(w http.ResponseWriter, r *http.Request, rest string) {
	uuid := strings.TrimSuffix(rest, ".webp")
	if uuid == "" || uuid == rest || strings.ContainsAny(uuid, "/\\.%") {
		http.NotFound(w, r)
		return
	}

	for _, try := range []struct{ ext, mime string }{
		{"webp", "image/webp"},
		{"jpg", "image/jpeg"},
	} {
		reader, err := s.openImageObject(r.Context(), "images", uuid+"."+try.ext)
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

// serveImageBundle streams the current per-set zip with ETag support.
func (s *Service) serveImageBundle(w http.ResponseWriter, r *http.Request, rest string) {
	code := strings.TrimSuffix(rest, ".zip")
	if code == "" || code == rest || strings.ContainsAny(code, "/\\.%") {
		http.NotFound(w, r)
		return
	}

	info, found := s.imagesStore.Get()[code]
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

	reader, err := s.openImageObject(r.Context(), "bundles", code+"-"+info.Hash+".zip")
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
