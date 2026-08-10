package offlineapi

import (
	"context"
	"hash/fnv"
	"io"
	"log"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/mtgban/simplecloud"
)

var (
	scryfallIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	sealedKeyPattern  = regexp.MustCompile(`^p-([0-9A-Z]{2,6})-([0-9]+)$`)
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

// serveImage streams one mirrored image by scryfall id or sealed key.
func (s *Service) serveImage(w http.ResponseWriter, r *http.Request, rest string) {
	key := strings.TrimSuffix(rest, ".jpg")
	if key == "" || key == rest {
		http.NotFound(w, r)
		return
	}

	var dir, name string
	switch {
	case scryfallIDPattern.MatchString(key):
		dir = path.Join("normal", "front", key[0:1], key[1:2])
		name = key + ".jpg"
	case sealedKeyPattern.MatchString(key):
		m := sealedKeyPattern.FindStringSubmatch(key)
		dir = path.Join(m[1], "sealed")
		name = m[2] + ".jpg"
	default:
		http.NotFound(w, r)
		return
	}

	reader, err := s.openImageObject(r.Context(), dir, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer reader.Close()

	// The bytes are the only version marker available for a single image: the
	// mirror rewrites an image in place when Scryfall reprocesses it, and the
	// images manifest only tracks whole sets. Buffering to hash them also lets
	// a failed read answer with an error instead of a truncated 200, and gives
	// the client a Content-Length to detect a short response against.
	data, err := io.ReadAll(reader)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}

	sum := fnv.New64a()
	sum.Write(data)
	etag := `"` + strconv.FormatUint(sum.Sum64(), 16) + `"`

	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "private, max-age=604800")
	w.Header().Set("ETag", etag)
	if inm := r.Header.Get("If-None-Match"); inm != "" && etagMatches(inm, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Write(data)
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
	// A bundle is far too large to buffer, so the status is already sent by
	// the time a read can fail. Declaring the length the manifest recorded at
	// build time turns a cut stream into an error the client raises, rather
	// than a short zip it caches and extracts as though it were whole.
	w.Header().Set("Content-Length", strconv.FormatInt(info.Bytes, 10))
	if n, err := io.Copy(w, reader); err != nil {
		log.Printf("offline: bundle %s cut short after %d of %d bytes: %v", code, n, info.Bytes, err)
	}
}
