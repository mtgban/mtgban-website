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

// serveImage streams one mirrored image by scryfall id or sealed key. The
// extension is part of the key's identity, not decoration: singles are
// Scryfall's webp and sealed are TCGplayer's jpg, so a request for the wrong
// one is a miss rather than a silent substitution.
func (s *Service) serveImage(w http.ResponseWriter, r *http.Request, rest string) {
	var key, dir, name, ctype string
	switch {
	case strings.HasSuffix(rest, ".webp"):
		key = strings.TrimSuffix(rest, ".webp")
		if !scryfallIDPattern.MatchString(key) {
			http.NotFound(w, r)
			return
		}
		// singles/grid/front/<c1>/<c2>/<scryfallId>.webp in the mirror
		dir, name, ctype = path.Join("singles", "grid", "front", key[0:1], key[1:2]), key+".webp", "image/webp"
	case strings.HasSuffix(rest, ".jpg"):
		key = strings.TrimSuffix(rest, ".jpg")
		m := sealedKeyPattern.FindStringSubmatch(key)
		if m == nil {
			http.NotFound(w, r)
			return
		}
		// sealed/<SETCODE>/<tcgProductId>.jpg in the mirror
		dir, name, ctype = path.Join("sealed", m[1]), m[2]+".jpg", "image/jpeg"
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

	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", "private, max-age=604800")
	w.Header().Set("ETag", etag)
	if inm := r.Header.Get("If-None-Match"); inm != "" && etagMatches(inm, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Write(data)
}
