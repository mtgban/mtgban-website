package offlineapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mtgban/simplecloud"
)

func newTestService(t *testing.T) (*Service, string) {
	t.Helper()
	dir := filepath.ToSlash(t.TempDir())
	s := NewService(Deps{
		ImagesBucket: func(ctx context.Context) (simplecloud.ReadWriter, string, error) {
			return &simplecloud.FileBucket{}, dir, nil
		},
		ImagesManifestBucket: func(ctx context.Context) (simplecloud.ReadWriter, string, error) {
			return &simplecloud.FileBucket{}, joinBucketPath(dir, "images-manifest.json"), nil
		},
		ManifestBucket: func(ctx context.Context) (simplecloud.ReadWriter, string, error) {
			return &simplecloud.FileBucket{}, joinBucketPath(dir, "offline-manifest.json"), nil
		},
		ManifestPathConfigured: func() bool { return false },
		ImagesPathConfigured:   func() bool { return true },
	})
	return s, dir
}

func TestServeOfflineImage(t *testing.T) {
	s, dir := newTestService(t)
	scryfallID := "ab154b52-1234-5678-9abc-def012345678"
	os.MkdirAll(filepath.Join(filepath.FromSlash(dir), "normal", "front", "a", "b"), 0755)
	os.WriteFile(filepath.Join(filepath.FromSlash(dir), "normal", "front", "a", "b", scryfallID+".jpg"), []byte("jpegdata"), 0644)
	os.MkdirAll(filepath.Join(filepath.FromSlash(dir), "sealed", "MH3"), 0755)
	os.WriteFile(filepath.Join(filepath.FromSlash(dir), "sealed", "MH3", "541185.jpg"), []byte("sealeddata"), 0644)

	tests := []struct {
		rest string
		code int
		body string
	}{
		{scryfallID + ".jpg", 200, "jpegdata"},
		{"p-MH3-541185.jpg", 200, "sealeddata"},
		{"../x", 404, ""},
		{"a%2f.jpg", 404, ""},
		{scryfallID + ".extra.jpg", 404, ""},
		{scryfallID + ".webp", 404, ""},
	}
	for _, tt := range tests {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/api/offline/images/"+tt.rest, nil)
		s.serveImage(w, r, tt.rest)
		if w.Code != tt.code {
			t.Errorf("%s: code = %d, want %d", tt.rest, w.Code, tt.code)
			continue
		}
		if tt.code != 200 {
			continue
		}
		if w.Body.String() != tt.body {
			t.Errorf("%s: body = %q, want %q", tt.rest, w.Body.String(), tt.body)
		}
		if got := w.Header().Get("Content-Type"); got != "image/jpeg" {
			t.Errorf("%s: content type = %q, want image/jpeg", tt.rest, got)
		}
		if got := w.Header().Get("Cache-Control"); got != "private, max-age=604800" {
			t.Errorf("%s: cache control = %q", tt.rest, got)
		}
	}
}

func TestOfflineManifestIncludesImages(t *testing.T) {
	s, _ := newTestService(t)
	s.imagesStore.Set(ImagesManifest{
		"NEO": {Hash: "abc123", Count: 302, Bytes: 24800000},
	})
	t.Cleanup(func() { s.imagesStore.Set(nil) })

	w := httptest.NewRecorder()
	s.serveManifest(w, httptest.NewRequest("GET", "/api/offline/manifest.json", nil))

	var doc struct {
		Images map[string]struct {
			H string `json:"h"`
			N int    `json:"n"`
			B int64  `json:"b"`
		} `json:"images"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	img, found := doc.Images["NEO"]
	if !found || img.H != "abc123" || img.N != 302 || img.B != 24800000 {
		t.Fatalf("images map mismatch: %+v", doc.Images)
	}
}

func TestOfflineManifestOmitsEmptyImages(t *testing.T) {
	s, _ := newTestService(t)
	s.imagesStore.Set(nil)

	w := httptest.NewRecorder()
	s.serveManifest(w, httptest.NewRequest("GET", "/api/offline/manifest.json", nil))
	if strings.Contains(w.Body.String(), `"images"`) {
		t.Errorf("empty images map should be omitted: %s", w.Body.String())
	}
}

func TestServeOfflineImageETag(t *testing.T) {
	s, dir := newTestService(t)
	id := "ab154b52-1234-5678-9abc-def012345678"
	os.MkdirAll(filepath.Join(filepath.FromSlash(dir), "normal", "front", "a", "b"), 0755)
	path := filepath.Join(filepath.FromSlash(dir), "normal", "front", "a", "b", id+".jpg")
	os.WriteFile(path, []byte("jpegdata"), 0644)

	get := func(inm string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/api/offline/images/"+id+".jpg", nil)
		if inm != "" {
			r.Header.Set("If-None-Match", inm)
		}
		s.serveImage(w, r, id+".jpg")
		return w
	}

	first := get("")
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag on the first response")
	}
	if got := first.Header().Get("Content-Length"); got != "8" {
		t.Errorf("Content-Length = %q, want 8 so a short body is detectable", got)
	}

	// a matching validator must save the body, including the weak form
	for _, inm := range []string{etag, "W/" + etag, `"other", ` + etag} {
		w := get(inm)
		if w.Code != http.StatusNotModified {
			t.Errorf("If-None-Match %s: code = %d, want 304", inm, w.Code)
		}
		if w.Body.Len() != 0 {
			t.Errorf("If-None-Match %s: 304 carried a body", inm)
		}
	}

	// rewriting the image in place, as a Scryfall reprocess does, must
	// invalidate the cached copy rather than serve it for another week
	os.WriteFile(path, []byte("reprocessed"), 0644)
	changed := get(etag)
	if changed.Code != http.StatusOK {
		t.Errorf("code = %d, want 200 after the bytes changed", changed.Code)
	}
	if changed.Header().Get("ETag") == etag {
		t.Error("ETag unchanged after the image was rewritten")
	}
}
