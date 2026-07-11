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
	os.MkdirAll(filepath.Join(filepath.FromSlash(dir), "images"), 0755)
	os.WriteFile(filepath.Join(filepath.FromSlash(dir), "images", "uuid-aaa.webp"), []byte("webpdata"), 0644)
	os.WriteFile(filepath.Join(filepath.FromSlash(dir), "images", "uuid-jpg.jpg"), []byte("jpegdata"), 0644)

	tests := []struct {
		rest string
		code int
		body string
		mime string
	}{
		{"uuid-aaa.webp", 200, "webpdata", "image/webp"},
		{"uuid-jpg.webp", 200, "jpegdata", "image/jpeg"},
		{"uuid-none.webp", 404, "", ""},
		{"uuid-aaa", 404, "", ""},
		{"../images/uuid-aaa.webp", 404, "", ""},
		{"..\\uuid-aaa.webp", 404, "", ""},
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
		if got := w.Header().Get("Content-Type"); got != tt.mime {
			t.Errorf("%s: content type = %q, want %q", tt.rest, got, tt.mime)
		}
		if got := w.Header().Get("Cache-Control"); got != "private, max-age=604800" {
			t.Errorf("%s: cache control = %q", tt.rest, got)
		}
	}
}

func TestServeOfflineImageBundle(t *testing.T) {
	s, dir := newTestService(t)
	os.MkdirAll(filepath.Join(filepath.FromSlash(dir), "bundles"), 0755)
	os.WriteFile(filepath.Join(filepath.FromSlash(dir), "bundles", "NEO-abc123.zip"), []byte("zipdata"), 0644)
	s.imagesStore.Set(ImagesManifest{"NEO": {Hash: "abc123", Count: 1, Bytes: 7}})
	t.Cleanup(func() { s.imagesStore.Set(nil) })

	w := httptest.NewRecorder()
	s.serveImageBundle(w, httptest.NewRequest("GET", "/api/offline/imagebundles/NEO.zip", nil), "NEO.zip")
	if w.Code != 200 || w.Body.String() != "zipdata" {
		t.Fatalf("bundle fetch: code %d body %q", w.Code, w.Body.String())
	}
	if w.Header().Get("ETag") != `"abc123"` {
		t.Fatalf("etag = %q", w.Header().Get("ETag"))
	}
	if w.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("content type = %q", w.Header().Get("Content-Type"))
	}

	r := httptest.NewRequest("GET", "/api/offline/imagebundles/NEO.zip", nil)
	r.Header.Set("If-None-Match", `"abc123"`)
	w = httptest.NewRecorder()
	s.serveImageBundle(w, r, "NEO.zip")
	if w.Code != http.StatusNotModified {
		t.Fatalf("conditional get: code = %d, want 304", w.Code)
	}

	r = httptest.NewRequest("GET", "/api/offline/imagebundles/NEO.zip", nil)
	r.Header.Set("If-None-Match", "*")
	w = httptest.NewRecorder()
	s.serveImageBundle(w, r, "NEO.zip")
	if w.Code != http.StatusNotModified {
		t.Fatalf("conditional get with *: code = %d, want 304", w.Code)
	}

	// Weak ETag validators must also match.
	r = httptest.NewRequest("GET", "/api/offline/imagebundles/NEO.zip", nil)
	r.Header.Set("If-None-Match", `W/"abc123"`)
	w = httptest.NewRecorder()
	s.serveImageBundle(w, r, "NEO.zip")
	if w.Code != http.StatusNotModified {
		t.Fatalf("weak etag: code = %d, want 304", w.Code)
	}

	w = httptest.NewRecorder()
	s.serveImageBundle(w, httptest.NewRequest("GET", "/api/offline/imagebundles/XXX.zip", nil), "XXX.zip")
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown set: code = %d, want 404", w.Code)
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
