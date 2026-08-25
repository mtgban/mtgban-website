package offlineapi

import (
	"context"
	"encoding/json"
	"net/http/httptest"
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
