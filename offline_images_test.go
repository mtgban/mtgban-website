package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/mtgban/mtgban-website/internal/imgmirror"
)

func setupOfflineImagesDir(t *testing.T) string {
	t.Helper()
	dir := filepath.ToSlash(t.TempDir())
	old := Config.Datastore.OfflineImagesPath
	Config.Datastore.OfflineImagesPath = dir
	t.Cleanup(func() { Config.Datastore.OfflineImagesPath = old })
	return dir
}

func TestServeOfflineImage(t *testing.T) {
	dir := setupOfflineImagesDir(t)
	os.MkdirAll(filepath.Join(dir, "images"), 0755)
	os.WriteFile(filepath.Join(dir, "images", "uuid-aaa.webp"), []byte("webpdata"), 0644)
	os.WriteFile(filepath.Join(dir, "images", "uuid-jpg.jpg"), []byte("jpegdata"), 0644)

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
		{"..%2fimages%2fuuid-aaa.webp", 404, "", ""},
	}
	for _, tt := range tests {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/api/offline/images/"+tt.rest, nil)
		serveOfflineImage(w, r, tt.rest)
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
	dir := setupOfflineImagesDir(t)
	os.MkdirAll(filepath.Join(dir, "bundles"), 0755)
	os.WriteFile(filepath.Join(dir, "bundles", "NEO-abc123.zip"), []byte("zipdata"), 0644)
	offlineImagesManifestStore.Set(imgmirror.Manifest{"NEO": {Hash: "abc123", Count: 1, Bytes: 7}})
	t.Cleanup(func() { offlineImagesManifestStore.Set(nil) })

	w := httptest.NewRecorder()
	serveOfflineImageBundle(w, httptest.NewRequest("GET", "/api/offline/imagebundles/NEO.zip", nil), "NEO.zip")
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
	serveOfflineImageBundle(w, r, "NEO.zip")
	if w.Code != http.StatusNotModified {
		t.Fatalf("conditional get: code = %d, want 304", w.Code)
	}

	w = httptest.NewRecorder()
	serveOfflineImageBundle(w, httptest.NewRequest("GET", "/api/offline/imagebundles/XXX.zip", nil), "XXX.zip")
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown set: code = %d, want 404", w.Code)
	}
}
