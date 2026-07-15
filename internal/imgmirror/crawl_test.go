package imgmirror

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mtgban/simplecloud"
)

func testCrawler(t *testing.T) *crawler {
	t.Helper()
	c := newCrawler(&simplecloud.FileBucket{}, filepath.ToSlash(t.TempDir()), State{})
	c.limit = &Limiter{Interval: 0}
	c.backoff = func(int) time.Duration { return 0 }
	return c
}

func TestDownloadRetriesOn429(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte("jpegbytes"))
	}))
	defer srv.Close()

	c := testCrawler(t)
	data, err := c.download(context.Background(), "test", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "jpegbytes" {
		t.Errorf("body = %q", data)
	}
	if hits != 3 {
		t.Errorf("attempts = %d, want 3", hits)
	}
}

func TestDownloadFailsFastOn404(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := testCrawler(t)
	if _, err := c.download(context.Background(), "test", srv.URL); err == nil {
		t.Fatal("expected error on 404")
	}
	if hits != 1 {
		t.Errorf("attempts = %d, want 1 (no retry on 404)", hits)
	}
}

func TestDownloadGivesUpAfterRetries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := testCrawler(t)
	if _, err := c.download(context.Background(), "test", srv.URL); err == nil {
		t.Fatal("expected error after exhausting retries")
	}
}

func TestFetchOneJpegFallback(t *testing.T) {
	payload := []byte("not really a jpeg")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer srv.Close()

	c := testCrawler(t)
	// Force the no-cwebp path regardless of the host machine.
	c.cwebp = ""

	err := c.fetchOne(context.Background(), "test", "uuid-test", Card{URL: srv.URL, SetCode: "TST"})
	if err != nil {
		t.Fatal(err)
	}

	stored, err := os.ReadFile(filepath.Join(c.base, "images", "uuid-test.jpg"))
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(payload) {
		t.Error("stored bytes differ from source")
	}

	entry := c.state["uuid-test"]
	sum := sha256.Sum256(payload)
	if entry.Digest != hex.EncodeToString(sum[:]) {
		t.Errorf("digest = %q", entry.Digest)
	}
	if entry.Ext != "jpg" || entry.Source != srv.URL {
		t.Errorf("state entry = %+v", entry)
	}
	if entry.EntryName("uuid-test") != "uuid-test.jpg" {
		t.Errorf("entry name = %q", entry.EntryName("uuid-test"))
	}
}

func TestFetchAllReturnsErrorOnFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusGone)
	}))
	defer srv.Close()

	c := testCrawler(t)
	want := map[string]Card{
		"uuid-fail": {URL: srv.URL + "/img.jpg", SetCode: "TST"},
		"uuid-bad":  {URL: "://bad url", SetCode: "TST"},
	}
	err := c.fetchAll(context.Background(), []string{"uuid-fail", "uuid-bad"}, want)
	if err == nil {
		t.Fatal("expected non-nil error when fetches fail")
	}
}

func TestRebuildBundlesMergesManifest(t *testing.T) {
	base := filepath.ToSlash(t.TempDir())
	os.MkdirAll(filepath.Join(base, "images"), 0755)
	os.WriteFile(filepath.Join(base, "images", "uuid-a.webp"), []byte("img-a"), 0644)

	state := State{"uuid-a": {Digest: "d1", Source: "s"}}
	want := map[string]Card{"uuid-a": {URL: "s", SetCode: "NEO"}}
	manifest := Manifest{"MID": {Hash: "keepme", Count: 9, Bytes: 99}}

	_, err := rebuildBundles(context.Background(), &simplecloud.FileBucket{}, base, state, want, manifest)
	if err != nil {
		t.Fatal(err)
	}

	got, err := LoadManifest(context.Background(), &simplecloud.FileBucket{}, base)
	if err != nil {
		t.Fatal(err)
	}
	if got["MID"].Hash != "keepme" {
		t.Error("out of scope manifest entry was dropped")
	}
	neo := got["NEO"]
	wantHash := BundleHash(map[string]string{"uuid-a": "d1"})
	if neo.Hash != wantHash || neo.Count != 1 || neo.Bytes == 0 {
		t.Errorf("NEO entry = %+v, want hash %s", neo, wantHash)
	}
	zipPath := filepath.Join(base, "bundles", "NEO-"+wantHash+".zip")
	if _, err := os.Stat(zipPath); err != nil {
		t.Errorf("bundle zip missing: %v", err)
	}
}
