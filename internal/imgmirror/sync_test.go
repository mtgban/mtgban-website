package imgmirror

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/mtgban/simplecloud"
)

func TestRunSyncSkipsOverCap(t *testing.T) {
	base := filepath.ToSlash(t.TempDir())
	want := map[string]Card{
		"uuid-1": {URL: "http://mirror.invalid/1.jpg", SetCode: "NEO"},
		"uuid-2": {URL: "http://mirror.invalid/2.jpg", SetCode: "NEO"},
	}
	res, err := RunSync(context.Background(), SyncOpts{
		Bucket: &simplecloud.FileBucket{}, Base: base, Want: want, MaxFetch: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.SkippedOverCap {
		t.Error("expected over-cap skip")
	}
	if res.Pending != 2 {
		t.Errorf("pending = %d, want 2", res.Pending)
	}
	if _, err := os.Stat(filepath.Join(base, "mirror-state.json")); !os.IsNotExist(err) {
		t.Error("over-cap skip must not write state")
	}
}

func TestRunSyncEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("imgbytes"))
	}))
	defer srv.Close()

	base := filepath.ToSlash(t.TempDir())
	want := map[string]Card{"uuid-1": {URL: srv.URL + "/1.jpg", SetCode: "NEO"}}
	res, err := RunSync(context.Background(), SyncOpts{
		Bucket: &simplecloud.FileBucket{}, Base: base, Want: want,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Fetched != 1 || res.FetchFailed != 0 || res.BundlesRebuilt != 1 || res.SkippedOverCap {
		t.Errorf("res = %+v", res)
	}
	m, err := LoadManifest(context.Background(), &simplecloud.FileBucket{}, base)
	if err != nil {
		t.Fatal(err)
	}
	if m["NEO"].Count != 1 {
		t.Errorf("manifest NEO = %+v", m["NEO"])
	}
}
