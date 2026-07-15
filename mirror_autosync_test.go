package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/internal/imgmirror"
	"github.com/mtgban/simplecloud"
)

// failBucket fails every read; for the transient marker error case.
type failBucket struct{ err error }

func (b failBucket) NewReader(ctx context.Context, path string) (io.ReadCloser, error) {
	return nil, b.err
}
func (b failBucket) NewWriter(ctx context.Context, path string) (io.WriteCloser, error) {
	return nil, b.err
}

func testAutoSync(t *testing.T, bucket simplecloud.ReadWriter, base string, want map[string]imgmirror.Card) (*mirrorAutoSync, *[]string, *int) {
	t.Helper()
	var alerts []string
	var after int
	m := newMirrorAutoSync(
		func(ctx context.Context) (simplecloud.ReadWriter, string, error) { return bucket, base, nil },
		func() map[string]imgmirror.Card { return want },
		func(kind, msg string) { alerts = append(alerts, kind+": "+msg) },
		func() { after++ },
	)
	return m, &alerts, &after
}

func TestAutoSyncSkipsWithoutMarker(t *testing.T) {
	base := filepath.ToSlash(t.TempDir())
	want := map[string]imgmirror.Card{"uuid-1": {URL: "http://mirror.invalid/1.jpg", SetCode: "NEO"}}
	m, alerts, after := testAutoSync(t, &simplecloud.FileBucket{}, base, want)

	m.runOnce(context.Background())

	if len(*alerts) != 0 || *after != 0 {
		t.Fatalf("alerts=%v after=%d, want none", *alerts, *after)
	}
	if _, err := os.Stat(filepath.Join(base, "mirror-state.json")); !os.IsNotExist(err) {
		t.Error("no-marker skip must not write state")
	}
}

func TestAutoSyncAlertsOverCap(t *testing.T) {
	base := filepath.ToSlash(t.TempDir())
	bucket := &simplecloud.FileBucket{}
	if err := imgmirror.WriteMarker(context.Background(), bucket, base, 1); err != nil {
		t.Fatal(err)
	}
	want := map[string]imgmirror.Card{
		"uuid-1": {URL: "http://mirror.invalid/1.jpg", SetCode: "NEO"},
		"uuid-2": {URL: "http://mirror.invalid/2.jpg", SetCode: "NEO"},
	}
	m, alerts, after := testAutoSync(t, bucket, base, want)
	m.maxFetch = 1

	m.runOnce(context.Background())

	if len(*alerts) != 1 || !strings.Contains((*alerts)[0], "delta too large") {
		t.Fatalf("alerts = %v", *alerts)
	}
	if *after != 0 {
		t.Error("over-cap skip must not call afterSync")
	}
}

func TestAutoSyncHappyPathCallsAfterSync(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("imgbytes"))
	}))
	defer srv.Close()

	base := filepath.ToSlash(t.TempDir())
	bucket := &simplecloud.FileBucket{}
	if err := imgmirror.WriteMarker(context.Background(), bucket, base, 1); err != nil {
		t.Fatal(err)
	}
	want := map[string]imgmirror.Card{"uuid-1": {URL: srv.URL + "/1.jpg", SetCode: "NEO"}}
	m, alerts, after := testAutoSync(t, bucket, base, want)

	m.runOnce(context.Background())

	if len(*alerts) != 0 {
		t.Fatalf("alerts = %v", *alerts)
	}
	if *after != 1 {
		t.Errorf("afterSync calls = %d, want 1", *after)
	}
}

func TestAutoSyncAlertsOnMarkerError(t *testing.T) {
	m, alerts, after := testAutoSync(t, failBucket{errors.New("auth failed")}, "base", nil)

	m.runOnce(context.Background())

	if len(*alerts) != 1 || !strings.Contains((*alerts)[0], "marker") {
		t.Fatalf("alerts = %v", *alerts)
	}
	if *after != 0 {
		t.Error("marker error must not call afterSync")
	}
}
