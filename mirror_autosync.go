package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/mtgban/mtgban-website/internal/debounce"
	"github.com/mtgban/mtgban-website/internal/imgmirror"
	"github.com/mtgban/simplecloud"
)

// mirrorAutoSyncMaxFetch caps the in-process delta; larger backfills belong
// to cmd/offlineimages.
const mirrorAutoSyncMaxFetch = 2000

var mirrorAutoSyncDebounce = 30 * time.Second

// mirrorAutoSync incrementally syncs the image mirror inside the website
// once the standalone binary has written the backfill marker.
type mirrorAutoSync struct {
	buckets   func(ctx context.Context) (simplecloud.ReadWriter, string, error)
	enumerate func() map[string]imgmirror.Card
	alert     func(kind, message string)
	afterSync func()
	maxFetch  int

	signal chan struct{}
}

func newMirrorAutoSync(
	buckets func(ctx context.Context) (simplecloud.ReadWriter, string, error),
	enumerate func() map[string]imgmirror.Card,
	alert func(kind, message string),
	afterSync func(),
) *mirrorAutoSync {
	return &mirrorAutoSync{
		buckets:   buckets,
		enumerate: enumerate,
		alert:     alert,
		afterSync: afterSync,
		maxFetch:  mirrorAutoSyncMaxFetch,
		signal:    make(chan struct{}, 1),
	}
}

// Request asks for a sync soon; bursts coalesce and it never blocks.
func (m *mirrorAutoSync) Request() {
	select {
	case m.signal <- struct{}{}:
	default:
	}
}

// Start runs the debounced sync loop. Runs never overlap because the loop is
// a single goroutine. The crawl saves state periodically, so a process exit
// mid-run is safe and resumable.
func (m *mirrorAutoSync) Start() {
	go debounce.Loop(m.signal, mirrorAutoSyncDebounce, func() { m.runOnce(context.Background()) })
}

// runOnce gates on the backfill marker and cap, then runs one sync pass.
func (m *mirrorAutoSync) runOnce(ctx context.Context) {
	bucket, base, err := m.buckets(ctx)
	if err != nil {
		log.Println("mirror autosync: bucket unavailable:", err)
		return
	}
	_, found, err := imgmirror.ReadMarker(ctx, bucket, base)
	if err != nil {
		m.alert("mirror-sync", "backfill marker unreadable, sync skipped: "+err.Error())
		return
	}
	if !found {
		log.Println("mirror autosync: no backfill marker, skipping (run cmd/offlineimages)")
		return
	}

	res, err := imgmirror.RunSync(ctx, imgmirror.SyncOpts{
		Bucket:   bucket,
		Base:     base,
		Want:     m.enumerate(),
		MaxFetch: m.maxFetch,
	})
	switch {
	case res.SkippedOverCap:
		m.alert("mirror-sync", fmt.Sprintf("delta too large for in-process sync (%d images, cap %d), run cmd/offlineimages", res.Pending, m.maxFetch))
	case err != nil:
		m.alert("mirror-sync", fmt.Sprintf("sync finished with errors (%d fetched, %d failed, %d bundles): %v", res.Fetched, res.FetchFailed, res.BundlesRebuilt, err))
		// Bundles that did rebuild are already saved; let clients see them.
		if res.BundlesRebuilt > 0 && m.afterSync != nil {
			m.afterSync()
		}
	case res.Fetched > 0 || res.BundlesRebuilt > 0:
		log.Printf("mirror autosync: %d images fetched, %d bundles rebuilt", res.Fetched, res.BundlesRebuilt)
		if m.afterSync != nil {
			m.afterSync()
		}
	}
}
