package imgmirror

import (
	"context"
	"log"

	"github.com/mtgban/simplecloud"
)

// SyncOpts configures one mirror sync pass.
type SyncOpts struct {
	Bucket simplecloud.ReadWriter
	Base   string
	// Want is the full image set to mirror, from EnumerateImages.
	Want map[string]Card
	// MaxFetch caps the pending delta; 0 means unlimited.
	MaxFetch int
}

// SyncResult reports one pass's work.
type SyncResult struct {
	Pending        int
	Fetched        int
	FetchFailed    int
	BundlesRebuilt int
	SkippedOverCap bool
}

// RunSync performs one incremental mirror pass: diff, crawl, bundle, manifest.
// An over-cap skip returns a nil error with SkippedOverCap set and no writes.
func RunSync(ctx context.Context, opts SyncOpts) (SyncResult, error) {
	var res SyncResult
	state, err := LoadState(ctx, opts.Bucket, opts.Base)
	if err != nil {
		return res, err
	}
	manifest, err := LoadManifest(ctx, opts.Bucket, opts.Base)
	if err != nil {
		return res, err
	}

	fetches := NeedFetch(state, opts.Want)
	res.Pending = len(fetches)
	log.Printf("%d images to fetch", len(fetches))
	if opts.MaxFetch > 0 && len(fetches) > opts.MaxFetch {
		res.SkippedOverCap = true
		return res, nil
	}

	c := newCrawler(opts.Bucket, opts.Base, state)
	fetchErr := c.fetchAll(ctx, fetches, opts.Want)
	res.Fetched, res.FetchFailed = c.done, c.failures
	// Bundle and manifest work completes before fetch failures surface so
	// callers get a consistent tree even on a partial run.
	rebuilt, err := rebuildBundles(ctx, opts.Bucket, opts.Base, c.state, opts.Want, manifest)
	res.BundlesRebuilt = rebuilt
	if err != nil {
		return res, err
	}
	return res, fetchErr
}
