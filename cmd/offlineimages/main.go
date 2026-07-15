// Command offlineimages mirrors card images into the offline bucket:
// fetch, WebP transcode, per set zip bundles, and images-manifest.json.
package main

import (
	"context"
	"flag"
	"log"
	"strings"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/internal/imgmirror"
	"github.com/mtgban/simplecloud"
)

func main() {
	configPath := flag.String("config", "config.json", "Path to the website config.json")
	setsCSV := flag.String("sets", "", "Comma separated set codes to limit the run")
	dryRun := flag.Bool("dry-run", false, "Plan only, write nothing")
	flag.Parse()

	if err := run(*configPath, *setsCSV, *dryRun); err != nil {
		log.Fatalln(err)
	}
}

func run(configPath, setsCSV string, dryRun bool) error {
	ctx := context.Background()

	cfg, err := loadWorkerConfig(configPath)
	if err != nil {
		return err
	}

	if err := loadCardDatastore(ctx, cfg); err != nil {
		return err
	}

	var setsFilter map[string]bool
	if setsCSV != "" {
		setsFilter = map[string]bool{}
		for _, code := range strings.Split(setsCSV, ",") {
			setsFilter[strings.ToUpper(strings.TrimSpace(code))] = true
		}
	}

	want := imgmirror.EnumerateImages(setsFilter)
	log.Printf("enumerated %d printings with images", len(want))
	for domain, n := range imgmirror.Domains(want) {
		log.Printf("source domain %s: %d images", domain, n)
	}

	base := cfg.Datastore.OfflineImagesPath
	mirror, err := cfg.newReadWriteBucket(ctx, base)
	if err != nil {
		return err
	}

	if dryRun {
		state, err := imgmirror.LoadState(ctx, mirror, base)
		if err != nil {
			return err
		}
		manifest, err := imgmirror.LoadManifest(ctx, mirror, base)
		if err != nil {
			return err
		}
		fetches := imgmirror.NeedFetch(state, want)
		log.Printf("%d images to fetch", len(fetches))
		setCodes := map[string]bool{}
		for _, card := range want {
			setCodes[card.SetCode] = true
		}
		rebuild := imgmirror.BundlesToRebuild(manifest, imgmirror.SetDigests(state, want))
		log.Printf("dry run: %d sets in scope, %d bundles stale right now: %v", len(setCodes), len(rebuild), rebuild)
		return nil
	}

	res, err := imgmirror.RunSync(ctx, imgmirror.SyncOpts{Bucket: mirror, Base: base, Want: want})
	log.Printf("fetched %d images (%d failed), %d bundles rebuilt", res.Fetched, res.FetchFailed, res.BundlesRebuilt)
	return err
}

// loadCardDatastore loads mtgmatcher the way the website does, minus the
// website only side effects.
func loadCardDatastore(ctx context.Context, cfg *workerConfig) error {
	bucket, err := cfg.newReadBucket(ctx, cfg.DatastorePath)
	if err != nil {
		return err
	}
	reader, err := simplecloud.InitReader(ctx, bucket, cfg.DatastorePath)
	if err != nil {
		return err
	}
	defer reader.Close()
	log.Println("loading datastore from", cfg.DatastorePath)
	return mtgmatcher.LoadDatastore(reader)
}
