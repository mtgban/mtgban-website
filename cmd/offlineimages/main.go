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

	want := enumerateImages(setsFilter)
	log.Printf("enumerated %d printings with images", len(want))
	for domain, n := range imgmirror.Domains(want) {
		log.Printf("source domain %s: %d images", domain, n)
	}

	base := cfg.Datastore.OfflineImagesPath
	mirror, err := cfg.newReadWriteBucket(ctx, base)
	if err != nil {
		return err
	}

	state, err := loadState(ctx, mirror, base)
	if err != nil {
		return err
	}
	manifest, err := loadManifest(ctx, mirror, base)
	if err != nil {
		return err
	}

	fetches := imgmirror.NeedFetch(state, want)
	log.Printf("%d images to fetch", len(fetches))

	if dryRun {
		setCodes := map[string]bool{}
		for _, card := range want {
			setCodes[card.SetCode] = true
		}
		rebuild := imgmirror.BundlesToRebuild(manifest, imgmirror.SetDigests(state, want))
		log.Printf("dry run: %d sets in scope, %d bundles stale right now: %v", len(setCodes), len(rebuild), rebuild)
		return nil
	}

	crawler := newCrawler(mirror, base, state)
	fetchErr := crawler.fetchAll(ctx, fetches, want)
	// Complete bundle/manifest work before surfacing fetch failures so cron
	// gets a consistent tree even on a partial run.
	if err := rebuildBundles(ctx, mirror, base, crawler.state, want, manifest); err != nil {
		return err
	}
	return fetchErr
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

// enumerateImages maps every uuid, sealed included, to its normal size
// image URL, skipping printings with no image.
func enumerateImages(setsFilter map[string]bool) map[string]imgmirror.Card {
	out := map[string]imgmirror.Card{}
	skipped := 0
	for _, uuid := range mtgmatcher.GetUUIDs() {
		co, err := mtgmatcher.GetUUID(uuid)
		if err != nil {
			continue
		}
		if setsFilter != nil && !setsFilter[co.SetCode] {
			continue
		}
		imgURL := co.Images["full"]
		if imgURL == "" {
			skipped++
			continue
		}
		out[uuid] = imgmirror.Card{URL: imgURL, SetCode: co.SetCode, Sealed: co.Sealed}
	}
	if skipped > 0 {
		log.Printf("skipped %d printings with no image URL", skipped)
	}
	return out
}
