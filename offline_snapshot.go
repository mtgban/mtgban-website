package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/internal/bucketstore"
	"github.com/mtgban/mtgban-website/internal/offline"
	"github.com/mtgban/simplecloud"
)

// OfflineSetVersion records when a set's canonical data last changed.
type OfflineSetVersion struct {
	Fingerprint string `json:"fp"`
	Version     string `json:"v"`
}

type offlineManifestFile struct {
	Generated string                       `json:"generated"`
	Sets      map[string]OfflineSetVersion `json:"sets"`
}

var offlineManifestStore = &bucketstore.Store[offlineManifestFile]{
	MissingOK: true,
	Bucket: func(ctx context.Context) (simplecloud.ReadWriter, string, error) {
		omPath := Config.Datastore.OfflineManifestPath
		if omPath == "" {
			return nil, "", errors.New("offline_manifest_path not configured")
		}
		u, err := url.Parse(omPath)
		if err != nil {
			return nil, "", err
		}
		switch {
		case u.Scheme == "" || len(u.Scheme) == 1:
			// one-letter scheme = Windows drive letter in a local path
			return &simplecloud.FileBucket{}, omPath, nil
		case u.Scheme == "b2":
			bucket, err := simplecloud.NewB2Client(ctx, Config.Datastore.BucketAccessKey, Config.Datastore.BucketSecretKey, u.Host)
			return bucket, omPath, err
		default:
			return nil, "", fmt.Errorf("unsupported offline manifest path scheme: %s", u.Scheme)
		}
	},
}

// computeOfflineFingerprints hashes every in-memory price tuple, per set.
func computeOfflineFingerprints() map[string]string {
	fps := map[string]*offline.Fingerprint{}
	add := func(store, uuid, tag string, price float64, qty int) {
		co, err := mtgmatcher.GetUUID(uuid)
		if err != nil {
			return
		}
		f := fps[co.SetCode]
		if f == nil {
			f = &offline.Fingerprint{}
			fps[co.SetCode] = f
		}
		f.Add(uuid, store, tag, uint64(math.Round(price*100)), qty)
	}

	for _, seller := range GetSellers() {
		shorthand := seller.Info().Shorthand
		for uuid, entries := range seller.Inventory() {
			for _, e := range entries {
				add(shorthand, uuid, e.Conditions, e.Price, e.Quantity)
			}
		}
	}
	for _, vendor := range GetVendors() {
		shorthand := vendor.Info().Shorthand
		for uuid, entries := range vendor.Buylist() {
			for _, e := range entries {
				add(shorthand, uuid, e.Conditions, e.BuyPrice, e.Quantity)
			}
		}
	}

	out := make(map[string]string, len(fps))
	for code, f := range fps {
		out[code] = strconv.FormatUint(f.Sum(), 16)
	}
	return out
}

// refreshOfflineManifest recomputes fingerprints and bumps versions for
// changed sets, persisting the result to the bucket.
func refreshOfflineManifest() {
	if len(GetSellers()) == 0 && len(GetVendors()) == 0 {
		log.Println("offline: no scrapers loaded, skipping manifest refresh")
		return
	}

	start := time.Now()
	prev := offlineManifestStore.Get().Sets
	now := start.UTC().Format(time.RFC3339)

	next := offlineManifestFile{Generated: now, Sets: map[string]OfflineSetVersion{}}
	changed := 0
	for code, fp := range computeOfflineFingerprints() {
		old, found := prev[code]
		if found && old.Fingerprint == fp {
			next.Sets[code] = old
			continue
		}
		next.Sets[code] = OfflineSetVersion{Fingerprint: fp, Version: now}
		changed++
	}

	err := offlineManifestStore.Save(context.Background(), next)
	if err != nil {
		log.Println("offline: manifest save failed:", err)
		return
	}
	refreshOfflineCatalog()
	log.Printf("offline: manifest refreshed in %v, %d/%d sets changed", time.Since(start), changed, len(next.Sets))
}

// serveOfflineManifest returns per-set version strings for sync diffing.
func serveOfflineManifest(w http.ResponseWriter, r *http.Request) {
	manifest := offlineManifestStore.Get()
	sets := make(map[string]string, len(manifest.Sets))
	for code, sv := range manifest.Sets {
		sets[code] = sv.Version
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, max-age=300")
	json.NewEncoder(w).Encode(map[string]any{
		"version":   1,
		"generated": manifest.Generated,
		"catalog":   offlineCatalogVersion(),
		"sets":      sets,
	})
}
