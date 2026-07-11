package offlineapi

import (
	"context"
	"encoding/json"
	"log"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/internal/offline"
)

// setVersion records when a set's canonical data last changed.
type setVersion struct {
	Fingerprint string `json:"fp"`
	Version     string `json:"v"`
}

type manifestFile struct {
	Generated string                `json:"generated"`
	Sets      map[string]setVersion `json:"sets"`
}

// computeFingerprints hashes every in-memory price tuple, per set.
func (s *Service) computeFingerprints() map[string]string {
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

	for _, seller := range s.deps.Sellers() {
		shorthand := seller.Info().Shorthand
		for uuid, entries := range seller.Inventory() {
			for _, e := range entries {
				add(shorthand, uuid, e.Conditions, e.Price, e.Quantity)
			}
		}
	}
	for _, vendor := range s.deps.Vendors() {
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

// refreshManifest recomputes fingerprints and bumps versions for changed sets,
// persisting the result to the bucket.
func (s *Service) refreshManifest() {
	if len(s.deps.Sellers()) == 0 && len(s.deps.Vendors()) == 0 {
		log.Println("offline: no scrapers loaded, skipping manifest refresh")
		return
	}

	start := time.Now()
	prev := s.manifestStore.Get().Sets
	now := start.UTC().Format(time.RFC3339)

	next := manifestFile{Generated: now, Sets: map[string]setVersion{}}
	changed := 0
	for code, fp := range s.computeFingerprints() {
		old, found := prev[code]
		if found && old.Fingerprint == fp {
			next.Sets[code] = old
			continue
		}
		next.Sets[code] = setVersion{Fingerprint: fp, Version: now}
		changed++
	}

	s.refreshCatalog()
	s.refreshImagesManifest()

	err := s.manifestStore.Save(context.Background(), next)
	if err != nil {
		log.Println("offline: manifest save failed:", err)
		return
	}
	log.Printf("offline: manifest refreshed in %v, %d/%d sets changed", time.Since(start), changed, len(next.Sets))
}

// serveManifest returns per-set version strings for sync diffing.
func (s *Service) serveManifest(w http.ResponseWriter, r *http.Request) {
	manifest := s.manifestStore.Get()
	sets := make(map[string]string, len(manifest.Sets))
	for code, sv := range manifest.Sets {
		sets[code] = sv.Version
	}
	doc := map[string]any{
		"version":   1,
		"generated": manifest.Generated,
		"catalog":   s.catalogVersion(),
		"sets":      sets,
	}
	if images := s.imagesStore.Get(); len(images) > 0 {
		doc["images"] = images
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, max-age=300")
	json.NewEncoder(w).Encode(doc)
}
