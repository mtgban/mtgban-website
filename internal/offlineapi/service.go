// Package offlineapi serves the offline PWA data endpoints as a
// dependency-injected service following the same pattern as internal/palette.
package offlineapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/internal/bucketstore"
	"github.com/mtgban/mtgban-website/internal/imgmirror"
	"github.com/mtgban/mtgban-website/internal/offline"
	"github.com/mtgban/simplecloud"
)

// Deps holds all main-package knowledge the service needs.
type Deps struct {
	// Allow authenticates a request and returns the caller's email.
	Allow func(r *http.Request) (email string, ok bool)

	// CanonicalSetCode returns the canonical (uppercased) set code for the
	// given input. Returns an error if the set is unknown. Main provides this
	// by wrapping mtgmatcher.GetSet; tests inject a fake so the package does
	// not need the live datastore.
	CanonicalSetCode func(setCode string) (string, error)

	// BuildSetPayload gathers and converts one set's prices for the given
	// store subset (main owns BanPrice and the getters).
	BuildSetPayload func(setCode string, stores []string) (*offline.SetPayload, error)

	// EnabledStores returns all non-blocklisted seller+vendor shorthands.
	EnabledStores func() []string

	Sellers func() []mtgban.Seller
	Vendors func() []mtgban.Vendor

	ScraperName       func(shorthand string) string
	CardObjectSources func(co *mtgmatcher.CardObject) []string

	// Bucket factories: paths are read per call so config edits are picked
	// up without rebuilding the service.
	ManifestBucket       func(ctx context.Context) (simplecloud.ReadWriter, string, error)
	ImagesManifestBucket func(ctx context.Context) (simplecloud.ReadWriter, string, error)
	// ImagesBucket returns the bucket and BASE path for the image tree.
	ImagesBucket             func(ctx context.Context) (simplecloud.ReadWriter, string, error)
	ManifestPathConfigured   func() bool
	ImagesPathConfigured     func() bool

	WatermarkSecret func() []byte

	RetailBlockList  func() []string
	BuylistBlockList func() []string
}

// Service exposes the offline API endpoints and background refresh logic.
type Service struct {
	deps          Deps
	manifestStore *bucketstore.Store[manifestFile]
	imagesStore   *bucketstore.Store[imgmirror.Manifest]
	catalog       atomic.Pointer[catalogCache]
}

// NewService constructs a Service wired to the given Deps.
func NewService(deps Deps) *Service {
	s := &Service{deps: deps}
	s.manifestStore = &bucketstore.Store[manifestFile]{
		MissingOK: true,
		Bucket:    deps.ManifestBucket,
	}
	s.imagesStore = &bucketstore.Store[imgmirror.Manifest]{
		MissingOK: true,
		Bucket:    deps.ImagesManifestBucket,
	}
	return s
}

// Handle dispatches /api/offline/ endpoints.
func (s *Service) Handle(w http.ResponseWriter, r *http.Request) {
	email, ok := s.deps.Allow(r)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "offline mode not available"})
		return
	}

	endpoint := strings.TrimPrefix(r.URL.Path, "/api/offline/")
	switch {
	case endpoint == "manifest.json":
		s.serveManifest(w, r)
	case endpoint == "catalog.json":
		s.serveCatalog(w, r)
	case strings.HasPrefix(endpoint, "prices/"):
		s.servePrices(w, r, email, strings.TrimPrefix(endpoint, "prices/"))
	case strings.HasPrefix(endpoint, "images/"):
		s.serveImage(w, r, strings.TrimPrefix(endpoint, "images/"))
	case strings.HasPrefix(endpoint, "imagebundles/"):
		s.serveImageBundle(w, r, strings.TrimPrefix(endpoint, "imagebundles/"))
	default:
		http.NotFound(w, r)
	}
}

// RefreshManifest recomputes fingerprints and bumps versions for changed sets.
// Called by cron and by scraper-load goroutines.
func (s *Service) RefreshManifest() {
	s.refreshManifest()
}

// LoadPersisted loads the offline manifest and images manifest at startup.
// Manifest load is skipped silently when ManifestPathConfigured returns false.
func (s *Service) LoadPersisted(ctx context.Context) error {
	if s.deps.ManifestPathConfigured() {
		if err := s.manifestStore.Load(ctx); err != nil {
			return err
		}
	}
	s.refreshImagesManifest()
	return nil
}
