// Package offlineapi serves the offline PWA data endpoints as a
// dependency-injected service following the same pattern as internal/palette.
package offlineapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/internal/bucketstore"
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

	// Game names the card game this deployment serves. It decides how image
	// keys are derived, because Magic's mirror keys on the scryfall id while
	// every other game keys on the card's own datastore uuid. Nil or empty
	// means Magic, which is what a deployment that never set it is.
	Game func() string

	// Bucket factories: paths are read per call so config edits are picked
	// up without rebuilding the service.
	ManifestBucket       func(ctx context.Context) (simplecloud.ReadWriter, string, error)
	ImagesManifestBucket func(ctx context.Context) (simplecloud.ReadWriter, string, error)
	// ImagesBucket returns the bucket and BASE path for the image tree.
	ImagesBucket func(ctx context.Context) (simplecloud.ReadWriter, string, error)
	// ImagesDownloadAuth issues a time-limited authorization to read the image
	// tree straight from the bucket: the base URL objects hang off, a token to
	// present with it, and when that stops working. Nil where the backing store
	// cannot issue one, which leaves clients with no way to sync images.
	ImagesDownloadAuth     func(ctx context.Context, valid time.Duration) (base, token string, expires time.Time, err error)
	ManifestPathConfigured func() bool
	ImagesPathConfigured   func() bool

	WatermarkSecret func() []byte

	RetailBlockList  func() []string
	BuylistBlockList func() []string

	// LastDatastoreUpdate reports when the card data was last replaced, so
	// the catalog can reuse the half derived from it. Nil rebuilds every
	// time, which is what a caller that does not track this would want.
	LastDatastoreUpdate func() time.Time
}

// Service exposes the offline API endpoints and background refresh logic.
type Service struct {
	deps          Deps
	manifestStore *bucketstore.Store[manifestFile]
	imagesStore   *bucketstore.Store[ImagesManifest]
	catalog       atomic.Pointer[catalogCache]
	// fragments caches the catalog's datastore half. Only refreshCatalog
	// touches it, under the mutex refreshManifest already holds.
	fragments *catalogFragments
	// refreshSignal wakes the background refresher; buffered so RequestRefresh
	// never blocks and bursts coalesce.
	refreshSignal chan struct{}
	mu            sync.Mutex
}

// NewService constructs a Service wired to the given Deps.
func NewService(deps Deps) *Service {
	s := &Service{deps: deps}
	s.manifestStore = &bucketstore.Store[manifestFile]{
		MissingOK: true,
		Bucket:    deps.ManifestBucket,
	}
	s.imagesStore = &bucketstore.Store[ImagesManifest]{
		MissingOK: true,
		Bucket:    deps.ImagesManifestBucket,
	}
	s.refreshSignal = make(chan struct{}, 1)
	return s
}

// magicImageKeys reports whether this deployment's images are filed under
// scryfall ids rather than datastore uuids.
func (s *Service) magicImageKeys() bool {
	if s.deps.Game == nil {
		return true
	}
	game := s.deps.Game()
	return game == "" || game == "magic"
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
	case endpoint == "bucket-auth":
		s.serveBucketAuth(w, r)
	default:
		http.NotFound(w, r)
	}
}

// RefreshManifest recomputes fingerprints and bumps versions for changed sets.
// Startup calls it directly; runtime triggers go through RequestRefresh.
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
