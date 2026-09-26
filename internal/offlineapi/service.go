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
	"github.com/mtgban/mtgban-website/internal/palette"
	"github.com/mtgban/simplecloud"
)

// Deps holds all main-package knowledge the service needs.
type Deps struct {
	// Datastore returns the current card datastore and when it was loaded,
	// together: a catalog refresh reads this once so the cards it marshals
	// and the source time it keys them on describe the same load.
	Datastore func() (*mtgmatcher.Backend, time.Time)
	// Allow authenticates a request and returns the caller's email.
	Allow func(r *http.Request) (email string, ok bool)

	// CanonicalSetCode returns the canonical (uppercased) set code for the
	// given input, matched against b. Returns an error if the set is
	// unknown. Main provides this by wrapping mtgmatcher.GetSet; tests
	// inject a fake so the package does not need the live datastore.
	CanonicalSetCode func(b *mtgmatcher.Backend, setCode string) (string, error)

	// BuildSetPayload gathers and converts one set's prices for the given
	// store subset, matched against b (main owns BanPrice and the getters).
	BuildSetPayload func(b *mtgmatcher.Backend, setCode string, stores []string) (*offline.SetPayload, error)

	// EnabledStores returns all non-blocklisted seller+vendor shorthands.
	EnabledStores func() []string

	Sellers func() []mtgban.Seller
	Vendors func() []mtgban.Vendor

	ScraperName       func(shorthand string) string
	CardObjectSources func(co *mtgmatcher.CardObject) []string

	// FinishNames are the names f: reaches a card by, and Finishes the list
	// the palette offers them in. The catalog carries both, so f: and its
	// menu work offline too. Finishes takes the same backend the catalog
	// refresh already read, rather than reading its own.
	FinishNames func(co *mtgmatcher.CardObject) []string
	Finishes    func(b *mtgmatcher.Backend) []palette.Finish

	// Game names the card game this deployment serves. It decides how image
	// keys are derived, because Magic's mirror keys on the scryfall id while
	// every other game keys on the card's TCGplayer product. Nil or empty
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
}

// datastore reads the live backend and its load time together. A nil hook
// or nil backend reads as an empty datastore, which never equals a later
// real load, so it just rebuilds every time.
func (s *Service) datastore() (*mtgmatcher.Backend, time.Time) {
	if s.deps.Datastore == nil {
		return &mtgmatcher.Backend{}, time.Time{}
	}
	b, t := s.deps.Datastore()
	if b == nil {
		return &mtgmatcher.Backend{}, time.Time{}
	}
	return b, t
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
// scryfall ids rather than datastore products.
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
