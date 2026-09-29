package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"slices"
	"sync/atomic"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/go-mtgban/tcgplayer"
	"github.com/mtgban/mtgban-website/internal/dsreload"
	"github.com/mtgban/mtgban-website/internal/offline"
	"github.com/mtgban/mtgban-website/internal/offlineapi"
	"github.com/mtgban/mtgban-website/internal/palette"
	"github.com/mtgban/mtgban-website/internal/suggest"
	"github.com/mtgban/simplecloud"
)

// site is one deployment: the live datastore, its page handlers and jobs,
// the palette and offline services they read, the datastore loader and the
// reload tracker.
type site struct {
	ds      atomic.Pointer[datastore]
	palette *palette.Service
	offline *offlineapi.Service
	reloads dsreload.Tracker

	// fetchLastSold is how the Discord $$ lookup fetches a printing's recent
	// sales: getLastSold, held here so a test can answer in its place.
	fetchLastSold func(ctx context.Context, b *mtgmatcher.Backend, cardID string, anyLang bool) ([]tcgplayer.LatestSalesData, error)
}

// newSite builds the services a deployment serves through. It runs at
// startup, before any datastore has loaded, so every hook below reads the
// site's current datastore at call time rather than now.
func newSite() *site {
	s := &site{fetchLastSold: getLastSold}

	// Pre-stored before the first load, so s.ds is never nil: nil numbers,
	// names and palette keep the pre-load answers scan, 204 and no-store.
	s.ds.Store(&datastore{
		backend:  &mtgmatcher.Backend{},
		editions: &editionsSnapshot{},
	})

	s.palette = &palette.Service{
		Backend:      s.backend,
		PromoAliases: func() map[string]string { return isKnownPromo },
		FinishLabel:  finishListLabel,
		FinishNames:  finishNames,
		Snapshot:     func() *palette.Snapshot { return s.datastore().palette },

		Sellers: GetSellers,
		Vendors: GetVendors,
	}

	s.offline = offlineapi.NewService(offlineapi.Deps{
		Datastore: func() (*mtgmatcher.Backend, time.Time) {
			ds := s.datastore()
			return ds.backend, ds.loadedAt
		},
		Allow: offlineModeAllowed,

		CanonicalSetCode: func(b *mtgmatcher.Backend, setCode string) (string, error) {
			set, err := b.GetSet(setCode)
			if err != nil {
				return "", err
			}
			return set.Code, nil
		},

		BuildSetPayload: func(b *mtgmatcher.Backend, setCode string, stores []string) (*offline.SetPayload, error) {
			set, err := b.GetSet(setCode)
			if err != nil {
				return nil, err
			}
			retail := getSellerPrices(b, "", stores, set.Code, nil, "", true, true, false, "")
			buylist := getVendorPrices(b, "", stores, set.Code, nil, "", true, true, false, "")
			for id, m := range getSellerPrices(b, "", stores, set.Code, nil, "", true, true, true, "") {
				if retail[id] == nil {
					retail[id] = m
					continue
				}
				for store, entry := range m {
					retail[id][store] = entry
				}
			}
			for id, m := range getVendorPrices(b, "", stores, set.Code, nil, "", true, true, true, "") {
				if buylist[id] == nil {
					buylist[id] = m
					continue
				}
				for store, entry := range m {
					buylist[id][store] = entry
				}
			}
			return banprice2offline(set.Code, time.Now().UTC(), retail, buylist), nil
		},

		EnabledStores: func() []string {
			var all []string
			for _, seller := range GetSellers() {
				shorthand := seller.Info().Shorthand
				if !slices.Contains(Config.SearchRetailBlockList, shorthand) && !slices.Contains(all, shorthand) {
					all = append(all, shorthand)
				}
			}
			for _, vendor := range GetVendors() {
				shorthand := vendor.Info().Shorthand
				if !slices.Contains(Config.SearchBuylistBlockList, shorthand) && !slices.Contains(all, shorthand) {
					all = append(all, shorthand)
				}
			}
			return all
		},

		Sellers: GetSellers,
		Vendors: GetVendors,

		ScraperName:       scraperName,
		CardObjectSources: cardobject2sources,
		FinishNames:       finishNames,
		Finishes:          s.palette.FinishList,

		ManifestBucket: func(ctx context.Context) (simplecloud.ReadWriter, string, error) {
			omPath := Config.Offline.ManifestPath
			if omPath == "" {
				return nil, "", errors.New("offline.manifest_path not configured")
			}
			u, err := url.Parse(omPath)
			if err != nil {
				return nil, "", err
			}
			switch {
			case u.Scheme == "" || len(u.Scheme) == 1:
				return &simplecloud.FileBucket{}, omPath, nil
			case u.Scheme == "b2":
				bucket, err := newB2ClientFor(ctx, u.Host)
				return bucket, omPath, err
			default:
				return nil, "", fmt.Errorf("unsupported offline manifest path scheme: %s", u.Scheme)
			}
		},

		ImagesManifestBucket: func(ctx context.Context) (simplecloud.ReadWriter, string, error) {
			bucket, base, err := offlineImagesFactory(ctx)
			if err != nil {
				return nil, "", err
			}
			return bucket, offlineapi.JoinBucketPath(base, "images-manifest.json"), nil
		},

		ImagesBucket: offlineImagesFactory,

		ImagesDownloadAuth: offlineImagesDownloadAuth,

		Game: func() mtgmatcher.Game { return Config.Game },

		ManifestPathConfigured: func() bool { return Config.Offline.ManifestPath != "" },
		ImagesPathConfigured:   func() bool { return Config.Offline.ImagesPath != "" },

		WatermarkSecret: func() []byte { return []byte(os.Getenv("BAN_SECRET")) },

		RetailBlockList:  func() []string { return Config.SearchRetailBlockList },
		BuylistBlockList: func() []string { return Config.SearchBuylistBlockList },
	})

	return s
}

// datastore returns the live datastore. Never nil: newSite pre-stores the
// empty one above, and loadDatastore is the only thing that replaces it.
func (s *site) datastore() *datastore {
	return s.ds.Load()
}

func (s *site) backend() *mtgmatcher.Backend {
	return s.datastore().backend
}

// newDatastore builds every derived snapshot from b; an empty backend gives
// empty snapshots.
func (s *site) newDatastore(b *mtgmatcher.Backend, loadedAt time.Time) *datastore {
	return &datastore{
		backend:  b,
		numbers:  newNumbersSnapshot(b),
		names:    suggest.NewNames(b.Names(mtgmatcher.NameFormCanonical, false), b.Names(mtgmatcher.NameFormCanonical, true)),
		editions: newEditionsSnapshot(b),
		palette:  s.palette.NewSnapshot(b),
		loadedAt: loadedAt,
	}
}

// Bucket serving the datastore and any other file living alongside it,
// created once at startup
func (s *site) loadDatastore(path string) error {
	log.Println("Loading datastore from", path)

	reader, err := openBucketPath(context.Background(), path)
	if err != nil {
		return err
	}
	defer reader.Close()

	// LoadDatastore would read the file whole and try every registered loader.
	backend, err := mtgmatcher.Open(datastoreGame(), reader)
	if err != nil {
		return err
	}
	// Build every derived snapshot - including the palette lists - before
	// publishing: one read of the datastore gives the backend and the
	// snapshots of the same load.
	s.ds.Store(s.newDatastore(backend, time.Now()))

	ServerNotify("init", "Datastore installed")

	// The reload tracker recovers this load, not a goroutine it starts.
	go func() {
		defer recoverJob("datastore load cacheNewspaper")
		s.cacheNewspaper()
	}()
	// TCGplayer's listing counts wait for a datastore to match them to.
	go func() {
		defer recoverJob("datastore load loadTCGListings")
		s.loadTCGListings()
	}()

	return nil
}

// startDatastoreReload loads the datastore in the background, reporting
// whether this call is the one that started it. See dsreload.Tracker.Start.
//
// The path is all it takes: openBucketPath reads the backend off the scheme,
// so a datastore and a backup living in different places are the same call.
func (s *site) startDatastoreReload(path, source string) bool {
	return s.reloads.Start(source, path, func() error {
		err := s.loadDatastore(path)
		if err != nil {
			return err
		}
		// What the endpoint used to do once the load returned. The offline
		// manifest is derived from the datastore, so a reload that leaves it
		// alone leaves it describing the previous one; the admin action never
		// asked for the refresh at all, and now does.
		ServerNotify("reload", "Datastore reloaded from "+path)
		s.offline.RequestRefresh()
		return nil
	})
}
