package main

import (
	"context"
	"log"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/internal/dsreload"
)

// site is one deployment's page handlers, plus the datastore loader and
// the reload tracker.
type site struct {
	reloads dsreload.Tracker
}

// newSite builds the site a deployment serves through.
func newSite() *site {
	return &site{}
}

// datastore returns the live datastore, or the empty one before the first
// load, from the package-level pointer.
func (s *site) datastore() *datastore {
	return currentDatastore()
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
		names:    newNamesSnapshot(b.Names("canonical", false), b.Names("canonical", true)),
		editions: newEditionsSnapshot(b),
		palette:  paletteService.NewSnapshot(b),
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
	liveDatastore.Store(s.newDatastore(backend, time.Now()))

	ServerNotify("init", "Datastore installed")
	go s.cacheNewspaper()

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
		offlineService.RequestRefresh()
		return nil
	})
}
