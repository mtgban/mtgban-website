package main

import (
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// backend and currentDatastore read testSite, which TestMain loads; a test
// with a site of its own reads that site. Production code declares neither,
// and one reintroduced there would collide with these.
func backend() *mtgmatcher.Backend { return testSite.backend() }
func currentDatastore() *datastore { return testSite.datastore() }

// TestSiteDatastorePublishesAtomically checks that a site never serves a nil
// datastore, even before anything has been published to it, and that
// publishing one atomically flips every reader to the new value.
func TestSiteDatastorePublishesAtomically(t *testing.T) {
	// A private site, not testSite: this wants the state before anything at
	// all has published, which testSite left behind in TestMain.
	s := newSite()
	got := s.datastore()
	if got == nil {
		t.Fatal("datastore() returned nil before any datastore was published")
	} else if len(got.backend.GetUUIDs()) != 0 {
		t.Fatalf("empty datastore contained %d cards", len(got.backend.GetUUIDs()))
	}

	want := s.newDatastore(&mtgmatcher.Backend{}, time.Now())
	s.ds.Store(want)
	got = s.datastore()
	if got != want {
		t.Fatal("datastore() did not return the atomically published datastore")
	}
}
