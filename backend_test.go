package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

func TestBackendPublishesAndRestoresAtomically(t *testing.T) {
	saved := matcherBackend.Load()
	t.Cleanup(func() { matcherBackend.Store(saved) })

	matcherBackend.Store(nil)
	if got := backend(); got == nil {
		t.Fatal("backend() returned nil before the datastore was published")
	} else if len(got.GetUUIDs()) != 0 {
		t.Fatalf("empty backend contained %d cards", len(got.GetUUIDs()))
	}

	want := &mtgmatcher.Backend{}
	matcherBackend.Store(want)
	if got := backend(); got != want {
		t.Fatal("backend() did not return the atomically published backend")
	}
}
