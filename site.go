package main

import (
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// site is one deployment's page handlers.
type site struct{}

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
