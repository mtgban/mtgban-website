package main

import (
	"github.com/mtgban/go-mtgban/matcher"
)

// backend and currentDatastore read testSite, which TestMain loads; a test
// with a site of its own reads that site. Production code declares neither,
// and one reintroduced there would collide with these.
func backend() *matcher.Backend    { return testSite.backend() }
func currentDatastore() *datastore { return testSite.datastore() }
