package main

import (
	"context"
	"errors"

	"github.com/mtgban/mtgban-website/internal/imgmirror"
	"github.com/mtgban/simplecloud"
)

// Stubs replaced by the fetch pipeline task.
type crawler struct {
	state imgmirror.State
}

func newCrawler(bucket simplecloud.ReadWriter, base string, state imgmirror.State) *crawler {
	return &crawler{state: state}
}

func (c *crawler) fetchAll(ctx context.Context, uuids []string, want map[string]imgmirror.Card) error {
	return errors.New("fetch pipeline not implemented yet")
}

func rebuildBundles(ctx context.Context, bucket simplecloud.ReadWriter, base string, state imgmirror.State, want map[string]imgmirror.Card, manifest imgmirror.Manifest) error {
	return errors.New("bundle pipeline not implemented yet")
}
