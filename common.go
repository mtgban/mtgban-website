package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/mtgban/mtgban-website/internal/access"
)

// The access table, the grant list, the affiliate data and the chart
// datasets live beside the config rather than inside it, each in its own
// file: see internal/access for the first two. This file wires the package to
// what stays deployment-owned - the bucket openers (credentials) - and holds
// the affiliate data and the datasets, which are read and written the same
// way.

// PatreonGrant keeps its historical name for the config decode and the admin
// code; the type lives with the package that manages the list.
type PatreonGrant = access.Grant

var Access = access.New(access.Hooks{
	Open:      openBucketPath,
	OpenWrite: openBucketWriter,
})

// ACL returns the tier -> feature -> option table this deployment enforces.
// The result is shared and must not be modified.
func ACL() access.Table {
	return Access.Table()
}

// PatreonGrants returns the current grant list. The result is shared and must
// not be modified; build a new slice and hand it to saveGrants instead.
func PatreonGrants() []PatreonGrant {
	return Access.Grants()
}

// loadCommonConfig fills the access table, the grant list, the affiliate
// data and the chart datasets, each from its own path. One failing does not
// stop the others loading.
func loadCommonConfig(ctx context.Context) error {
	err := Access.Load(ctx, access.Sources{
		TablePath:  Config().ACLPath,
		GrantsPath: Config().PatreonGrantsPath,
	})
	return errors.Join(err, loadAffiliates(ctx), loadDatasets(ctx))
}

// AffiliatesConfig is the affiliate data every game shares: the codes are
// the partner accounts, and a store a game doesn't carry never matches its
// list entries, so one file serves all deployments.
type AffiliatesConfig struct {
	Codes       map[string]string `json:"affiliate"`
	List        []string          `json:"affiliates_list"`
	BuylistList []string          `json:"affiliates_buylist_list"`
}

// affiliatesMu serialises the writers (loadAffiliates, saveAffiliates);
// readers go through the atomic and never block.
var affiliatesMu sync.Mutex
var affiliatesPtr atomic.Pointer[AffiliatesConfig]

// Affiliates returns the current affiliate data. The result is shared and
// must not be modified.
func Affiliates() AffiliatesConfig {
	value := affiliatesPtr.Load()
	if value == nil {
		return AffiliatesConfig{}
	}
	return *value
}

// loadAffiliates fills the affiliate data from its own path. A configured
// path that cannot be read is an error, not a silent fallback, and the
// previous value stays published.
func loadAffiliates(ctx context.Context) error {
	affiliatesMu.Lock()
	defer affiliatesMu.Unlock()

	if Config().AffiliatesPath == "" {
		return errors.New("affiliates: no path configured")
	}

	var value AffiliatesConfig
	reader, err := openBucketPath(ctx, Config().AffiliatesPath)
	if err != nil {
		return fmt.Errorf("affiliates %s: %w", Config().AffiliatesPath, err)
	}
	defer reader.Close()
	err = json.NewDecoder(reader).Decode(&value)
	if err != nil {
		return fmt.Errorf("affiliates %s: %w", Config().AffiliatesPath, err)
	}
	affiliatesPtr.Store(&value)
	return nil
}

// saveAffiliates persists the affiliate data to its shared file and
// publishes it on success, following the savers below.
func saveAffiliates(ctx context.Context, value AffiliatesConfig) error {
	affiliatesMu.Lock()
	defer affiliatesMu.Unlock()

	if Config().AffiliatesPath == "" {
		return errors.New("affiliates: no path configured")
	}

	writer, err := openBucketWriter(ctx, Config().AffiliatesPath)
	if err != nil {
		return err
	}
	err = json.NewEncoder(writer).Encode(value)
	// Close finalises the upload, so its error is the write's error too, and
	// a failure there must not be reported as a save.
	cerr := writer.Close()
	if err != nil {
		return err
	}
	if cerr != nil {
		return cerr
	}
	affiliatesPtr.Store(&value)
	notifyAccessReload(ctx, affiliatesReloadChannel)
	return nil
}

// datasetsMu serialises the writers (loadDatasets, saveDatasets); readers go
// through the atomic and never block.
var datasetsMu sync.Mutex
var datasetsPtr atomic.Pointer[[]DatasetConfig]

// Datasets returns the chart datasets: the datasets_path file's when the
// config names one, else timeseries_config.datasets. The result is shared and
// must not be modified.
func Datasets() []DatasetConfig {
	if Config().DatasetsPath == "" {
		return Config().TimeseriesConfig.Datasets
	}
	value := datasetsPtr.Load()
	if value == nil {
		return nil
	}
	return *value
}

// loadDatasets reads the chart datasets from datasets_path, when the config
// names one, and rebuilds the chart providers from them. A configured path
// that cannot be read is an error, and the previous value stays published.
func loadDatasets(ctx context.Context) error {
	datasetsMu.Lock()
	defer datasetsMu.Unlock()

	path := Config().DatasetsPath
	if path == "" {
		return nil
	}
	reader, err := openBucketPath(ctx, path)
	if err != nil {
		return fmt.Errorf("datasets %s: %w", path, err)
	}
	defer reader.Close()
	var value []DatasetConfig
	err = json.NewDecoder(reader).Decode(&value)
	if err != nil {
		return fmt.Errorf("datasets %s: %w", path, err)
	}
	datasetsPtr.Store(&value)
	buildProviderRegistry()
	return nil
}

// saveDatasets persists the chart datasets to datasets_path and publishes
// them on success, following saveAffiliates.
func saveDatasets(ctx context.Context, value []DatasetConfig) error {
	datasetsMu.Lock()
	defer datasetsMu.Unlock()

	path := Config().DatasetsPath
	if path == "" {
		return errors.New("datasets: no path configured")
	}

	writer, err := openBucketWriter(ctx, path)
	if err != nil {
		return err
	}
	err = json.NewEncoder(writer).Encode(value)
	cerr := writer.Close()
	if err != nil {
		return err
	}
	if cerr != nil {
		return cerr
	}
	datasetsPtr.Store(&value)
	buildProviderRegistry()
	notifyAccessReload(ctx, datasetsReloadChannel)
	return nil
}

// The savers notify the peer deployments (access_notify.go) once the value
// is persisted, each on its own channel so a peer re-reads only the file
// that changed.

func saveGrants(ctx context.Context, grants []PatreonGrant) error {
	err := Access.SaveGrants(ctx, grants)
	if err != nil {
		return err
	}
	if Config().PatreonGrantsPath != "" {
		notifyAccessReload(ctx, grantsReloadChannel)
	}
	return nil
}

func saveACL(ctx context.Context, table access.Table) error {
	err := Access.SaveTable(ctx, table)
	if err != nil {
		return err
	}
	if Config().ACLPath != "" {
		notifyAccessReload(ctx, aclReloadChannel)
	}
	return nil
}

// validateACLTable refuses tables that would obviously lock the site out: an
// empty table grants nothing to anyone, and a table where no tier carries
// Admin could not be fixed from the admin page again.
func validateACLTable(table access.Table) error {
	if len(table) == 0 {
		return errors.New("table is empty")
	}
	for _, features := range table {
		if _, found := features["Admin"]; found {
			return nil
		}
	}
	return errors.New("no tier grants Admin, which would lock the admin page out")
}
