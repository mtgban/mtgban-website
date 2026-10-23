package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/mtgban/mtgban-website/internal/access"
	"github.com/mtgban/mtgban-website/internal/infrastructure"
	"github.com/mtgban/mtgban-website/timeseries"
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

// loadCommonConfig fills the infrastructure, the access table, the
// grant list, the affiliate data and the chart datasets, each from its own
// path. The infrastructure goes first, since its bucket keys may be
// what the others are read with; one failing does not stop the others.
func loadCommonConfig(ctx context.Context) error {
	infrastructureErr := loadInfrastructure(ctx)
	err := Access.Load(ctx, access.Sources{
		TablePath:  Config().ACLPath,
		GrantsPath: Config().PatreonGrantsPath,
	})
	return errors.Join(infrastructureErr, err, loadAffiliates(ctx), loadDatasets(ctx))
}

// infrastructurePtr holds the infrastructure_path file as last read or
// saved; readers go through the atomic and never block.
var infrastructurePtr atomic.Pointer[infrastructure.Config]

// infrastructureFile returns the infrastructure_path file as last read or
// saved, empty when the config names none. The result is shared and must not
// be modified.
func infrastructureFile() infrastructure.Config {
	value := infrastructurePtr.Load()
	if Config().InfrastructurePath == "" || value == nil {
		return infrastructure.Config{}
	}
	return *value
}

// Infrastructure returns the infrastructure settings this deployment uses:
// the infrastructure_path file's, with every key its own config sets in place
// of the file's. The result is shared and must not be modified.
func Infrastructure() infrastructure.Config {
	return Config().Config.Over(infrastructureFile())
}

// loadInfrastructure reads the infrastructure_path file, when the config
// names one. A path that cannot be read is an error, and the previous value
// stays published.
func loadInfrastructure(ctx context.Context) error {
	path := Config().InfrastructurePath
	if path == "" {
		return nil
	}
	reader, err := openBucketPath(ctx, path)
	if err != nil {
		return fmt.Errorf("infrastructure %s: %w", path, err)
	}
	defer reader.Close()
	var value infrastructure.Config
	err = json.NewDecoder(reader).Decode(&value)
	if err != nil {
		return fmt.Errorf("infrastructure %s: %w", path, err)
	}
	infrastructurePtr.Store(&value)
	return nil
}

// saveInfrastructure writes the infrastructure_path file, publishes it, and
// tells the peers to reload it, unless validateInfrastructure refuses it
// against the file as last read or saved.
func saveInfrastructure(ctx context.Context, value infrastructure.Config) error {
	path := Config().InfrastructurePath
	if path == "" {
		return errors.New("infrastructure: no path configured")
	}
	err := validateInfrastructure(value, infrastructureFile())
	if err != nil {
		return err
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
	infrastructurePtr.Store(&value)
	notifyAccessReload(ctx, infrastructureReloadChannel)
	return nil
}

// validateInfrastructure refuses a file that takes from every peer what
// running, the file it replaces, gives them: a bucket key (B2 refuses the
// next load), a Patreon client or secret (login breaks), or a database's
// settings (a restart opens none).
// Dropping one of those is an edit to the file itself, not the editor's.
// It also refuses a handoff origin that handoffOrigins would leave out.
func validateInfrastructure(value, running infrastructure.Config) error {
	var problems []string
	for _, origin := range slices.Sorted(maps.Keys(value.HandoffOrigins)) {
		if !validHandoffOrigin(origin) {
			problems = append(problems, "handoff origin "+origin+" is not a bare https scheme and host")
		}
	}
	for _, name := range slices.Sorted(maps.Keys(running.BucketKeys)) {
		key := value.BucketKeys[name]
		if key.AccessKey == "" || key.AccessSecret == "" {
			problems = append(problems, "drops the bucket key for "+name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(running.Patreon.Client)) {
		if value.Patreon.Client[name] == "" {
			problems = append(problems, "drops the Patreon client for "+name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(running.Patreon.Secret)) {
		if value.Patreon.Secret[name] == "" {
			problems = append(problems, "drops the Patreon secret for "+name)
		}
	}
	for _, db := range []struct {
		key            string
		running, value *timeseries.SQLConfig
	}{
		{"sql_config", running.SQLConfig, value.SQLConfig},
		{"user_state_config", running.UserStateConfig, value.UserStateConfig},
		{"observability_config", running.ObservabilityConfig, value.ObservabilityConfig},
		{"new_newspaper_sql_config", running.NewNewspaperSQLConfig, value.NewNewspaperSQLConfig},
	} {
		if !emptySQLConfig(db.running) && emptySQLConfig(db.value) {
			problems = append(problems, "empties "+db.key)
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func emptySQLConfig(config *timeseries.SQLConfig) bool {
	return config == nil || *config == (timeseries.SQLConfig{})
}

// infrastructureRestartKeys names the keys that differ between before and
// after among those read only at startup (main.go): the database clients,
// the NOTIFY listener and the Google client. The bucket keys, Patreon and
// the uploader are read on every use, so they apply as soon as published.
func infrastructureRestartKeys(before, after infrastructure.Config) []string {
	var keys []string
	for _, db := range []struct {
		key           string
		before, after *timeseries.SQLConfig
	}{
		{"sql_config", before.SQLConfig, after.SQLConfig},
		{"user_state_config", before.UserStateConfig, after.UserStateConfig},
		{"observability_config", before.ObservabilityConfig, after.ObservabilityConfig},
		{"new_newspaper_sql_config", before.NewNewspaperSQLConfig, after.NewNewspaperSQLConfig},
	} {
		if !sameSQLConfig(db.before, db.after) {
			keys = append(keys, db.key)
		}
	}
	if before.GoogleCredentials != after.GoogleCredentials {
		keys = append(keys, "google_credentials")
	}
	return keys
}

func sameSQLConfig(a, b *timeseries.SQLConfig) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
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

// Datasets returns the chart datasets read from datasets_path, none when the
// config names no file. The result is shared and must not be modified.
func Datasets() []DatasetConfig {
	value := datasetsPtr.Load()
	if Config().DatasetsPath == "" || value == nil {
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
// empty table grants nothing to anyone, an option set to an empty string
// locks out its tier, and a table where no tier carries Admin could not be
// fixed from the admin page again.
func validateACLTable(table access.Table) error {
	if len(table) == 0 {
		return errors.New("table is empty")
	}
	for tier, features := range table {
		if feature, key, found := emptyOption(features); found {
			return fmt.Errorf("tier %s sets %s.%s to an empty string; remove the key, or use none for AlertChannels", tier, feature, key)
		}
	}
	for _, features := range table {
		if _, found := features["Admin"]; found {
			return nil
		}
	}
	return errors.New("no tier grants Admin, which would lock the admin page out")
}

// emptyOption finds an option set to an empty string. Signing keeps it but
// verification drops it, so every signed page of whoever carries it fails.
func emptyOption(features map[string]map[string]string) (feature, key string, found bool) {
	for feature, options := range features {
		for key, val := range options {
			if val == "" {
				return feature, key, true
			}
		}
	}
	return "", "", false
}
