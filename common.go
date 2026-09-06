package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/mtgban/mtgban-website/internal/access"
)

// The access table, the grant list and the affiliate data live beside the
// config rather than inside it: see internal/access for the first two. This
// file wires the package to what stays deployment-owned — the bucket openers
// (credentials) and the inline-config fallback that persists grants into the
// config until every deployment has its paths split out — and holds the
// affiliate data, which follows the same path-or-fallback rule but is never
// written at runtime.

// PatreonGrant keeps its historical name for the config decode and the admin
// code; the type lives with the package that manages the list.
type PatreonGrant = access.Grant

var Access = access.New(access.Hooks{
	Open:             openBucketPath,
	OpenWrite:        openBucketWriter,
	SaveTableInline:  saveACLInline,
	SaveGrantsInline: savePatreonGrantsInline,
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

// loadCommonConfig fills the access table, the grant list and the affiliate
// data, each from its own path where one is configured and from the config
// itself where none is.
func loadCommonConfig(ctx context.Context) error {
	err := Access.Load(ctx, access.Sources{
		TablePath:      Config.ACLPath,
		GrantsPath:     Config.PatreonGrantsPath,
		FallbackTable:  Config.ACL,
		FallbackGrants: Config.Patreon.Grants,
	})
	if err != nil {
		return err
	}
	return loadAffiliates(ctx)
}

// AffiliatesConfig is the affiliate data every game shares: the codes are
// the partner accounts, and a store a game doesn't carry never matches its
// list entries, so one file serves all deployments. The json keys match the
// inline config fields the value migrates out of, which makes the shared
// file the same shape as the config section it replaces.
type AffiliatesConfig struct {
	Codes       map[string]string `json:"affiliate"`
	List        []string          `json:"affiliates_list"`
	BuylistList []string          `json:"affiliates_buylist_list"`
}

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

// loadAffiliates fills the affiliate data, from its own path where one is
// configured and from the config itself where none is. A configured path
// that cannot be read is an error, not a silent fallback, and the previous
// value stays published.
func loadAffiliates(ctx context.Context) error {
	value := AffiliatesConfig{
		Codes:       Config.Affiliate,
		List:        Config.AffiliatesList,
		BuylistList: Config.AffiliatesBuylistList,
	}
	if Config.AffiliatesPath != "" {
		value = AffiliatesConfig{}
		reader, err := openBucketPath(ctx, Config.AffiliatesPath)
		if err != nil {
			return fmt.Errorf("affiliates %s: %w", Config.AffiliatesPath, err)
		}
		defer reader.Close()
		err = json.NewDecoder(reader).Decode(&value)
		if err != nil {
			return fmt.Errorf("affiliates %s: %w", Config.AffiliatesPath, err)
		}
	}
	affiliatesPtr.Store(&value)
	return nil
}

// The savers notify the peer deployments (access_notify.go) once the value
// is persisted, each on its own channel so a peer re-reads only the file
// that changed - and only when the save went to its own file, since an
// inline save rewrites this deployment's config, which no peer reads.

func saveGrants(ctx context.Context, grants []PatreonGrant) error {
	err := Access.SaveGrants(ctx, grants)
	if err != nil {
		return err
	}
	if Config.PatreonGrantsPath != "" {
		notifyAccessReload(ctx, grantsReloadChannel)
	}
	return nil
}

func saveACL(ctx context.Context, table access.Table) error {
	err := Access.SaveTable(ctx, table)
	if err != nil {
		return err
	}
	if Config.ACLPath != "" {
		notifyAccessReload(ctx, aclReloadChannel)
	}
	return nil
}

// The inline savers rewrite the config file with the new value, which is
// where both have always been written. Used only while a config still
// carries the value inline; they go away with the migration, together with
// the inline fields.

func savePatreonGrantsInline(ctx context.Context, grants []PatreonGrant) error {
	return updateInlineConfig(ctx, func(config *ConfigType) {
		config.Patreon.Grants = grants
	})
}

func saveACLInline(ctx context.Context, table access.Table) error {
	return updateInlineConfig(ctx, func(config *ConfigType) {
		config.ACL = table
	})
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

// updateInlineConfig persists a mutated copy of the config to where it was
// loaded from and publishes it on success.
func updateInlineConfig(ctx context.Context, mutate func(*ConfigType)) error {
	newConfig := Config
	mutate(&newConfig)
	if err := writeConfigTo(ctx, ConfigBucket, Config.sourcePath, newConfig); err != nil {
		return err
	}
	Config = newConfig
	return nil
}
