package main

import (
	"context"
	"errors"

	"github.com/mtgban/mtgban-website/internal/access"
)

// The access table and the grant list live beside the config rather than
// inside it: see internal/access. This file wires the package to what stays
// deployment-owned — the bucket openers (credentials) and the inline-config
// fallback that persists grants into the config until every deployment has
// its paths split out.

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

// loadCommonConfig fills the access table and the grant list, from their own
// paths where one is configured and from the config itself where none is.
func loadCommonConfig(ctx context.Context) error {
	return Access.Load(ctx, access.Sources{
		TablePath:      Config.ACLPath,
		GrantsPath:     Config.PatreonGrantsPath,
		FallbackTable:  Config.ACL,
		FallbackGrants: Config.Patreon.Grants,
	})
}

func saveGrants(ctx context.Context, grants []PatreonGrant) error {
	return Access.SaveGrants(ctx, grants)
}

func saveACL(ctx context.Context, table access.Table) error {
	return Access.SaveTable(ctx, table)
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
