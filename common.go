package main

import (
	"context"

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
	Open:       openBucketPath,
	OpenWrite:  openBucketWriter,
	SaveInline: savePatreonGrantsInline,
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

// savePatreonGrantsInline rewrites the config file with the new grant list,
// which is where the admin page has always written it. Used only while a
// config still carries its grants inline; goes away with the migration,
// together with both inline fields.
func savePatreonGrantsInline(ctx context.Context, grants []PatreonGrant) error {
	newConfig := Config
	newConfig.Patreon.Grants = grants
	if err := writeConfigTo(ctx, ConfigBucket, Config.sourcePath, newConfig); err != nil {
		return err
	}
	Config = newConfig
	return nil
}
