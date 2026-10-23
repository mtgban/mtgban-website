// Package infrastructure holds the settings every deployment uses alike,
// filed once beside the configs rather than copied into each: the bucket
// keys, the Google and Patreon credentials, the uploader endpoints, the
// sites allowed to hand the upload a card list, and the databases. A deployment's own config can still set any of them, and its
// value wins.
package infrastructure

import (
	"cmp"

	"github.com/mtgban/mtgban-website/timeseries"
	"github.com/mtgban/mtgban-website/userstate"
)

// Config is the infrastructure settings file, under the keys a deployment's config
// uses for the same settings.
type Config struct {
	BucketKeys        map[string]BucketKey `json:"bucket_keys,omitempty"`
	GoogleCredentials string               `json:"google_credentials,omitempty"`
	Patreon           Patreon              `json:"patreon"`
	Uploader          map[string]string    `json:"uploader,omitempty"`
	// HandoffOrigins maps each site allowed to hand /upload/handoff a card
	// list to how its results are headed.
	HandoffOrigins        map[string]HandoffOrigin `json:"handoff_origins,omitempty"`
	SQLConfig             *timeseries.SQLConfig    `json:"sql_config,omitempty"`
	UserStateConfig       *userstate.SQLConfig     `json:"user_state_config,omitempty"`
	ObservabilityConfig   *timeseries.SQLConfig    `json:"observability_config,omitempty"`
	NewNewspaperSQLConfig *timeseries.SQLConfig    `json:"new_newspaper_sql_config,omitempty"`
}

// HandoffOrigin is how the results of a list one handoff origin sent are
// headed.
type HandoffOrigin struct {
	// Name heads the results; empty heads them with the host.
	Name string `json:"name,omitempty"`
	// Seller is the path segment the origin's URLs name a seller after, as
	// "Users" in Cardmarket's /<language>/<Game>/Users/<seller>/Offers/...
	// The seller is added to the heading; empty names none.
	Seller string `json:"seller,omitempty"`
}

// BucketKey is a B2 application key pair scoped to a single bucket, keyed by
// bucket name in Config.BucketKeys.
type BucketKey struct {
	AccessKey    string `json:"access_key"`
	AccessSecret string `json:"access_secret"`
}

// Patreon is the OAuth client each Patreon source signs in through.
type Patreon struct {
	Source string            `json:"source"`
	Client map[string]string `json:"client"`
	Secret map[string]string `json:"secret"`
}

// Over returns base with every key own sets replaced by own's, whole: a
// deployment overrides a key by setting it in its config, and inherits
// it by leaving it out.
func (own Config) Over(base Config) Config {
	if own.BucketKeys != nil {
		base.BucketKeys = own.BucketKeys
	}
	base.GoogleCredentials = cmp.Or(own.GoogleCredentials, base.GoogleCredentials)
	if own.Patreon.Source != "" || own.Patreon.Client != nil || own.Patreon.Secret != nil {
		base.Patreon = own.Patreon
	}
	if own.Uploader != nil {
		base.Uploader = own.Uploader
	}
	if own.HandoffOrigins != nil {
		base.HandoffOrigins = own.HandoffOrigins
	}
	base.SQLConfig = cmp.Or(own.SQLConfig, base.SQLConfig)
	base.UserStateConfig = cmp.Or(own.UserStateConfig, base.UserStateConfig)
	base.ObservabilityConfig = cmp.Or(own.ObservabilityConfig, base.ObservabilityConfig)
	base.NewNewspaperSQLConfig = cmp.Or(own.NewNewspaperSQLConfig, base.NewNewspaperSQLConfig)
	return base
}
