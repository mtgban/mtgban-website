// Package infrastructure holds the settings every deployment uses alike,
// filed once beside the configs rather than copied into each: the bucket
// keys, the Google and Patreon credentials, the uploader endpoints, the
// sites allowed to hand the upload a card list, and the databases. A deployment's own config can still set any of them, and its
// value wins.
package infrastructure

import (
	"cmp"
	"time"

	"github.com/mtgban/mtgban-website/timeseries"
	"github.com/mtgban/mtgban-website/userstate"
)

// Config is the infrastructure settings file, under the keys a deployment's config
// uses for the same settings.
type Config struct {
	BucketKeys        map[string]BucketKey `json:"bucket_keys,omitempty"`
	GoogleCredentials string               `json:"google_credentials,omitempty"`
	Patreon           Patreon              `json:"patreon"`
	PatreonRenewal    PatreonRenewal       `json:"patreon_renewal,omitzero"`
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

// PatreonRenewal is how the site keeps a reader's Patreon session and renews
// their signature from it. Renewal is off while AfterDays is 0.
type PatreonRenewal struct {
	// AfterDays is the age a signature reaches before the next request
	// renews it; 0 turns renewal off.
	AfterDays int `json:"after_days,omitempty"`
	// GraceDays is how long after a signature ran out its reader's cookie
	// may still renew it; 0 means never.
	GraceDays int `json:"grace_days,omitempty"`
	// MaxSessionDays caps a session from the login that made it; 0 means
	// DefaultMaxSessionDays.
	MaxSessionDays int `json:"max_session_days,omitempty"`
	// ClearOnNegative logs a reader out when Patreon says nothing is
	// pledged any more; without it that answer is treated as no answer.
	ClearOnNegative bool `json:"clear_on_negative,omitempty"`
	// RenewTimeoutSeconds bounds the Patreon calls of one renewal; 0 means
	// DefaultRenewTimeoutSeconds.
	RenewTimeoutSeconds int `json:"renew_timeout_seconds,omitempty"`
}

// DefaultMaxSessionDays is the cap MaxSessionDays 0 stands for.
const DefaultMaxSessionDays = 90

// DefaultRenewTimeoutSeconds is the wait RenewTimeoutSeconds 0 stands for.
const DefaultRenewTimeoutSeconds = 5

// After is the age at which a signature is renewed.
func (p PatreonRenewal) After() time.Duration {
	return time.Duration(p.AfterDays) * 24 * time.Hour
}

// Grace is how long after it ran out a signature may still be renewed.
func (p PatreonRenewal) Grace() time.Duration {
	return time.Duration(p.GraceDays) * 24 * time.Hour
}

// MaxSession is how long a session lasts from its login.
func (p PatreonRenewal) MaxSession() time.Duration {
	days := p.MaxSessionDays
	if days <= 0 {
		days = DefaultMaxSessionDays
	}
	return time.Duration(days) * 24 * time.Hour
}

// RenewTimeout is how long one renewal waits on Patreon.
func (p PatreonRenewal) RenewTimeout() time.Duration {
	seconds := p.RenewTimeoutSeconds
	if seconds <= 0 {
		seconds = DefaultRenewTimeoutSeconds
	}
	return time.Duration(seconds) * time.Second
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
	base.PatreonRenewal = cmp.Or(own.PatreonRenewal, base.PatreonRenewal)
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
