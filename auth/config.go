package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Environment variable constants
const (
	EnvSupabaseURL     = "SUPABASE_URL"
	EnvSupabaseAnonKey = "SUPABASE_ANON_KEY"
	EnvSupabaseSecret  = "SUPABASE_JWT_SECRET"
	EnvRefreshInterval = "REFRESH_INTERVAL"
)

// getEnv retrieves an environment variable with an optional fallback value
func getEnv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

// getDurationEnv retrieves a duration from environment variable with a fallback
func getDurationEnv(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	duration, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return duration
}

// validate checks the configuration for validity
func (c *AuthConfig) validate() error {
	// Validate tier ACL
	for feature, tiers := range c.TierACL {
		for _, tier := range tiers {
			if !Tier(tier).IsValid() {
				return fmt.Errorf("invalid tier '%v' for feature '%s'", tier, feature)
			}
		}
	}

	// Validate role ACL
	for feature, roles := range c.RoleACL {
		for _, role := range roles {
			if !Role(role).IsValid() {
				return fmt.Errorf("invalid role '%v' for feature '%s'", role, feature)
			}
		}
	}

	// Validate feature flags
	for feature, flags := range c.FeatureFlags {
		if !Feature(feature).IsValid() {
			return fmt.Errorf("invalid feature '%v'", feature)
		}
		for flag, value := range flags {
			if value == nil {
				return fmt.Errorf("invalid flag '%v' for feature '%s'", flag, feature)
			}
		}
	}

	// Validate auth settings
	if c.SBase.SupabaseURL == "" {
		return fmt.Errorf("supabase URL must be provided")
	}

	if c.SBase.SupabaseKey == "" {
		return fmt.Errorf("supabase anonymous key must be provided")
	}

	if c.SBase.SupabaseSecret == "" {
		return fmt.Errorf("supabase JWT secret must be provided")
	}

	return nil
}

func LoadAuthConfig(data []byte) (*AuthConfig, error) {
	config := NewAuthConfig()
	if data != nil {
		if err := json.Unmarshal(data, config); err != nil {
			return nil, NewConfigError("failed to unmarshal auth config", err)
		}
	}

	// Map environment variables to settings
	envMap := map[*string]string{
		&config.SBase.SupabaseURL:    EnvSupabaseURL,
		&config.SBase.SupabaseKey:    EnvSupabaseAnonKey,
		&config.SBase.SupabaseSecret: EnvSupabaseSecret,
	}
	for setting, env := range envMap {
		if *setting == "" {
			*setting = getEnv(env, *setting)
		}
	}

	if config.SBase.RefreshInterval == 0 {
		config.SBase.RefreshInterval = getDurationEnv(EnvRefreshInterval, 24*time.Hour)
	}

	if err := config.validate(); err != nil {
		return nil, NewConfigError("invalid auth configuration", err)
	}
	return config, nil
}

// LoadDefaultAuthConfig loads the configuration with environment variables
func LoadDefaultAuthConfig() (*AuthConfig, error) {
	return LoadAuthConfig(nil)
}

// LoadAuthConfigFromJSON loads and validates the configuration from JSON data
func LoadAuthConfigFromJSON(data []byte) (*AuthConfig, error) {
	return LoadAuthConfig(data)
}

// NewAuthConfig creates a new AuthConfig with default settings
func NewAuthConfig() *AuthConfig {
	return &AuthConfig{
		RoleACL:      map[string][]Role{},
		TierACL:      map[string][]Tier{},
		FeatureFlags: map[string]map[string]interface{}{},
		SBase: AuthSettings{
			RefreshInterval: 24 * time.Hour,
			SupabaseURL:     "",
			SupabaseKey:     "",
			SupabaseSecret:  "",
		},
	}
}
