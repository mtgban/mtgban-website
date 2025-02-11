package models

import (
	"encoding/json"
	"fmt"
	"time"
)

type contextKey struct {
	name string
}

func (k contextKey) String() string {
	return "cache key:" + k.name
}

var UserContextKey = contextKey{
	name: UserData{}.ID,
}

type UserData struct {
	ID         string    `json:"id"`
	Role       UserRole  `json:"role"`
	Status     string    `json:"status"`
	Email      string    `json:"email"`
	CreatedAt  time.Time `json:"created_at"`
	LastSignIn time.Time `json:"last_sign_in"`
}

type WebhookPayload struct {
	Type      string                 `json:"type"`
	Table     string                 `json:"table"`
	Record    map[string]interface{} `json:"record"`
	OldRecord map[string]interface{} `json:"old_record,omitempty"`
}

type AuthConfig struct {
	ACL          map[string]UserRole                     `json:"acl"`
	FeatureFlags map[string]map[string]map[string]string `json:"feature_flags"`
	Auth         struct {
		ContextTimeout   time.Duration `json:"context_timeout"`
		RefreshInterval  time.Duration `json:"refresh_interval"`
		WebhookSecretKey string        `json:"webhook_secret_key"`
	} `json:"auth"`
}

type AuthError struct {
	Code    int
	Message string
	Err     error
}

func (e *AuthError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func LoadAuthConfigFromJSON(data []byte) (*AuthConfig, error) {
	var config AuthConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal auth config: %w", err)
	}

	for feature, role := range config.ACL {
		if !role.IsValid() {
			return nil, fmt.Errorf("invalid role '%s' for feature '%s'", role, feature)
		}
	}

	if config.Auth.ContextTimeout > 0 {
		if _, err := time.ParseDuration(config.Auth.ContextTimeout.String()); err != nil {
			return nil, fmt.Errorf("invalid context timeout: %w", err)
		}
	}

	if config.Auth.RefreshInterval > 0 {
		if _, err := time.ParseDuration(fmt.Sprintf("%dms", config.Auth.RefreshInterval)); err != nil {
			return nil, fmt.Errorf("invalid refresh interval: %w", err)
		}
	}

	return &config, nil
}
