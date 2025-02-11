package models

import (
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
	JWTSecret        []byte
	ContextTimeout   time.Duration
	RefreshInterval  time.Duration
	WebhookSecretKey string
}

func DefaultAuthConfig() *AuthConfig {
	return &AuthConfig{
		ContextTimeout:  5 * time.Second,
		RefreshInterval: 5 * time.Minute,
	}
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
