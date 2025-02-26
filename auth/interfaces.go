package auth

import (
	"context"
	"time"

	postgrest "github.com/supabase-community/postgrest-go"
)

// SupabaseClient is a wrapper around the postgrest.QueryBuilder
// It provides a way to interact with the database
type SupabaseClient interface {
	From(table string) *postgrest.QueryBuilder
}

// UserRepo defines the interface for the user repository within the auth service
// It provides methods to interact with the user data stored in the database
type UserRepo interface {
	// GetSubscribedUsers retrieves all users who are subscribed to a product
	// Returns a slice of all subscribed users or an error if the operation fails
	GetSubscribedUsers(ctx context.Context) ([]UserData, error)

	// GetUserByID retrieves a user by their ID
	GetUserByID(ctx context.Context, id string) (*UserData, error)

	// GetAllUserIDs retrieves all user IDs
	GetAllUserIDs(ctx context.Context) ([]string, error)
}

// Cache interface defines the methods for the user cache system.
// it provides basic CRUD operations for UserData objects.
type Cache interface {
	// Basic CRUD operations
	GetAllUsers() map[string]*UserData
	GetUser(userID string) (*UserData, error)
	SetUser(user *UserData) error
	DeleteUser(userID string) error

	// Metadata operations
	GetLastModified(userID string) time.Time
	GetLastSync() time.Time
	UpdateLastSync()

	// Context operations
	GetUserFromContext(ctx context.Context) (*UserData, error)

	// Data loading and refresh operations
	LoadInitialData(ctx context.Context, repo UserRepo) error
	ForceRefresh(ctx context.Context, repo UserRepo)

	// Lifecycle operations
	Shutdown(ctx context.Context) error
}

// AuthProvider defines the interface for the authentication service
type AuthProvider interface {
	// Authentication
	IsAuthenticated(user *UserData) bool
	GetUserFromContext(ctx context.Context) (*UserData, error)
	GetUser(ctx context.Context, userID string) (*UserData, error)

	// Authorization
	CanAccessFeature(user *UserData, feature Feature) bool
	GetFeatureFlags(user *UserData, feature Feature) map[string]string
	GetFeatureFlag(user *UserData, feature Feature, flagName string) string
	IsFeatureFlagEnabled(user *UserData, feature Feature, flagName string) bool

	// User features management
	GetUserFeatures(ctx context.Context, userID string) (map[string]map[string]map[string]string, error)
	UpdateUserFeatures(ctx context.Context, userID string, features map[string]map[string]map[string]string) error

	// UI integration
	ApplyAuthVarsToPageVars(user *UserData, pageVars map[string]interface{})

	// Lifecycle management
	LoadInitialData(ctx context.Context) error
	RefreshCache(ctx context.Context) error
	Shutdown(ctx context.Context) error
}
