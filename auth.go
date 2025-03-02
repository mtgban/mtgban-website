package 

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	postgrest "github.com/supabase-community/postgrest-go"
)

// ====================================================================
// CONSTANTS AND VARIABLES
// ====================================================================

// Context Keys
type ContextKey string

func (k ContextKey) String() string {
	return "cache key:" + string(k)
}

const (
	UserContextKey ContextKey = "user"   // User ID
	RoleContextKey ContextKey = "role"   // Administrative Role
	TierContextKey ContextKey = "tier"   // Subscription Tier
	PageAccessKey  ContextKey = "access" // Page Access
	PermissionsKey ContextKey = "permissions"
)

// Environment variable constants
const (
	EnvSupabaseURL     = "SUPABASE_URL"
	EnvSupabaseAnonKey = "SUPABASE_ANON_KEY"
	EnvSupabaseSecret  = "SUPABASE_JWT_SECRET"
	EnvRefreshInterval = "REFRESH_INTERVAL"
)

// Webhook constants
const (
	maxWebhookBodySize = 1 << 20 // 1MB limit
	webhookTimeout     = 30 * time.Second
)

// Cache errors
var (
	ErrEntryExpired = fmt.Errorf("cache entry has expired")
	ErrInvalidInput = fmt.Errorf("invalid input parameters")
	ErrCacheFull    = fmt.Errorf("cache has reached maximum capacity")
)

// ====================================================================
// INTERFACES
// ====================================================================

// SupabaseClient is a wrapper around the postgrest.QueryBuilder
// It provides a way to interact with the database
type SupabaseClient interface {
	From(table string) *postgrest.QueryBuilder
}

type User interface {
	FromData(data *UserData) (User, error)
	FromContext(ctx context.Context) (User, error)
	FromToken(token string) (User, error)
	FromRequest(r *http.Request) (User, error)
	GetId() (string, error)
	GetEmail() (string, error)
	GetRole() (Role, error)
	GetTier() (Tier, error)
	GetStatus() (Status, error)
	GetFeatures() (FeatureFlags, error)
	HasAccess(resource string) bool
	GetAccess() (role Role, tier Tier, features FeatureFlags)
	GetPreferences() (preferences []string)
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

	// GetUserFeatures retrieves the features for a user by their ID
	GetUserFeatures(ctx context.Context, userID string) (map[string]string, error)
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
	GetUser(ctx context.Context, userID string) (*UserData, error)

	// Authorization
	CanAccessFeature(user *UserData, feature Feature) bool
	GetFeatureFlags(user *UserData, feature Feature) map[string]string
	GetFeatureFlag(user *UserData, feature Feature, flagName string) string
	IsFeatureFlagEnabled(user *UserData, feature Feature, flagName string) bool

	// User features management
	UpdateUserFeatures(ctx context.Context, userID string, features map[string]map[string]map[string]string) error

	// UI integration
	ApplyAuthVarsToPageVars(user *UserData, pageVars map[string]interface{})

	// Lifecycle management
	LoadInitialData(ctx context.Context) error
	RefreshCache(ctx context.Context) error
	Shutdown(ctx context.Context) error
}

// AuthFlags interface for user permissions
type AuthFlags interface {
	CanShowAll() bool
	CanDownloadCSV() bool
	IsOneDay() bool
	CanBuylist() bool
	CanChangeStores() bool
	CanFilterByPrice() bool
	CanFilterByPercentage() bool

	GetUserID() string
	GetUserEmail() string
	GetUserTier() *Tier
	GetUserRole() *Role
}

// ====================================================================
// ERROR TYPES
// ====================================================================

// ConfigError represents configuration validation errors
type ConfigError struct {
	Code    int
	Message string
	Err     error
}

func (e *ConfigError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// NewConfigError creates a new ConfigError
func NewConfigError(message string, err error) *ConfigError {
	return &ConfigError{
		Code:    400,
		Message: message,
		Err:     err,
	}
}

// CacheError represents general cache operation errors
type CacheError struct {
	Code    int    // HTTP status code
	Message string // Human readable error message
	Err     error  // Underlying error if any
	Op      string // Operation that failed
	Details string // Additional error context
}

// Error returns a formatted error message with operation and details
func (e *CacheError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("cache %s failed: %s - %v [%s]", e.Op, e.Message, e.Err, e.Details)
	}
	return fmt.Sprintf("cache %s failed: %s [%s]", e.Op, e.Message, e.Details)
}

// NewCacheError creates a new CacheError with operation context
func NewCacheError(code int, op string, message string, details string, err error) *CacheError {
	return &CacheError{
		Code:    code,
		Message: message,
		Err:     err,
		Op:      op,
		Details: details,
	}
}

// CacheNotFoundError represents when a cache lookup fails
type CacheNotFoundError struct {
	Key     string // Cache key that was not found
	CacheID string // Identifier for which cache was queried
}

func (e *CacheNotFoundError) Error() string {
	return fmt.Sprintf("key '%s' not found in cache '%s'", e.Key, e.CacheID)
}

// KeyNotFoundError represents when a specific key lookup fails
type KeyNotFoundError struct {
	Key      string // The key that was not found
	Resource string // The resource type being looked up
	Err      error  // Original error if any
}

func (e *KeyNotFoundError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s with key '%s' not found: %v", e.Resource, e.Key, e.Err)
	}
	return fmt.Sprintf("%s with key '%s' not found", e.Resource, e.Key)
}

// NewKeyNotFoundError creates a new KeyNotFoundError
func NewKeyNotFoundError(resource string, key string, err error) *KeyNotFoundError {
	return &KeyNotFoundError{
		Key:      key,
		Resource: resource,
		Err:      err,
	}
}

// AuthError represents authentication-related errors with detailed context
type AuthError struct {
	Code      int    // HTTP status code
	Message   string // Human readable error message
	Operation string // Operation that failed (e.g. "token validation", "role check")
	RequestID string // Request ID for tracing
	UserID    string // User ID if available
	Err       error  // Underlying error
}

// Error returns a detailed error message with context
func (e *AuthError) Error() string {
	base := fmt.Sprintf("[%d] %s failed: %s", e.Code, e.Operation, e.Message)
	if e.UserID != "" {
		base += fmt.Sprintf(" (UserID: %s)", e.UserID)
	}
	if e.RequestID != "" {
		base += fmt.Sprintf(" [RequestID: %s]", e.RequestID)
	}
	if e.Err != nil {
		base += fmt.Sprintf(" - caused by: %v", e.Err)
	}
	return base
}

// NewAuthError creates a new AuthError with full context
func NewAuthError(code int, op string, message string, reqID string, userID string, err error) *AuthError {
	return &AuthError{
		Code:      code,
		Operation: op,
		Message:   message,
		RequestID: reqID,
		UserID:    userID,
		Err:       err,
	}
}

// UnauthorizedError represents a 401 Unauthorized error with token details
type UnauthorizedError struct {
	Message   string
	TokenType string // e.g. "Bearer", "API Key"
	TokenHint string // First few chars of token for debugging
	RequestID string
	Err       error
}

// Error returns detailed token error information
func (e *UnauthorizedError) Error() string {
	msg := fmt.Sprintf("Unauthorized - %s", e.Message)
	if e.TokenType != "" {
		msg += fmt.Sprintf(" (TokenType: %s", e.TokenType)
		if e.TokenHint != "" {
			msg += fmt.Sprintf(", Hint: %s...)", e.TokenHint)
		} else {
			msg += ")"
		}
	}
	if e.RequestID != "" {
		msg += fmt.Sprintf(" [RequestID: %s]", e.RequestID)
	}
	if e.Err != nil {
		msg += fmt.Sprintf(" - %v", e.Err)
	}
	return msg
}

// NewUnauthorizedError creates a new UnauthorizedError
func NewUnauthorizedError(message string, tokenType string, tokenHint string, reqID string, err error) *UnauthorizedError {
	return &UnauthorizedError{
		Message:   message,
		TokenType: tokenType,
		TokenHint: tokenHint,
		RequestID: reqID,
		Err:       err,
	}
}

// ForbiddenError represents a 403 Forbidden error with role context
type ForbiddenError struct {
	Message      string
	UserID       string
	CurrentRole  string
	RequiredRole string
	Resource     string
	RequestID    string
	Err          error
}

// Error returns detailed access denied information
func (e *ForbiddenError) Error() string {
	msg := fmt.Sprintf("Forbidden - %s", e.Message)
	if e.UserID != "" {
		msg += fmt.Sprintf(" (UserID: %s", e.UserID)
		if e.CurrentRole != "" && e.RequiredRole != "" {
			msg += fmt.Sprintf(", Current Role: %s, Required: %s)", e.CurrentRole, e.RequiredRole)
		} else {
			msg += ")"
		}
	}
	if e.Resource != "" {
		msg += fmt.Sprintf(" - Attempted access to: %s", e.Resource)
	}
	if e.RequestID != "" {
		msg += fmt.Sprintf(" [RequestID: %s]", e.RequestID)
	}
	if e.Err != nil {
		msg += fmt.Sprintf(" - %v", e.Err)
	}
	return msg
}

// NewForbiddenError creates a ForbiddenError with role context
func NewForbiddenError(message string, userID string, currentRole string, requiredRole string, resource string, reqID string, err error) *ForbiddenError {
	return &ForbiddenError{
		Message:      message,
		UserID:       userID,
		CurrentRole:  currentRole,
		RequiredRole: requiredRole,
		Resource:     resource,
		RequestID:    reqID,
		Err:          err,
	}
}

// MissingRequiredRoleError represents a missing required role error
type MissingRequiredRoleError struct {
	Message      string
	UserID       string
	CurrentRole  string
	RequiredRole string
	RequestID    string
	Err          error
}

// Error returns detailed missing role information
func (e *MissingRequiredRoleError) Error() string {
	msg := fmt.Sprintf("Access Denied - %s", e.Message)
	if e.UserID != "" {
		msg += fmt.Sprintf(" (UserID: %s, Current Role: %s, Required: %s)",
			e.UserID, e.CurrentRole, e.RequiredRole)
	}
	if e.RequestID != "" {
		msg += fmt.Sprintf(" [RequestID: %s]", e.RequestID)
	}
	if e.Err != nil {
		msg += fmt.Sprintf(" - %v", e.Err)
	}
	return msg
}

// NewMissingRequiredRoleError creates a new MissingRequiredRoleError
func NewMissingRequiredRoleError(message string, userID string, currentRole string, requiredRole string, reqID string, err error) *MissingRequiredRoleError {
	return &MissingRequiredRoleError{
		Message:      message,
		UserID:       userID,
		CurrentRole:  currentRole,
		RequiredRole: requiredRole,
		RequestID:    reqID,
		Err:          err,
	}
}

// ====================================================================
// MODELS
// ====================================================================

type AccessType string

const (
	RoleAccess    AccessType = "role"
	TierAccess    AccessType = "tier"
	FeatureAccess AccessType = "feature"
	APIAccess     AccessType = "api"
)

//
// Role System - Administrative Permissions
//

type Role string

// Roles grant permissions without the need for a subscription.
const (
	RoleRoot      Role = "root"
	RoleAdmin     Role = "admin"
	RoleModerator Role = "moderator"
	RoleDeveloper Role = "developer"
	RoleLostBoy   Role = "lostboy"
)

// AllRoles returns a slice of all valid roles
func AllRoles() []Role {
	return []Role{
		RoleRoot,
		RoleAdmin,
		RoleModerator,
		RoleDeveloper,
		RoleLostBoy,
	}
}

// IsValid verifies the role is legit
func (r Role) IsValid() bool {
	validRoles := []Role{
		RoleRoot,
		RoleAdmin,
		RoleModerator,
		RoleDeveloper,
		RoleLostBoy,
	}
	return slices.Contains(validRoles, r)
}

// String returns string representation
func (r Role) String() string {
	return string(r)
}

// Tier System - Subscription-based Features
type Tier string

// Tiers grant permissions at the subscription level.
// A user may only have one tier at a time.
const (
	TierFree    Tier = "free"
	TierPioneer Tier = "pioneer"
	TierModern  Tier = "modern"
	TierLegacy  Tier = "legacy"
	TierVintage Tier = "vintage"
	TierAPI     Tier = "api"
)

func AllTiers() []Tier {
	tiers := make([]Tier, 0, len(TierConfig))
	for tier := range TierConfig {
		tiers = append(tiers, tier)
	}
	return tiers
}

// TierProperties defines properties for each tier
type TierProperties struct {
	Subscribed bool   // Whether this tier requires a subscription
	Hierarchy  []Tier // Lower tiers this tier has access to
}

// TierConfig defines the configuration for all tiers
var TierConfig = map[Tier]TierProperties{
	TierFree:    {Subscribed: false, Hierarchy: []Tier{}},
	TierAPI:     {Subscribed: true, Hierarchy: []Tier{}},
	TierPioneer: {Subscribed: true, Hierarchy: []Tier{TierFree}},
	TierModern:  {Subscribed: true, Hierarchy: []Tier{TierFree, TierPioneer}},
	TierLegacy:  {Subscribed: true, Hierarchy: []Tier{TierFree, TierPioneer, TierModern}},
	TierVintage: {Subscribed: true, Hierarchy: []Tier{TierFree, TierPioneer, TierModern, TierLegacy}},
}

// Mapping from product names to tiers
var productTierMap = map[string]Tier{
	"pioneer": TierPioneer,
	"modern":  TierModern,
	"legacy":  TierLegacy,
	"vintage": TierVintage,
	"api":     TierAPI,
}

// String returns the string representation of the tier
func (t Tier) String() string {
	return string(t)
}

// FromProductName converts a product name to a tier
func FromProductName(productName string) Tier {
	normalized := strings.ToLower(strings.TrimSpace(productName))
	if tier, exists := productTierMap[normalized]; exists {
		return tier
	}
	return TierFree
}

// IsValid checks if this is a valid tier
func (t Tier) IsValid() bool {
	_, exists := TierConfig[t]
	return exists || t == ""
}

//
// Features - Application Pages/Functionality
//

// Feature represents a high-level application feature (typically a page)
type Feature string

// Application features (pages/sections)
const (
	search    Feature = "Search"
	newspaper Feature = "Newspaper"
	sleepers  Feature = "Sleepers"
	upload    Feature = "Upload"
	global    Feature = "Global"
	arbitrage Feature = "Arbitrage"
	reverse   Feature = "Reverse"
	admin     Feature = "Admin"
)

// AllFeatures returns a list of all features
func AllFeatures() []Feature {
	return []Feature{
		search,
		newspaper,
		sleepers,
		upload,
		global,
		arbitrage,
		reverse,
		admin,
	}
}

// HandlerPermission defines permission structure for a specific handler
type HandlerPermission struct {
	Flags []string `json:"flags,omitempty"`
	Level string   `json:"level,omitempty"`
}

// AccessGroup defines a group of permissions (for a role or tier)
type AccessGroup struct {
	Features []string                     `json:"features"`
	Handlers map[string]HandlerPermission `json:"handlers"`
}

// ACLConfig defines the complete access control configuration
type ACLConfig struct {
	Roles map[string]AccessGroup `json:"roles"`
	Tiers map[string]AccessGroup `json:"tiers"`
}

// UserPermissions represents computed permissions for a user
type UserPermissions struct {
	UserId      string
	AccessMap   map[string]bool   // Quick lookup for handler access by name
	FlagValues  map[string]string // Computed flag values
	LevelValues map[string]string // Computed access levels (e.g., news levels)
}

// HandlerRegistry maps handler names to actual handler functions
type HandlerRegistry struct {
	handlerFuncs map[string]http.HandlerFunc
	logger       *log.Logger
}

// NewHandlerRegistry creates a new handler registry
func NewHandlerRegistry(logger *log.Logger) *HandlerRegistry {
	if logger == nil {
		logger = log.New(os.Stdout, "[HANDLER] ", log.LstdFlags)
	}

	return &HandlerRegistry{
		handlerFuncs: make(map[string]http.HandlerFunc),
		logger:       logger,
	}
}

// RegisterHandler adds a handler to the registry
func (hr *HandlerRegistry) RegisterHandler(name string, handler http.HandlerFunc) {
	hr.handlerFuncs[name] = handler
	hr.logger.Printf("Registered handler: %s", name)
}

// GetHandler retrieves a handler by name
func (hr *HandlerRegistry) GetHandler(name string) (http.HandlerFunc, bool) {
	handler, exists := hr.handlerFuncs[name]
	return handler, exists
}

// LoadACLConfig loads and parses the ACL configuration from a file
func LoadACLConfig(filepath string) (*ACLConfig, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("reading ACL config file: %w", err)
	}

	var config ACLConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing ACL config: %w", err)
	}

	return &config, nil
}

// ComputeUserPermissions calculates all permissions for a user based on their role and tier
func ComputeUserPermissions(userData *UserData, config *ACLConfig, registry *HandlerRegistry) *UserPermissions {
	perms := &UserPermissions{
		UserId:      userData.ID,
		AccessMap:   make(map[string]bool),
		FlagValues:  make(map[string]string),
		LevelValues: make(map[string]string),
	}

	// Apply tier permissions first (base permissions)
	if userData.Tier != "" {
		if tierAccess, exists := config.Tiers[string(userData.Tier)]; exists {
			applyAccessGroup(perms, tierAccess, registry)
		}
	}

	// Apply role permissions second (can override tier permissions)
	if userData.Role != nil {
		if roleAccess, exists := config.Roles[string(*userData.Role)]; exists {
			applyAccessGroup(perms, roleAccess, registry)
		}
	}

	// Apply any user-specific feature flags last (highest precedence)
	if userData.Features != nil {
		for flagName, flagValue := range userData.Features {
			perms.FlagValues[flagName] = flagValue
		}
	}

	return perms
}

// applyAccessGroup applies permissions from an access group to a user
func applyAccessGroup(perms *UserPermissions, group AccessGroup, registry *HandlerRegistry) {
	// Apply base features
	for _, feature := range group.Features {
		perms.FlagValues["has_"+feature] = "true"
	}

	// Apply handler-specific permissions
	for handlerName, handlerPerm := range group.Handlers {
		_, exists := registry.GetHandler(handlerName)
		if !exists {
			continue
		}

		// Apply flags
		for _, flag := range handlerPerm.Flags {
			parts := strings.Split(flag, ":")
			if len(parts) == 2 {
				perms.FlagValues[parts[0]] = parts[1]
			}
		}

		// Apply levels
		if handlerPerm.Level != "" {
			perms.LevelValues[handlerName] = handlerPerm.Level
		}

		// Compute handler access
		perms.AccessMap[handlerName] = computeHandlerAccess(handlerName, handlerPerm, perms)
	}
}

// computeHandlerAccess determines if a user has access to a specific handler
func computeHandlerAccess(handlerName string, perm HandlerPermission, perms *UserPermissions) bool {
	// Check if user has base feature access
	if perms.FlagValues["has_"+handlerName] != "true" {
		return false
	}

	// Check level requirements
	if perm.Level != "" {
		userLevel := perms.LevelValues[handlerName]
		if !isLevelSufficient(userLevel, perm.Level) {
			return false
		}
	}

	// Check flag requirements (if any explicit denials exist)
	for _, flag := range perm.Flags {
		parts := strings.Split(flag, ":")
		if len(parts) != 2 {
			continue
		}

		flagName := parts[0]
		requiredValue := parts[1]

		// Special handling for explicit denial flags
		if strings.HasSuffix(flagName, "Disabled") && requiredValue == "ALL" {
			return false
		}
	}

	return true
}

// isLevelSufficient compares access levels (e.g., 0day > 1day > 3day)
func isLevelSufficient(userLevel, requiredLevel string) bool {
	levels := map[string]int{
		"0day": 3,
		"1day": 2,
		"3day": 1,
	}

	userValue := levels[userLevel]
	reqValue := levels[requiredLevel]

	return userValue >= reqValue
}

// PermissionHandler wraps the auth handler to check precomputed permissions
type PermissionHandler struct {
	authHandler *AuthHandler
	registry    *HandlerRegistry
	aclConfig   *ACLConfig
	logger      *log.Logger
}

// NewPermissionHandler creates a new permission-aware handler
func NewPermissionHandler(
	authHandler *AuthHandler,
	registry *HandlerRegistry,
	aclConfig *ACLConfig,
	logger *log.Logger,
) *PermissionHandler {
	if logger == nil {
		logger = log.New(os.Stdout, "[PERM-HANDLER] ", log.LstdFlags)
	}

	return &PermissionHandler{
		authHandler: authHandler,
		registry:    registry,
		aclConfig:   aclConfig,
		logger:      logger,
	}
}

// ProtectWithPermissions protects a handler with precomputed permissions check
func (h *PermissionHandler) ProtectWithPermissions(
	handlerName string,
	handler http.HandlerFunc,
) http.Handler {
	// Register the handler in the registry if not already registered
	h.registry.RegisterHandler(handlerName, handler)

	// Create a wrapper handler that checks permissions
	wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get user from context (set by auth middleware)
		userID, ok := r.Context().Value(UserContextKey).(string)
		if !ok {
			http.Error(w, "Unauthorized - no user in context", http.StatusUnauthorized)
			return
		}

		// Get full user data
		ctx := r.Context()
		userData, err := h.authHandler.authService.GetUserByID(ctx, userID)
		if err != nil {
			h.logger.Printf("Failed to get user %s: %v", userID, err)
			http.Error(w, "Unauthorized - invalid user", http.StatusUnauthorized)
			return
		}

		// Compute permissions
		perms := ComputeUserPermissions(userData, h.aclConfig, h.registry)

		// Check if handler is accessible
		if !perms.AccessMap[handlerName] {
			h.logger.Printf("Access denied for user %s to handler %s", userID, handlerName)
			http.Error(w, "Forbidden - insufficient permissions", http.StatusForbidden)
			return
		}

		// Add permissions to context for downstream handlers
		ctx = context.WithValue(ctx, "permissions", perms)

		// Call the handler
		handler.ServeHTTP(w, r.WithContext(ctx))
	})

	// Apply token authentication before permission check
	return h.authHandler.ProtectedHandler(wrappedHandler) // Just require authentication
}

// GetFlagValue gets a flag value for a handler from permissions
func GetFlagValue(r *http.Request, flagName string) string {
	perms, ok := r.Context().Value("permissions").(*UserPermissions)
	if !ok {
		return ""
	}
	return perms.FlagValues[flagName]
}

// GetLevel gets a level value for a handler from permissions
func GetLevel(r *http.Request, handlerName string) string {
	perms, ok := r.Context().Value("permissions").(*UserPermissions)
	if !ok {
		return ""
	}
	return perms.LevelValues[handlerName]
}

// HasFeature checks if a user has access to a feature
func HasFeature(r *http.Request, featureName string) bool {
	perms, ok := r.Context().Value("permissions").(*UserPermissions)
	if !ok {
		return false
	}
	return perms.FlagValues["has_"+featureName] == "true"
}

// IsValid checks if this is a valid feature
func (f Feature) IsValid() bool {
	return slices.Contains(AllFeatures(), f) || f == ""
}

//
// Subscription Status
//

type Status string

const (
	StatusActive    Status = "active"
	StatusInactive  Status = "inactive"
	StatusCancelled Status = "cancelled"
)

//
// Feature Flags
//

// FeatureFlags is a type alias for feature flags map
type FeatureFlags map[string]string

// Typealias for All or None
type AllOrNone string

const (
	All  AllOrNone = "ALL"
	None AllOrNone = "NONE"
)

// Typealias for News Version
type NewsVersion string

const (
	Day0 NewsVersion = "0day"
	Day1 NewsVersion = "1day"
	Day3 NewsVersion = "3day"
)

// Features represents the application features that can be enabled or disabled
type Features struct {
	// Search Features
	SearchDisabled        AllOrNone `json:"search_disabled"`         // "ALL", "NONE"
	SearchBuylistDisabled AllOrNone `json:"search_buylist_disabled"` // "ALL", "NONE"
	CanDownloadCSV        bool      `json:"can_download_csv"`
	CanFilterByPrice      bool      `json:"can_filter_by_price"`
	ShowSealedYP          bool      `json:"show_sealed_yp"`

	// Arbitrage Features
	ArbitEnabled         AllOrNone `json:"arbit_enabled"`          // "ALL", "NONE"
	ArbitDisabledVendors AllOrNone `json:"arbit_disabled_vendors"` // "ALL", "NONE"
	GlobalArbitrage      bool      `json:"global_arbitrage"`

	// Upload Features
	CanBuylist      bool `json:"can_buylist"`
	CanChangeStores bool `json:"can_change_stores"`
	HasOptimizer    bool `json:"has_optimizer"`
	NoUploadLimit   bool `json:"no_upload_limit"`

	// News Features
	NewsAccess   NewsVersion `json:"news_access"` // "0day", "1day", "3day"
	CanSwitchDay bool        `json:"can_switch_day"`

	// Premium Features
	CanFilterByPercentage bool `json:"can_filter_by_percentage"`
	HasSleepers           bool `json:"has_sleepers"`
	ExperimentsEnabled    bool `json:"experiments_enabled"`
	AnyEnabled            bool `json:"any_enabled"`
}

// UserData represents a complete user record with roles, tier, and features
type UserData struct {
	ID       string            `json:"id"`
	Email    string            `json:"email"`
	Role     *Role             `json:"role"`     // Administrative role (pointer to allow nil)
	Tier     Tier              `json:"tier"`     // Subscription tier
	Status   Status            `json:"status"`   // Subscription status
	Features map[string]string `json:"features"` // Feature flags
}

// UserImpl is a concrete implementation of the User interface
type user struct {
	data *UserData
}

func (u *user) User(data *UserData) User {
	return &user{data: data}
}

func (u *user) FromContext(ctx context.Context) (User, error) {
	return u, nil
}

func (u *user) FromToken(token string) (User, error) {
	return u, nil
}

func (u *user) FromRequest(r *http.Request) (User, error) {
	return u, nil
}

func (u *user) GetId() (string, error) {
	return u.data.ID, nil
}

func (u *user) GetEmail() (string, error) {
	return u.data.Email, nil
}

func (u *user) GetRole() (Role, error) {
	if u.data.Role == nil {
		return "", fmt.Errorf("no role set")
	}
	return *u.data.Role, nil
}

func (u *user) GetTier() (Tier, error) {
	return u.data.Tier, nil
}

func (u *user) GetStatus() (Status, error) {
	return u.data.Status, nil
}

func (u *user) GetFeatures() (FeatureFlags, error) {
	return u.data.Features, nil
}

func (u *user) FromData(data *UserData) (User, error) {
	return &user{data: data}, nil
}

func (u *user) HasAccess(resource string) bool {
	// Try as Role
	if role := Role(resource); role.IsValid() {
		return u.hasRoleAccess(role)
	}

	// Try as Tier
	if tier := Tier(resource); tier.IsValid() {
		return u.hasTierAccess(tier)
	}

	// Try as Feature
	if feature := Feature(resource); feature.IsValid() {
		hasAccess, _ := u.hasFeatureAccess(feature)
		return hasAccess
	}

	return false
}

func (u *user) GetAccess() (role Role, tier Tier, features FeatureFlags) {
	if u.data.Role != nil {
		role = *u.data.Role
	}
	return role, u.data.Tier, u.data.Features
}

func (u *user) GetPreferences() []string {
	return nil // TODO: Implement if needed
}

// hasRoleAccess checks if the user's role grants access to page/resource
func (u *user) hasRoleAccess(requiredRole Role) bool {
	// no role, no access
	if u.data.Role == nil {
		return false
	}

	// Direct match
	if *u.data.Role == requiredRole {
		return true
	}

	// Admin role has access to everything
	if *u.data.Role == RoleAdmin {
		return true
	}

	return false
}

// hasTierAccess checks if the user's tier has access to the required tier
func (u *user) hasTierAccess(requiredTier Tier) bool {
	// no tier, no access
	if u.data.Tier == "" {
		return false
	}

	// Direct match
	if u.data.Tier == requiredTier {
		return true
	}

	// Check tier hierarchy
	props, exists := TierConfig[u.data.Tier]
	if !exists {
		return false
	}
	return slices.Contains(props.Hierarchy, requiredTier)
}

// hasFeatureAccess checks if the user has access to a specific feature
func (u *user) hasFeatureAccess(requiredFeature Feature) (bool, map[string]map[string]string) {
	if u.data.Features == nil {
		return false, nil
	}
	for feature, value := range u.data.Features {
		if feature == string(requiredFeature) {
			// Convert string value to nested map structure
			return true, map[string]map[string]string{
				feature: {"value": value},
			}
		}
	}
	return false, nil
}

// GetFeature gets a feature flag value from the user's features
func (u *user) GetFeature(category, feature, setting string) string {
	if u.data.Features == nil {
		return ""
	}
	return u.data.Features[category]
}

// Configuration Types
//

// AuthConfig holds the complete authorization configuration
type AuthConfig struct {
	ACL      map[string]map[string]interface{} `json:"acl"`
	DBConfig AuthSettings                      `json:"db"`
}

// AuthSettings contains authentication configuration
type AuthSettings struct {
	RefreshInterval time.Duration `json:"refresh_interval"`
	SupabaseURL     string        `json:"supabase_url"`
	SupabaseKey     string        `json:"supabase_key"`
	SupabaseSecret  string        `json:"supabase_secret"`
}

// Webhook Types
type WebhookPayload struct {
	Type      string                 `json:"type"`
	Table     string                 `json:"table"`
	Record    map[string]interface{} `json:"record"`
	OldRecord map[string]interface{} `json:"old_record,omitempty"`
}

// CopyMatchingFields copies all matching fields from source to destination using reflection
func CopyMatchingFields(source, destination interface{}) {
	sourceVal := reflect.ValueOf(source)
	destVal := reflect.ValueOf(destination)

	// Ensure we're working with pointers to structs
	if sourceVal.Kind() != reflect.Ptr || destVal.Kind() != reflect.Ptr {
		return // Both must be pointers
	}

	sourceVal = sourceVal.Elem()
	destVal = destVal.Elem()

	if sourceVal.Kind() != reflect.Struct || destVal.Kind() != reflect.Struct {
		return // Both must be structs
	}

	// Iterate over the fields in the source struct
	sourceType := sourceVal.Type()
	for i := 0; i < sourceVal.NumField(); i++ {
		sourceField := sourceType.Field(i)

		// Skip unexported fields
		if sourceField.PkgPath != "" {
			continue
		}

		sourceFieldName := sourceField.Name
		sourceFieldValue := sourceVal.Field(i)

		// Look for matching field in destination struct
		destFieldValue := destVal.FieldByName(sourceFieldName)

		// Check if the field exists and can be set
		if destFieldValue.IsValid() && destFieldValue.CanSet() {
			// Handle direct type matches
			if sourceFieldValue.Type().AssignableTo(destFieldValue.Type()) {
				destFieldValue.Set(sourceFieldValue)
				continue
			}

			// Handle pointer-to-non-pointer conversions
			if destFieldValue.Kind() != reflect.Ptr &&
				sourceFieldValue.Kind() == reflect.Ptr &&
				!sourceFieldValue.IsNil() {
				sourceElem := sourceFieldValue.Elem()
				if sourceElem.Type().AssignableTo(destFieldValue.Type()) {
					destFieldValue.Set(sourceElem)
				}
				continue
			}

			// Handle non-pointer-to-pointer conversions
			if destFieldValue.Kind() == reflect.Ptr &&
				sourceFieldValue.Kind() != reflect.Ptr {
				if sourceFieldValue.Type().AssignableTo(destFieldValue.Type().Elem()) {
					// Create a new pointer of the right type
					newPtr := reflect.New(destFieldValue.Type().Elem())
					// Set its value
					newPtr.Elem().Set(sourceFieldValue)
					// Set the pointer field
					destFieldValue.Set(newPtr)
				}
				continue
			}
		}
	}
}

// Auth options and vars
type AuthOptions struct {
	UserName                  string
	UserEmail                 string
	UserTier                  string
	SearchDisabled            string
	SearchBuylistDisabled     string
	SearchDownloadCSV         string
	ArbitEnabled              string
	ArbitDisabledVendors      string
	NewsEnabled               string
	UploadBuylistEnabled      string
	UploadChangeStoresEnabled string
	UploadOptimizer           string
	UploadNoLimit             string
	AnyEnabled                string
	AnyExperimentsEnabled     string
	APImode                   string
}

// pageVars holds variables for page rendering
type AuthVars struct {
	CanShowAll            bool
	CanDownloadCSV        bool
	IsOneDay              bool
	GlobalMode            bool
	ReverseMode           bool
	CanFilterByPrice      bool
	CanFilterByPercentage bool
	CanBuylist            bool
	CanChangeStores       bool

	// User info
	UserID    string
	UserEmail string
	UserTier  *Tier
	UserRole  *Role
}

// ====================================================================
// CONFIGURATION
// ====================================================================

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
	// Validate auth settings first
	if c.DBConfig.SupabaseURL == "" {
		return fmt.Errorf("supabase URL must be provided")
	}
	if c.DBConfig.SupabaseKey == "" {
		return fmt.Errorf("supabase anonymous key must be provided")
	}
	if c.DBConfig.SupabaseSecret == "" {
		return fmt.Errorf("supabase JWT secret must be provided")
	}

	// Validate ACL structure exists
	if c.ACL == nil {
		return fmt.Errorf("ACL configuration is required")
	}

	return nil
}

func LoadAuthConfig(filepath *string) (*AuthConfig, error) {
	if filepath == nil {
		fmt.Println("No filepath provided, using default config")
		return NewAuthConfig(), nil
	}

	data, err := os.ReadFile(*filepath)
	if err != nil {
		return nil, NewConfigError("failed to read auth config file", err)
	}

	return loadAuthConfig(data)
}

func loadAuthConfig(data []byte) (*AuthConfig, error) {
	config := NewAuthConfig()
	if data != nil {
		if err := json.Unmarshal(data, config); err != nil {
			return nil, NewConfigError("failed to unmarshal auth config", err)
		}
	}

	// Map environment variables to settings
	envMap := map[*string]string{
		&config.DBConfig.SupabaseURL:    EnvSupabaseURL,
		&config.DBConfig.SupabaseKey:    EnvSupabaseAnonKey,
		&config.DBConfig.SupabaseSecret: EnvSupabaseSecret,
	}
	for setting, env := range envMap {
		if *setting == "" {
			*setting = getEnv(env, *setting)
		}
	}

	if config.DBConfig.RefreshInterval == 0 {
		config.DBConfig.RefreshInterval = getDurationEnv(EnvRefreshInterval, 24*time.Hour)
	}

	if err := config.validate(); err != nil {
		return nil, NewConfigError("invalid auth configuration", err)
	}
	return config, nil
}

// NewAuthConfig creates a new AuthConfig with default settings
func NewAuthConfig() *AuthConfig {
	return &AuthConfig{
		ACL: map[string]map[string]interface{}{
			"roles":    make(map[string]interface{}),
			"tiers":    make(map[string]interface{}),
			"features": make(map[string]interface{}),
		},
		DBConfig: AuthSettings{
			RefreshInterval: 24 * time.Hour,
			SupabaseURL:     "",
			SupabaseKey:     "",
			SupabaseSecret:  "",
		},
	}
}

// ====================================================================
// CACHE IMPLEMENTATION
// ====================================================================

// userID is a type alias for user's UUID within supabase
type userID string

// cacheEntry represents a cached user data with metadata
type cacheEntry struct {
	data         *UserData
	lastModified time.Time
	expiry       time.Time
}

func (e *cacheEntry) isExpired() bool {
	if e.expiry.IsZero() {
		return false
	}
	return time.Now().After(e.expiry)
}

// Cache implements the Cache interface for user data
type UserCache struct {
	users           sync.Map
	lastSync        time.Time
	mu              sync.RWMutex
	logger          *log.Logger
	cleanupInterval time.Duration
	defaultTTL      time.Duration
	gracePeriod     time.Duration
}

// CacheOptions defines configuration parameters for the cache system
type CacheOptions struct {
	// Logging configuration
	Logger    *log.Logger
	LogPrefix string
	LogFlags  int

	// Time-based controls
	CleanupInterval time.Duration
	DefaultTTL      time.Duration
	GracePeriod     time.Duration
	TokenTTL        time.Duration

	// Performance tuning
	RefreshThreshold   float64
	RefreshConcurrency int
	BackgroundRefresh  bool
	RefreshBatchSize   int
	RefreshInterval    time.Duration

	// Monitoring and metrics
	EnableMetrics      bool
	MetricsBufferSize  int
	AlertThreshold     int
	MonitoringInterval time.Duration

	// Security settings
	RequireTokenValidation bool
	TokenValidationTimeout time.Duration
	AllowStaleData         bool
}

// CacheMetrics tracks cache performance metrics
type CacheMetrics struct {
	Hits             atomic.Uint64
	Misses           atomic.Uint64
	Evictions        atomic.Uint64
	CapacityWarnings atomic.Uint64
	ExpirationEvents atomic.Uint64
}

func DefaultCacheOptions() *CacheOptions {
	return &CacheOptions{
		LogPrefix:              "[CACHE] ",
		LogFlags:               log.LstdFlags | log.Lshortfile,
		CleanupInterval:        10 * time.Minute,
		DefaultTTL:             24 * time.Hour,
		GracePeriod:            5 * time.Minute,
		TokenTTL:               1 * time.Hour,
		RefreshThreshold:       0.75,
		RefreshConcurrency:     4,
		BackgroundRefresh:      true,
		RefreshBatchSize:       100,
		RefreshInterval:        15 * time.Minute,
		EnableMetrics:          true,
		MetricsBufferSize:      1000,
		AlertThreshold:         50,
		MonitoringInterval:     1 * time.Minute,
		RequireTokenValidation: true,
		TokenValidationTimeout: 5 * time.Second,
		AllowStaleData:         false,
	}
}

func ValidateOptions(opts *CacheOptions) error {
	if opts == nil {
		return fmt.Errorf("nil options provided")
	}

	if opts.CleanupInterval < time.Minute {
		return fmt.Errorf("cleanup interval must be at least one minute")
	}

	if opts.DefaultTTL <= opts.GracePeriod {
		return fmt.Errorf("default TTL (%v) must be greater than grace period (%v)",
			opts.DefaultTTL, opts.GracePeriod)
	}

	if opts.TokenTTL <= 0 {
		return fmt.Errorf("token TTL must be positive")
	}

	if opts.RefreshThreshold <= 0 || opts.RefreshThreshold >= 1.0 {
		return fmt.Errorf("refresh threshold must be between 0 and 1")
	}

	if opts.RefreshConcurrency < 1 {
		return fmt.Errorf("refresh concurrency must be at least 1")
	}

	if opts.BackgroundRefresh && opts.RefreshInterval < time.Minute {
		return fmt.Errorf("refresh interval must be at least one minute when background refresh is enabled")
	}

	if opts.EnableMetrics && opts.MetricsBufferSize < 1 {
		return fmt.Errorf("metrics buffer size must be positive when metrics are enabled")
	}

	if opts.MonitoringInterval < time.Second {
		return fmt.Errorf("monitoring interval must be at least one second")
	}

	return nil
}

func NewCache(opts *CacheOptions) *UserCache {
	if opts == nil {
		opts = DefaultCacheOptions()
	}

	if opts.Logger == nil {
		opts.Logger = log.New(os.Stdout, opts.LogPrefix, opts.LogFlags)
	}

	opts.Logger.Printf("Initializing new cache with options: %+v", opts)

	cache := &UserCache{
		users:           sync.Map{},
		lastSync:        time.Now(),
		logger:          opts.Logger,
		cleanupInterval: opts.CleanupInterval,
		defaultTTL:      opts.DefaultTTL,
		gracePeriod:     opts.GracePeriod,
	}

	opts.Logger.Printf("Cache instance created with cleanup interval: %v, TTL: %v",
		opts.CleanupInterval, opts.DefaultTTL)

	if opts.CleanupInterval > 0 {
		opts.Logger.Printf("Starting periodic cleanup goroutine")
		go cache.periodicCleanup(context.Background())
	}

	return cache
}

func (c *UserCache) GetUserFromContext(ctx context.Context) (*UserData, error) {
	userID, ok := ctx.Value(UserContextKey).(string)

	if !ok {
		return nil, fmt.Errorf("user_id not found in context")
	}
	return c.GetUser(userID)
}

func (c *UserCache) GetAllUsers() map[string]*UserData {
	users := make(map[string]*UserData)
	c.users.Range(func(key, value any) bool {
		entry := value.(*cacheEntry)
		if !entry.isExpired() {
			users[string(key.(userID))] = entry.data
		}
		return true
	})
	return users
}

func (c *UserCache) GetUser(id string) (*UserData, error) {
	if id == "" {
		return nil, fmt.Errorf("%w: empty user ID", ErrInvalidInput)
	}

	entry, ok := c.users.Load(userID(id))
	if !ok {
		return nil, nil
	}

	cacheEntry := entry.(*cacheEntry)
	now := time.Now()

	if cacheEntry.isExpired() {
		// Check grace period
		if c.gracePeriod > 0 && now.Sub(cacheEntry.expiry) <= c.gracePeriod {
			return cacheEntry.data, nil
		}

		c.DeleteUser(id)
		return nil, ErrEntryExpired
	}

	return cacheEntry.data, nil
}

func (c *UserCache) SetUser(userData *UserData) error {
	if userData == nil {
		return fmt.Errorf("%w: attempted to cache nil UserData", ErrInvalidInput)
	}

	if userData.ID == "" {
		return fmt.Errorf("%w: empty user ID", ErrInvalidInput)
	}

	entry := &cacheEntry{
		data:         userData,
		lastModified: time.Now(),
		expiry:       time.Now().Add(c.defaultTTL),
	}

	c.users.Store(userID(userData.ID), entry)
	return nil
}

func (c *UserCache) DeleteUser(id string) error {
	c.users.Delete(userID(id))

	c.logger.Printf("Deleted user %s from cache", id)
	return nil
}

func (c *UserCache) GetLastModified(id string) time.Time {
	if entry, ok := c.users.Load(userID(id)); ok {

		return entry.(*cacheEntry).lastModified
	}
	return time.Time{}
}

func (c *UserCache) LoadInitialData(ctx context.Context, repo UserRepo) error {
	users, err := repo.GetSubscribedUsers(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch subscribed users: %w", err)
	}

	var loadedCount int
	for _, user := range users {
		if user.ID == "" {
			continue
		}

		if err := c.SetUser(&user); err != nil {
			continue
		}

		c.logger.Printf("Successfully cached user %s with tier %s", user.ID, user.Tier)
		loadedCount++
	}

	c.mu.Lock()
	c.lastSync = time.Now()
	c.mu.Unlock()

	c.logger.Printf("LoadInitialData complete - Processed %d users, successfully loaded %d",
		len(users), loadedCount)

	return nil
}

func (c *UserCache) ForceRefresh(ctx context.Context, repo UserRepo) {
	c.mu.Lock()
	c.LoadInitialData(ctx, repo)
	c.lastSync = time.Now()
	c.mu.Unlock()
}

func (c *UserCache) GetLastSync() time.Time {
	return c.lastSync
}

func (c *UserCache) UpdateLastSync() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastSync = time.Now()
}

func (c *UserCache) periodicCleanup(ctx context.Context) {
	ticker := time.NewTicker(c.cleanupInterval)

	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.cleanup()
		}
	}
}

func (c *UserCache) cleanup() {
	c.users.Range(func(key, value any) bool {
		if value.(*cacheEntry).isExpired() {
			c.users.Delete(key)
		}
		return true
	})
}

func (c *UserCache) Shutdown(ctx context.Context) error {
	c.logger.Printf("Starting Cache shutdown")

	c.users.Range(func(key, value any) bool {
		select {
		case <-ctx.Done():
			return false
		default:
			c.users.Delete(key)
			return true
		}
	})

	if ctx.Err() != nil {
		return fmt.Errorf("shutdown interrupted: %w", ctx.Err())
	}

	c.logger.Printf("Cache shutdown complete")
	return nil
}

// ====================================================================
// SUPABASE IMPLEMENTATION
// ====================================================================

// supabaseClient implements the SupabaseClient interface
type supabaseClient struct {
	*postgrest.Client
}

func (s *supabaseClient) From(table string) *postgrest.QueryBuilder {
	return s.Client.From(table)
}

// InitSupabaseClient creates and configures a Supabase client
func InitSupabaseClient(url string, anonKey string) (SupabaseClient, error) {
	if url == "" {
		url = os.Getenv("SUPABASE_URL")
	}
	if anonKey == "" {
		anonKey = os.Getenv("SUPABASE_ANON_KEY")
	}

	if url == "" || anonKey == "" {
		return nil, NewAuthError(400, "InitSupabaseClient", "Supabase URL or anon key not set", "", "", nil)
	}

	// debug prints
	fmt.Printf("Initializing Supabase client with URL: %s and anon key: %s\n", url, anonKey)
	client := postgrest.NewClient(url, "", map[string]string{
		"apikey":        anonKey,
		"Authorization": "Bearer " + anonKey,
	})

	return &supabaseClient{client}, nil
}

// SubscriberInfo represents a row in our active_subscribers table
type SubscriberInfo struct {
	UUID     string   `json:"uuid"`
	Tier     Tier     `json:"tier"`
	Status   Status   `json:"status"`
	Email    string   `json:"email"`
	Features Features `json:"features"`
}

// SupabaseUserRepository implements the UserRepository interface
type SupabaseUserRepository struct {
	client SupabaseClient
	logger *log.Logger
}

func NewSupabaseUserRepository(client SupabaseClient, logger *log.Logger) (*SupabaseUserRepository, error) {
	if client == nil {
		return nil, NewAuthError(400, "NewSupabaseUserRepository", "Supabase client cannot be nil", "", "", nil)
	}

	if logger == nil {
		logger = log.New(os.Stdout, "[SUPABASE-REPO] ", log.LstdFlags)
	}

	logger.Printf("Initializing Supabase user repository")

	return &SupabaseUserRepository{
		client: client,
		logger: logger,
	}, nil
}

func executeWithContext[T any](ctx context.Context, operation func() (T, error)) (T, error) {
	var zero T

	resultCh := make(chan struct {
		value T
		err   error
	}, 1)

	go func() {
		value, err := operation()

		select {
		case resultCh <- struct {
			value T
			err   error
		}{value, err}:
		case <-ctx.Done():
			// Context was canceled, just return
			return
		}
	}()

	select {
	case result := <-resultCh:
		return result.value, result.err
	case <-ctx.Done():
		return zero, fmt.Errorf("operation canceled: %w", ctx.Err())
	}
}

func (r *SupabaseUserRepository) GetAllUserIDs(ctx context.Context) ([]string, error) {
	r.logger.Printf("Starting GetAllUserIDs request")

	return executeWithContext(ctx, func() ([]string, error) {
		var userIDs []string

		r.logger.Printf("Building query for users table")

		// Only select the UUID field
		query := r.client.From("users").
			Select("uuid", "", false)

		_, err := query.ExecuteTo(&userIDs)

		if err != nil {
			r.logger.Printf("Error executing query: %v", err)
			return nil, fmt.Errorf("failed to get all user IDs: %w", err)
		}

		r.logger.Printf("Successfully retrieved %d user IDs", len(userIDs))
		return userIDs, nil
	})
}

func (r *SupabaseUserRepository) GetUserByID(ctx context.Context, userID string) (*UserData, error) {
	if userID == "" {
		return nil, NewKeyNotFoundError("user", "empty-id", nil)
	}

	r.logger.Printf("Starting GetUserByID request for user: %s", userID)

	return executeWithContext(ctx, func() (*UserData, error) {
		var subscriber SubscriberInfo

		count, err := r.client.From("active_subscribers").
			Select("uuid, tier, status, email, features", "", false).
			Eq("uuid", userID).
			Eq("status", "active").
			Single().
			ExecuteTo(&subscriber)

		if err != nil {
			r.logger.Printf("Error executing query: %v", err)
			return nil, fmt.Errorf("failed to get user %s: %w", userID, err)
		}

		if count == 0 {
			r.logger.Printf("No active subscriber found for user ID: %s", userID)
			return nil, NewKeyNotFoundError("user", userID, nil)
		}

		tier := subscriber.Tier

		userData := &UserData{
			ID:       subscriber.UUID,
			Tier:     tier,
			Email:    subscriber.Email,
			Status:   Status(subscriber.Status),
			Features: make(map[string]string),
		}

		r.logger.Printf("Successfully retrieved user data: %+v", userData)
		return userData, nil
	})
}

func (r *SupabaseUserRepository) GetSubscribedUsers(ctx context.Context) ([]UserData, error) {
	r.logger.Printf("Starting GetSubscribedUsers request")

	return executeWithContext(ctx, func() ([]UserData, error) {
		var subscribers []SubscriberInfo

		query := r.client.From("active_subscribers").
			Select("uuid, email, tier, features", "", false).
			Eq("status", "active")

		count, err := query.ExecuteTo(&subscribers)
		if err != nil {
			r.logger.Printf("Error getting subscribers: %v", err)
			return nil, fmt.Errorf("failed to get subscribed users: %w", err)
		}

		r.logger.Printf("Retrieved %d subscriber records", count)

		for i, sub := range subscribers {
			r.logger.Printf("Subscriber %d:", i+1)
			r.logger.Printf("  UUID: %s", sub.UUID)
			r.logger.Printf("  Email: %s", sub.Email)
			r.logger.Printf("  Tier: %s", sub.Tier)
			r.logger.Printf("  Status: %s", sub.Status)
			r.logger.Printf("  Features: %+v", sub.Features)
			r.logger.Printf("  ---")
		}

		userData := make([]UserData, 0, len(subscribers))
		for _, sub := range subscribers {
			tier := sub.Tier
			user := UserData{
				ID:       sub.UUID,
				Tier:     tier,
				Email:    sub.Email,
				Status:   Status(sub.Status),
				Features: make(map[string]string),
			}
			userData = append(userData, user)
		}

		r.logger.Printf("Processed %d subscribers", len(userData))
		for i, sub := range userData {
			r.logger.Printf("Subscriber %d:", i+1)
			r.logger.Printf("  UUID: %s", sub.ID)
			r.logger.Printf("  Email: %s", sub.Email)
			r.logger.Printf("  Tier: %s", sub.Tier)
			r.logger.Printf("  Status: %s", sub.Status)
			r.logger.Printf("  Features: %+v", sub.Features)
			r.logger.Printf("  ---")
		}
		return userData, nil
	})
}

func (r *SupabaseUserRepository) GetUserFeatures(ctx context.Context, userID string) (map[string]string, error) {
	r.logger.Printf("Starting GetUserFeatures request for user: %s", userID)

	return executeWithContext(ctx, func() (map[string]string, error) {
		var features map[string]string

		_, err := r.client.From("active_subscribers").
			Select("features", "", false).
			Eq("uuid", userID).
			Single().
			ExecuteTo(&features)

		if err != nil {
			r.logger.Printf("Error executing query: %v", err)
			return nil, fmt.Errorf("failed to get user features: %w", err)
		}

		r.logger.Printf("Successfully retrieved user features: %+v", features)
		return features, nil
	})
}

// ====================================================================
// AUTH SERVICE
// ====================================================================

// AuthService provides authentication and authorization services
type Authservice struct {
	client      SupabaseClient
	repo        UserRepo
	cache       *UserCache
	logger      *log.Logger
	config      *AuthConfig
	authHandler *AuthHandler
	shutdown    chan struct{}
	wg          sync.WaitGroup
}

// AuthServiceOption is a functional option for configuring the auth service
type AuthServiceOption func(*Authservice) error

// WithLogger sets a custom logger for the auth service
func WithLogger(logger *log.Logger) AuthServiceOption {
	return func(s *Authservice) error {
		if logger == nil {
			return fmt.Errorf("nil logger provided")
		}
		s.logger = logger
		return nil
	}
}

// WithCache sets a custom cache for the auth service
func WithCache(cache *UserCache) AuthServiceOption {
	return func(s *Authservice) error {
		if cache == nil {
			return fmt.Errorf("nil cache provided")
		}
		s.cache = cache
		return nil
	}
}

// WithRepository sets a custom user repository
func WithRepository(repo UserRepo) AuthServiceOption {
	return func(s *Authservice) error {
		if repo == nil {
			return fmt.Errorf("nil repository provided")
		}
		s.repo = repo
		return nil
	}
}

// NewAuthService creates a new AuthService with options
func NewAuthService(client SupabaseClient, config *AuthConfig, options ...AuthServiceOption) (*Authservice, error) {
	if client == nil {
		return nil, fmt.Errorf("nil client provided")
	}

	if config == nil {
		return nil, fmt.Errorf("nil config provided")
	}

	// Create service with default values
	service := &Authservice{
		client:   client,
		config:   config,
		logger:   log.New(os.Stdout, "[AUTH] ", log.LstdFlags),
		shutdown: make(chan struct{}),
	}

	// Apply options
	for _, option := range options {
		if err := option(service); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	// Create default cache if not provided
	if service.cache == nil {
		cacheOpts := DefaultCacheOptions()
		cacheOpts.Logger = service.logger
		service.cache = NewCache(cacheOpts)
	}

	// Create default repository if not provided
	if service.repo == nil {
		repo, err := NewSupabaseUserRepository(client, service.logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create repository: %w", err)
		}
		service.repo = repo
	}

	// Initialize cache with data
	if err := service.cache.LoadInitialData(context.Background(), service.repo); err != nil {
		return nil, fmt.Errorf("failed to initialize cache: %w", err)
	}

	// Start background refresh if interval is set
	if config.DBConfig.RefreshInterval > 0 {
		service.wg.Add(1)
		go service.startPeriodicRefresh()
	}

	service.logger.Printf("Auth service initialized successfully")
	return service, nil
}

// startPeriodicRefresh starts a goroutine that periodically refreshes the cache
func (s *Authservice) startPeriodicRefresh() {
	defer s.wg.Done()

	refreshInterval := s.config.DBConfig.RefreshInterval
	if refreshInterval < time.Minute {
		refreshInterval = 24 * time.Hour
	}

	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()

	s.logger.Printf("Starting periodic cache refresh every %v", refreshInterval)

	for {
		select {
		case <-s.shutdown:
			s.logger.Printf("Stopping periodic cache refresh")
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			s.logger.Printf("Performing scheduled cache refresh")

			if err := s.RefreshCache(ctx); err != nil {
				s.logger.Printf("Error refreshing cache: %v", err)
			}

			cancel()
		}
	}
}

// RefreshCache refreshes the cache with the latest user data
func (s *Authservice) RefreshCache(ctx context.Context) error {
	return s.cache.LoadInitialData(ctx, s.repo)
}

// GetUserByID retrieves a user by ID with cache
func (s *Authservice) GetUserByID(ctx context.Context, userID string) (*UserData, error) {
	if userID == "" {
		return nil, fmt.Errorf("empty user ID")
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context error: %w", err)
	}

	// Try to get from cache first
	user, err := s.cache.GetUser(userID)
	if err == nil && user != nil {
		return user, nil
	}

	// Fall back to database
	user, err = s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, NewAuthError(
			404,
			"GetUserByID",
			"User not found",
			"",
			userID,
			err,
		)
	}

	// Update cache
	if err := s.cache.SetUser(user); err != nil {
		s.logger.Printf("Error updating cache for user %s: %v", userID, err)
	}

	return user, nil
}

// GetUserFromContext retrieves the user data from the request context
func (s *Authservice) GetUserFromContext(ctx context.Context) (*UserData, error) {
	if ctx == nil {
		return nil, fmt.Errorf("nil context")
	}
	// Try to get user directly from context
	return s.cache.GetUserFromContext(ctx)
}

// parseUserData parses UserData from a map
func (s *Authservice) parseUserData(record map[string]interface{}) (*UserData, error) {
	userData := &UserData{}

	// Parse ID first (required)
	for _, field := range []string{"id", "uuid"} {
		if id, ok := record[field].(string); ok && id != "" {
			userData.ID = id
			break
		}
	}
	if userData.ID == "" {
		return nil, fmt.Errorf("missing or invalid id field")
	}

	// Parse other fields
	parsers := map[string]func(interface{}) error{
		"role": func(v interface{}) error {
			if str, ok := v.(string); ok && str != "" {
				role := Role(str)
				if !role.IsValid() {
					return fmt.Errorf("invalid role: %s", str)
				}
				userData.Role = &role
			}
			return nil
		},
		"email": func(v interface{}) error {
			if str, ok := v.(string); ok {
				userData.Email = str
			}
			return nil
		},
		"tier": func(v interface{}) error {
			if str, ok := v.(string); ok && str != "" {
				tier := Tier(str)
				if !tier.IsValid() {
					return fmt.Errorf("invalid tier: %s", str)
				}
				userData.Tier = tier
			}
			return nil
		},
		"status": func(v interface{}) error {
			if str, ok := v.(string); ok {
				userData.Status = Status(str)
			}
			return nil
		},
		"features": func(v interface{}) error {
			if m, ok := v.(map[string]string); ok {
				userData.Features = m
			}
			return nil
		},
	}

	// Apply all parsers
	for field, parser := range parsers {
		if val, ok := record[field]; ok {
			if err := parser(val); err != nil {
				return nil, err
			}
		}
	}

	return userData, nil
}

// GetUserFeatures retrieves and applies feature flags for a user
func (s *Authservice) GetUserFeatures(ctx context.Context, userID string) (map[string]string, error) {
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if user.Features != nil {
		return user.Features, nil
	}

	features, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user features: %w", err)
	}

	user.Features = features.Features

	// Update cache
	if err := s.cache.SetUser(user); err != nil {
		s.logger.Printf("Warning: failed to update user features in cache: %v", err)
	}

	return user.Features, nil
}

// CanAccessFeature checks if a user can access a feature based on role, tier, and feature flags
func (s *Authservice) CanAccessFeature(user *UserData, feature Feature) bool {
	if user == nil || !feature.IsValid() {
		return false
	}

	// Check if feature exists in user's features
	if user.Features != nil {
		if value, exists := user.Features[string(feature)]; exists {
			return value == "true" || value == "1"
		}
	}

	// If no explicit feature flag, check role-based access
	if user.Role != nil {
		switch *user.Role {
		case RoleAdmin:
			return true
		}
	}

	// Check tier-based access
	switch user.Tier {
	case TierVintage, TierLegacy:
		return true
	}

	return false
}

// ApplyAuthVarsToPageVars maps user features to PageVars dynamically
func (s *Authservice) ApplyAuthVarsToPageVars(user *UserData, pageVars map[string]interface{}) {
	if user == nil || pageVars == nil {
		return
	}
	// Set basic user info
	pageVars["UserID"] = user.ID
	pageVars["UserEmail"] = user.Email
	pageVars["UserTier"] = user.Tier
	pageVars["UserRole"] = user.Role

	// Set flag for having any features enabled
	pageVars["HasFeatures"] = user.Features != nil

	// Map feature flags directly
	if user.Features != nil {
		for flagName, flagValue := range user.Features {
			pageVars[flagName] = flagValue
			if IsBooleanValue(flagValue) {
				boolValue := (flagValue == "true" || flagValue == "enabled" || flagValue == "yes" || flagValue == "1")
				pageVars[flagName] = boolValue
			}
		}
	}
}

// IsBooleanValue checks if a string value should be treated as a boolean
func IsBooleanValue(value string) bool {
	lowerValue := strings.ToLower(value)
	return lowerValue == "true" || lowerValue == "false" ||
		lowerValue == "yes" || lowerValue == "no" ||
		lowerValue == "enabled" || lowerValue == "disabled" ||
		lowerValue == "all" || lowerValue == "none"
}

// Shutdown performs a graceful shutdown of the auth service
func (s *Authservice) Shutdown(ctx context.Context) error {
	s.logger.Printf("Initiating graceful shutdown of auth service")

	// Signal background goroutines to stop
	close(s.shutdown)

	// Setup a channel to wait for goroutines
	done := make(chan struct{})
	go func() {
		s.wg.Wait()

		// Shutdown the cache
		if err := s.cache.Shutdown(ctx); err != nil {
			s.logger.Printf("Warning: cache shutdown error: %v", err)
		}

		close(done)
	}()

	// Wait for shutdown to complete or context to be cancelled
	select {
	case <-done:
		s.logger.Printf("Auth service shutdown completed successfully")
		return nil
	case <-ctx.Done():
		s.logger.Printf("Auth service shutdown interrupted: %v", ctx.Err())
		return fmt.Errorf("shutdown interrupted: %w", ctx.Err())
	}
}

// ====================================================================
// HTTP HANDLER
// ====================================================================

// AuthType defines type of route protection
type AuthType string

const (
	NoAuth      AuthType = "none"
	TokenAuth   AuthType = "token"
	RoleAuth    AuthType = "role"
	TierAuth    AuthType = "tier"
	FeatureAuth AuthType = "feature"
	APIAuth     AuthType = "api"
)

type RouteConfig struct {
	AuthType AuthType
	ReqAuth  interface{}
	Logger   *log.Logger
	Timeout  time.Duration
	DevMode  bool
}

type AuthHandler struct {
	authService *Authservice
	logger      *log.Logger
	devMode     bool
	timeout     time.Duration
}

func NewAuthHandler(authService *Authservice, options ...func(*AuthHandler)) *AuthHandler {
	wrapper := &AuthHandler{
		authService: authService,
		logger:      authService.logger,
		timeout:     10 * time.Second,
	}

	for _, option := range options {
		option(wrapper)
	}

	return wrapper
}

func WithRouteLogger(logger *log.Logger) func(*AuthHandler) {
	return func(w *AuthHandler) {
		if logger != nil {
			w.logger = logger
		}
	}
}

func WithDevMode(devMode bool) func(*AuthHandler) {
	return func(w *AuthHandler) {
		w.devMode = devMode
	}
}

func WithTimeout(timeout time.Duration) func(*AuthHandler) {
	return func(w *AuthHandler) {
		if timeout > 0 {
			w.timeout = timeout
		}
	}
}

func extractToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			return strings.TrimPrefix(authHeader, "bearer ")
		}

		return authHeader
	}

	cookie, err := r.Cookie("auth")
	if err == nil && cookie.Value != "" {
		return cookie.Value
	}

	return r.URL.Query().Get("token")
}

func getSignatureFromCookies(r *http.Request) string {
	var (
		userID string
		sig    string
	)

	// Get user ID from cookie
	userID = readCookie(r, "sub")
	if userID == "" {
		return ""
	}

	// Use auth service to get user data from cache/database
	_, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Still retrieve the sig from cookies for backward compatibility
	for _, cookie := range r.Cookies() {
		if cookie.Name == "MTGBAN" {
			sig = cookie.Value
			break
		}
	}

	// If not in cookies, check query parameters
	querySig := r.FormValue("sig")
	if sig == "" && querySig != "" {
		sig = querySig
	}

	// Basic validation of signature expiration for compatibility
	exp := GetParamFromSig(sig, "Expires")
	if exp == "" {
		return ""
	}

	expires, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || expires < time.Now().Unix() {
		return ""
	}

	// Now we can just return the signature
	return sig
}

func TranslateSignatureToFeatures(sig string) map[string]string {
	features := make(map[string]string)

	if val := GetParamFromSig(sig, "Search"); val != "" {
		features["Search"] = val
	}

	if val := GetParamFromSig(sig, "Arbit"); val != "" {
		features["Arbit"] = val
	}

	if val := GetParamFromSig(sig, "Download"); val != "" {
		features["can_download_csv"] = val
	}

	if val := GetParamFromSig(sig, "ByPrice"); val != "" {
		features["can_filter_by_price"] = val
	}

	if val := GetParamFromSig(sig, "ByPerc"); val != "" {
		features["can_filter_by_percentage"] = val
	}

	return features
}

func (w *AuthHandler) handlePanic(rw http.ResponseWriter, r *http.Request) {
	if err := recover(); err != nil {
		w.logger.Printf("Panic at the DiscGo %s %s: %v\nHeaders: %v\n",
			r.Method,
			r.URL.Path,
			err,
			r.Header,
		)
		http.Error(rw, "Internal Freakout sesh", http.StatusInternalServerError)
	}
}

// Helper function to determine if this is an API request
func isAPIRequest(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/api/") ||
		r.Header.Get("Accept") == "application/json"
}

func (w *AuthHandler) ProtectedHandler(next http.Handler) http.Handler {
	logger := w.logger
	timeout := w.timeout

	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		defer w.handlePanic(rw, r)

		if w.devMode {
			logger.Printf("I know these guys, let them pass: %s", r.URL.Path)
			next.ServeHTTP(rw, r)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		// Handle API requests if needed
		if isAPIRequest(r) {
			w.handleAPIRequest(ctx, rw, r, next)
			return
		}

		// Get user from token
		token := extractToken(r)
		if token == "" {
			http.Error(rw, "Yaint got no token, skedaddle", http.StatusUnauthorized)
			return
		}

		userData, err := w.getUserFromToken(ctx, token)
		if err != nil {
			logger.Printf("Auth error for %s: %v", r.URL.Path, err)
			http.Error(rw, "Begone, thot!", http.StatusUnauthorized)
			return
		}

		// Get pre-computed permissions from cache
		perms := &UserPermissions{
			UserId:      userData.ID,
			AccessMap:   make(map[string]bool),
			FlagValues:  make(map[string]string),
			LevelValues: make(map[string]string),
		}
		if perms == nil {
			logger.Printf("No permissions found for user %s", userData.ID)
			http.Error(rw, "Forbidden", http.StatusForbidden)
			return
		}

		// Single permission check
		if !perms.AccessMap[r.URL.Path] {
			logger.Printf("Access denied for user %s to %s", userData.ID, r.URL.Path)
			http.Error(rw, "Forbidden", http.StatusForbidden)
			return
		}

		// Add user and permissions to context
		ctx = context.WithValue(ctx, UserContextKey, userData)
		ctx = context.WithValue(ctx, PermissionsKey, perms)

		next.ServeHTTP(rw, r.WithContext(ctx))
	})
}

func (w *AuthHandler) handleAPIRequest(ctx context.Context, rw http.ResponseWriter, r *http.Request, next http.Handler) {
	// Set headers for API response
	rw.Header().Add("Content-Type", "application/json")

	token := extractToken(r)
	if token == "" {
		http.Error(rw, "Unauthorized: No token provided", http.StatusUnauthorized)
		return
	}

	userData, err := w.getUserFromToken(ctx, token)
	if err != nil {
		w.logger.Printf("API Auth error: %v", err)
		http.Error(rw, "Unauthorized: Invalid or expired token", http.StatusUnauthorized)
		return
	}

	u := &user{data: userData}
	hasAccess := u.HasAccess(string(TierAPI))
	if !hasAccess {
		w.logger.Printf("API access denied for user %s: Pay up, sucka", userData.ID)
		http.Error(rw, `{"error": "Insufficient permissions"}`, http.StatusForbidden)
		return
	}

	ctx = context.WithValue(ctx, "APIMode", true)
	ctx = context.WithValue(ctx, UserContextKey, userData.ID)

	next.ServeHTTP(rw, r.WithContext(ctx))
}

func (w *AuthHandler) getUserFromToken(ctx context.Context, tokenString string) (*UserData, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("empty token")
	}

	// Get JWT secret from the auth service config
	jwtSecret := w.authService.config.DBConfig.SupabaseSecret
	if jwtSecret == "" {
		return nil, fmt.Errorf("jwt secret not configured")
	}
	// Parse and validate JWT
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token validation failed")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims format")
	}

	// Get user ID from subject claim
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return nil, fmt.Errorf("missing subject in token")
	}

	// Get user from auth service
	user, err := w.authService.GetUserByID(ctx, sub)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	return user, nil
}

// ProtectFunc is a convenience wrapper for http.HandlerFunc
func (w *AuthHandler) ProtectFunc(handlerFunc http.HandlerFunc, requiredAccess interface{}) http.Handler {
	return w.ProtectedHandler(handlerFunc)
}

// WithConfig is a fully configurable protection method
func (w *AuthHandler) WithConfig(config RouteConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return w.ProtectedHandler(next)
	}
}

// ====================================================================
// WEBHOOK HANDLER
// ====================================================================

// WebhookHandler encapsulates webhook handling logic
type WebhookHandler struct {
	service       *Authservice
	secretKey     string
	allowedTypes  map[string]bool
	allowedTables map[string]bool
}

// NewWebhookHandler creates a new webhook handler
func NewWebhookHandler(service *Authservice, secretKey string) *WebhookHandler {
	if secretKey == "" {
		service.logger.Println("WARNING: Webhook secret key is not set")
	}

	fmt.Println("secretKey", secretKey)

	return &WebhookHandler{
		service:   service,
		secretKey: secretKey,
		allowedTypes: map[string]bool{
			"INSERT": true,
			"UPDATE": true,
			"DELETE": true,
		},
		allowedTables: map[string]bool{
			"active_subscribers":       true,
			"active_subscribers_table": true,
			"profiles":                 true,
		},
	}
}

// verifyWebhookSecret securely compares provided secret with configured secret
func (h *WebhookHandler) verifyWebhookSecret(providedSecret string) bool {
	if h.secretKey == "" || providedSecret == "" {
		return false
	}

	return subtle.ConstantTimeCompare(
		[]byte(providedSecret),
		[]byte(h.secretKey),
	) == 1
}

// parseWebhookPayload safely parses and validates webhook payload
func (h *WebhookHandler) parseWebhookPayload(body io.Reader) (*WebhookPayload, error) {
	// Parse webhook payload
	var payload WebhookPayload
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(&payload); err != nil {
		return nil, fmt.Errorf("invalid payload format: %w", err)
	}

	// Validate webhook payload
	if payload.Type == "" {
		return nil, fmt.Errorf("missing required field: type")
	}

	if payload.Table == "" {
		return nil, fmt.Errorf("missing required field: table")
	}

	// Validate operation type
	if !h.allowedTypes[payload.Type] {
		return nil, fmt.Errorf("invalid webhook type: %s", payload.Type)
	}

	// Check if this is a relevant table
	if !h.allowedTables[payload.Table] {
		return nil, fmt.Errorf("unsupported table: %s", payload.Table)
	}

	return &payload, nil
}

// EnforceWebhookSigning is a middleware that verifies webhook requests
func (h *WebhookHandler) EnforceWebhookSigning(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Basic method and content-type validation
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		contentType := r.Header.Get("Content-Type")
		if contentType != "application/json" {
			http.Error(w, "Invalid content type", http.StatusUnsupportedMediaType)
			return
		}

		// Extract and verify webhook signature
		headerSecret := r.Header.Get("X-Webhook-Secret")
		if headerSecret == "" {
			headerSecret = r.Header.Get("secret")
		}

		if !h.verifyWebhookSecret(headerSecret) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Proceed to next handler
		next.ServeHTTP(w, r)
	})
}

// HandleWebhook processes incoming webhook requests
func (h *WebhookHandler) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	// Limit request body size to prevent abuse
	r.Body = http.MaxBytesReader(w, r.Body, maxWebhookBodySize)

	// Set a timeout
	ctx, cancel := context.WithTimeout(r.Context(), webhookTimeout)
	defer cancel()
	r = r.WithContext(ctx)

	// Basic validation
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "Invalid content type", http.StatusUnsupportedMediaType)
		return
	}

	// Verify webhook signature backup check
	headerSecret := r.Header.Get("X-Webhook-Secret")
	if headerSecret == "" {
		headerSecret = r.Header.Get("secret")
	}

	if !h.verifyWebhookSecret(headerSecret) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse webhook payload
	payload, err := h.parseWebhookPayload(r.Body)
	if err != nil {
		h.service.logger.Printf("Failed to parse webhook payload: %v", err)
		http.Error(w, fmt.Sprintf("Invalid payload: %v", err), http.StatusBadRequest)
		return
	}

	// Process webhook
	func() {
		defer func() {
			if r := recover(); r != nil {
				h.service.logger.Printf("Panic in webhook handler: %v", r)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
		}()

		switch payload.Type {
		case "INSERT", "UPDATE":
			if err := h.handleUserUpsert(ctx, payload.Record); err != nil {
				h.service.logger.Printf("Failed to handle user upsert: %v", err)
				http.Error(w, "Failed to process user data", http.StatusBadRequest)
				return
			}

		case "DELETE":
			if err := h.handleUserDelete(ctx, payload.Record); err != nil {
				h.service.logger.Printf("Failed to handle user delete: %v", err)
				http.Error(w, "Failed to process deletion", http.StatusBadRequest)
				return
			}
		}
	}()

	w.WriteHeader(http.StatusOK)
}

// handleUserUpsert processes a user insert or update webhook
func (h *WebhookHandler) handleUserUpsert(ctx context.Context, record map[string]interface{}) error {

	userData, err := h.service.parseUserData(record)
	if err != nil {
		return fmt.Errorf("failed to parse user data: %w", err)
	}

	// Add the user to cache
	if err := h.service.cache.SetUser(userData); err != nil {
		return fmt.Errorf("failed to update cache: %w", err)
	}

	h.service.logger.Printf("Updated cache for user %s via webhook", userData.ID)
	return nil
}

// handleUserDelete processes a user deletion webhook
func (h *WebhookHandler) handleUserDelete(ctx context.Context, record map[string]interface{}) error {
	// Try to extract user ID from various keys
	var userID string
	for _, key := range []string{"id", "uuid", "user_id"} {
		if val, ok := record[key].(string); ok && val != "" {
			userID = val
			break
		}
	}

	if userID == "" {
		return fmt.Errorf("invalid or missing user ID in delete record")
	}

	// Remove the user from cache
	if err := h.service.cache.DeleteUser(userID); err != nil {
		return fmt.Errorf("failed to delete from cache: %w", err)
	}

	h.service.logger.Printf("Removed user %s from cache via webhook", userID)
	return nil
}

// RegisterWebhookHandlers sets up the webhook routes
func RegisterWebhookHandlers(router *http.ServeMux, authService *Authservice) {
	handler := NewWebhookHandler(authService, authService.config.DBConfig.SupabaseSecret)

	// Create the handler chain with middleware
	handlerChain := handler.EnforceWebhookSigning(
		http.HandlerFunc(handler.HandleWebhook),
	)

	// Register webhook endpoints
	router.Handle("/admin/updates", handlerChain)
	router.Handle("/webhook/auth", handlerChain)
}

// ====================================================================
// MIDDLEWARE FUNCTIONS
// ====================================================================

// noSigning is a middleware that passes requests through without token verification
func noSigning(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer recoverPanic(r, w)
		next.ServeHTTP(w, r)
	})
}

// enforceSigning is a middleware that enforces authentication and rate limiting
func enforceSigning(next http.Handler, authService *Authservice) http.Handler {
	// Create a handler that will be protected
	wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer recoverPanic(r, w)

		// Get user from context (already validated by Protection system)
		userData := r.Context().Value(UserContextKey).(*UserData)
		token := extractToken(r)

		// Your existing rate limiting logic
		if !UserRateLimiter.Allow(getUserEmail(token, authService)) && r.URL.Path != "/admin" {
			pageVars := genPageNav("Error", token, authService)
			pageVars.Title = "Rate Limit Exceeded"
			pageVars.ErrorMessage = "You have made too many requests. Please try again later."
			render(w, "home.html", pageVars)
			return
		}

		// Your existing nav feature checks
		for _, navName := range OrderNav {
			nav := ExtraNavs[navName]
			if r.URL.Path == nav.Link {
				u := &user{data: userData}
				if !u.HasAccess(string(Feature(navName))) {
					pageVars := genPageNav(nav.Name, token, authService)
					pageVars.Title = "Unauthorized"
					pageVars.ErrorMessage = "You are not authorized to access this page."
					render(w, nav.Page, pageVars)
					return
				}
				break
			}
		}

		next.ServeHTTP(w, r)
	})

	// Wrap with Protection system
	return wrappedHandler
}

// getUserEmail retrieves a user's email from their token
func getUserEmail(token string, authService *Authservice) string {
	if token == "" {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	userData, _ := authService.cache.GetUserFromContext(ctx)
	if userData == nil {
		return ""
	}

	return userData.Email
}

// enforceAPISigning is middleware for API routes that enforces API access tier
func enforceAPISigning(next http.Handler, authService *Authservice) http.Handler {
	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer recoverPanic(r, w)
		w.Header().Add("RateLimit-Limit", fmt.Sprint(APIRequestsPerSec))
		next.ServeHTTP(w, r)
	})

	// Protect the handler with auth checks
	return authService.authHandler.ProtectFunc(baseHandler, nil)
}

// extractAndValidateToken parses and validates an authorization token from a request
func extractAndValidateToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", &AuthError{
			Code:    http.StatusUnauthorized,
			Message: "Missing authorization header",
		}
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		return "", &AuthError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid authorization format",
		}
	}

	return tokenString, nil
}