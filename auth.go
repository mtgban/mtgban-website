package main

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	supabase "github.com/the-muppet/supabase-go"
	"golang.org/x/exp/slices"
)

// ============================================================================================
// Constants and Types
// ============================================================================================

//go:embed all:nextAuth/out
var authAssets embed.FS

// contentTypeMap maps file extensions to content types
var contentTypeMap = map[string]string{
	".html":  "text/html",
	".js":    "application/javascript",
	".css":   "text/css",
	".json":  "application/json",
	".map":   "application/json",
	".png":   "image/png",
	".jpg":   "image/jpeg",
	".jpeg":  "image/jpeg",
	".svg":   "image/svg+xml",
	".ico":   "image/x-icon",
	".woff":  "font/woff",
	".woff2": "font/woff2",
	".ttf":   "font/ttf",
}

// Context keys for storing data in request context
type ctxKey string

const (
	authServiceKey  ctxKey = "authService"
	userContextKey  ctxKey = "user"
	sessionKey      ctxKey = "session"
	aclContextKey   ctxKey = "acl"
	spoofContextKey ctxKey = "spoof"
	MTGBAN_ROLE     ctxKey = "mtgban_website"
)

const (
	authTokenCookie    = "auth_token"
	refreshTokenCookie = "refresh_token"
	csrfTokenCookie    = "csrf_token"
)

// Common authentication errors
var (
	ErrInvalidCredentials = AuthError{
		Code:       "INVALID_CREDENTIALS",
		Message:    "Invalid email or password",
		StatusCode: http.StatusUnauthorized,
	}
	ErrSessionExpired = AuthError{
		Code:       "SESSION_EXPIRED",
		Message:    "Your session has expired. Please log in again.",
		StatusCode: http.StatusUnauthorized,
	}
	ErrEmailTaken = AuthError{
		Code:       "EMAIL_TAKEN",
		Message:    "Email address is already in use",
		StatusCode: http.StatusBadRequest,
	}
	ErrWeakPassword = AuthError{
		Code:       "WEAK_PASSWORD",
		Message:    "Password does not meet strength requirements",
		StatusCode: http.StatusBadRequest,
	}
	ErrCSRFValidation = AuthError{
		Code:       "INVALID_CSRF_TOKEN",
		Message:    "Invalid security token",
		StatusCode: http.StatusForbidden,
	}
	ErrRateLimitExceeded = AuthError{
		Code:       "RATE_LIMIT_EXCEEDED",
		Message:    "Too many requests. Please try again later.",
		StatusCode: http.StatusTooManyRequests,
	}
	ErrMissingToken = AuthError{
		Code:       "MISSING_TOKEN",
		Message:    "Authentication required",
		StatusCode: http.StatusUnauthorized,
	}
	ErrInvalidToken = AuthError{
		Code:       "INVALID_TOKEN",
		Message:    "Invalid authentication token",
		StatusCode: http.StatusUnauthorized,
	}
	ErrServerError = AuthError{
		Code:       "SERVER_ERROR",
		Message:    "An unexpected error occurred",
		StatusCode: http.StatusInternalServerError,
	}
	ErrPermissionDenied = AuthError{
		Code:       "PERMISSION_DENIED",
		Message:    "You do not have permission to access this resource.",
		StatusCode: http.StatusForbidden,
	}
	ErrInvalidRequest = AuthError{
		Code:       "INVALID_REQUEST",
		Message:    "Invalid request format",
		StatusCode: http.StatusBadRequest,
	}
	ErrMissingFields = AuthError{
		Code:       "MISSING_FIELDS",
		Message:    "Required fields are missing",
		StatusCode: http.StatusBadRequest,
	}
	ErrCSRFSecretNotFound = AuthError{
		Code:       "CSRF_SECRET_NOT_FOUND",
		Message:    "CSRF secret not found",
		StatusCode: http.StatusInternalServerError,
	}
)

// ============================================================================================
// Authentication Types
// ============================================================================================

// AuthConfig holds the configuration settings for the authentication service
type AuthConfig struct {
	Domain         string      `json:"domain"`
	DebugMode      string      `json:"debug_mode"`
	SecureCookies  string      `json:"secure_cookies"`
	SignatureTTL   int         `json:"signature_ttl"`
	LogPrefix      string      `json:"log_prefix"`
	DB             DBConfig    `json:"db"`
	ExemptRoutes   []string    `json:"exempt_routes"`
	ExemptPrefixes []string    `json:"exempt_prefixes"`
	ExemptSuffixes []string    `json:"exempt_suffixes"`
	CSRFPath       string      `json:"csrf_path"`
	CSRFInterval   int         `json:"csrf_interval"`
	Cache          CacheConfig `json:"cache"`
}

// AuthService handles all authentication-related functionality
type AuthService struct {
	Logger       *log.Logger
	Supabase     *supabase.Client
	MTGBAN       *supabase.Client
	Config       AuthConfig
	CSRF         *CSRF
	ACL          *BanACL
	Navs         map[string]*NavElem
	SessionCache *SessionCache
}

// AuthToken represents the authentication token for a user
type AccessToken struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

// RefreshToken represents the refresh token for a user
type RefreshToken struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

// AuthTokens represents the authentication tokens for a user
type AuthTokens struct {
	AccessToken  *AccessToken  `json:"access_token"`
	RefreshToken *RefreshToken `json:"refresh_token"`
	CSRFToken    string        `json:"csrf_token"`
}

// AuthResponse represents the response from supabase for authentication requests
type AuthResponse struct {
	Issuer       string       `json:"iss"`
	Subject      string       `json:"sub"`
	Audience     string       `json:"aud"`
	ExpiresAt    int64        `json:"exp"`
	IssuedAt     int64        `json:"iat"`
	Email        string       `json:"email"`
	Phone        string       `json:"phone"`
	AppMetadata  AppMetadata  `json:"app_metadata"`
	UserMetadata UserMetadata `json:"user_metadata"`
	Role         string       `json:"role"`
	AAL          string       `json:"aal"`
	AMR          []AMREntry   `json:"amr"`
	SessionID    string       `json:"session_id"`
	IsAnonymous  bool         `json:"is_anonymous"`
}

// AppMetadata represents the app metadata from supabase
type AppMetadata struct {
	Provider  string   `json:"provider"`
	Providers []string `json:"providers"`
}

// UserMetadata represents the user metadata from supabase
type UserMetadata struct {
	CreatedAt     string `json:"created_at"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	FullName      string `json:"full_name"`
	PhoneVerified bool   `json:"phone_verified"`
	SignupIP      string `json:"signup_ip"`
	Sub           string `json:"sub"`
	Tier          string `json:"tier"`
	UserAgent     string `json:"user_agent"`
}

// AMREntry represents the AMR entries from supabase
type AMREntry struct {
	Method    string `json:"method"`
	Timestamp int64  `json:"timestamp"`
}

// UserSession represents cached user data and permissions for authentication
type UserSession struct {
	UserId      string         `json:"user_id"`
	Tokens      *AuthTokens    `json:"tokens"`
	User        *UserData      `json:"user"`
	Permissions map[string]any `json:"permissions"`
	Metadata    map[string]any `json:"metadata"`
	CreatedAt   time.Time      `json:"created_at"`
	LastActive  time.Time      `json:"last_active"`
}

// UserResponse represents the response for a user
type UserResponse struct {
	UserId    string `json:"user_id"`
	Email     string `json:"email"`
	Tier      string `json:"tier"`
	Role      string `json:"role"`
	ExpiresAt int64  `json:"expires_at"`
	CSRFToken string `json:"csrf_token"`
}

// AuthError represents a standardized authentication error
type AuthError struct {
	Code       string
	Message    string
	StatusCode int
	Internal   error
}

// Error returns the string representation of the error
func (e AuthError) Error() string {
	if e.Internal != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Internal)
	}
	return e.Message
}

// APIResponse provides a consistent structure for API responses
type APIResponse struct {
	Success    bool   `json:"success"`
	Message    string `json:"message,omitempty"`
	Error      string `json:"error,omitempty"`
	Code       string `json:"code,omitempty"`
	Data       any    `json:"data,omitempty"`
	RedirectTo string `json:"redirectTo,omitempty"`
}

// UserData holds minimal user data for MTGBAN users
type UserData struct {
	UserId string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	Tier   string `json:"tier"`
}

// BanUser represents a user within the BAN ACL system
type BanUser struct {
	UserData    *UserData      `json:"user"`
	Permissions map[string]any `json:"permissions"`
}

// BanACL holds the Access Control List, mapping emails to user permissions
type BanACL struct {
	Users   map[string]*BanUser
	mux     sync.RWMutex
	Updated time.Time
}

// ============================================================================================
// Request and Context Types
// ============================================================================================

// Request types for auth API endpoints
type (
	// LoginRequest represents the expected JSON payload for login
	LoginRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Remember bool   `json:"remember"`
	}

	// SignupRequest represents the expected JSON payload for signup
	SignupRequest struct {
		Email    string         `json:"email"`
		Password string         `json:"password"`
		UserData map[string]any `json:"userData"`
	}

	// PasswordResetRequest represents the expected JSON payload for password reset
	PasswordResetRequest struct {
		Email string `json:"email"`
	}
)

// Middleware type definition for cleaner chaining
type Middleware func(http.HandlerFunc) http.HandlerFunc

// ============================================================================================
// AuthService Initialization
// ============================================================================================

func initAuthConfig() AuthConfig {
	authConfig := AuthConfig{
		DB: DBConfig{
			URL:     Config.Auth.DB.URL,
			AnonKey: Config.Auth.DB.AnonKey,
			RoleKey: Config.Auth.DB.RoleKey,
			Secret:  Config.Auth.DB.Secret,
		},
		Cache: CacheConfig{
			TTL:             Config.Auth.Cache.TTL,
			CleanupInterval: Config.Auth.Cache.CleanupInterval,
			MaxSize:         Config.Auth.Cache.MaxSize,
			Metrics:         Config.Auth.Cache.Metrics,
		},
		DebugMode:      Config.Auth.DebugMode,
		SecureCookies:  Config.Auth.SecureCookies,
		LogPrefix:      Config.Auth.LogPrefix,
		ExemptRoutes:   Config.Auth.ExemptRoutes,
		ExemptPrefixes: Config.Auth.ExemptPrefixes,
		ExemptSuffixes: Config.Auth.ExemptSuffixes,
		CSRFPath:       Config.Auth.CSRFPath,
		CSRFInterval:   Config.Auth.CSRFInterval,
	}
	authConfig, err := validateAuthConfig(authConfig)
	if err != nil {
		log.Fatalf("Failed to validate auth config: %v", err)
	}
	return authConfig
}

// Validation checks
func validateAuthConfig(config AuthConfig) (AuthConfig, error) {
	if config.DB.URL == "" {
		return config, fmt.Errorf("AuthConfig: DB.URL is required")
	}
	if config.DB.AnonKey == "" {
		return config, fmt.Errorf("AuthConfig: DB.AnonKey is required (for client-side interaction)")
	}
	if config.DB.Secret == "" {
		log.Println("Warning: AuthConfig: DB.Secret is not set. Backend operations requiring admin privileges might fail.")
	}
	return config, nil
}

func NewAuthService(config AuthConfig, extraNavs map[string]*NavElem) (*AuthService, error) {
	logger := log.New(os.Stdout, config.LogPrefix, log.LstdFlags)
	// init Supabase client
	GetServices().Initialize(&config.DB)
	client := GetServices().GetSupabaseClient()
	if client == nil {
		clientErr := fmt.Errorf("failed to create Supabase client")
		logger.Printf("NewAuthService: Supabase client error: %v", clientErr)
		return nil, clientErr
	}
	logger.Printf("Supabase client initialized successfully.")

	// Create the service instance
	logger.Printf("NewAuthService: Creating AuthService struct instance...")
	service := &AuthService{
		Logger:       logger,
		Supabase:     client,
		Config:       config,
		CSRF:         nil,
		ACL:          &BanACL{Users: make(map[string]*BanUser)},
		Navs:         extraNavs,
		SessionCache: nil,
	}
	logger.Printf("NewAuthService: AuthService instance created.")

	csrf, err := NewCSRF(config.CSRFPath, service.Logger)
	if err != nil {
		logger.Printf("NewAuthService: CSRF error: %v", err)
		return nil, fmt.Errorf("failed to create CSRF: %w", err)
	}
	service.CSRF = csrf
	logger.Printf("NewAuthService: CSRF initialized.")

	// init session cache
	sessionCache := NewSessionCache(InitCacheConfig(config))
	if sessionCache == nil {
		logger.Printf("NewAuthService: SessionCache initialization failed")
		return nil, fmt.Errorf("failed to create SessionCache")
	}
	service.SessionCache = sessionCache
	logger.Printf("NewAuthService: SessionCache initialized")

	logger.Printf("NewAuthService: Initialized successfully.")
	return service, nil
}

// LoadBanACL fetches ACL data from the Supabase DB and populates the service's BanACL struct
func (a *AuthService) LoadBanACL() error {
	a.Logger.Println("Loading BAN ACL data...")
	var banUsersData []struct {
		UserId      string         `json:"user_id"`
		Email       string         `json:"email"`
		Tier        string         `json:"tier"`
		Role        string         `json:"role"`
		Permissions map[string]any `json:"permissions"`
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err := a.Supabase.DB.From("acl").Select("user_id,email,tier,role,permissions").ExecuteWithContext(ctx, &banUsersData)
	if err != nil {
		a.Logger.Printf("Error fetching BAN ACL data: %v", err)
		return fmt.Errorf("failed to fetch acl data from Supabase: %w", err)
	}

	a.ACL.mux.Lock()
	defer a.ACL.mux.Unlock()

	// create a new map
	newUsers := make(map[string]*BanUser)

	for _, userData := range banUsersData {
		permsCopy := make(map[string]any)
		for k, v := range userData.Permissions {
			permsCopy[k] = v
		}

		newUsers[userData.Email] = &BanUser{
			UserData: &UserData{
				UserId: userData.UserId,
				Email:  userData.Email,
				Tier:   userData.Tier,
				Role:   userData.Role,
			},
			Permissions: permsCopy,
		}
	}
	// replace the old map with the new one
	a.ACL.Users = newUsers
	a.ACL.Updated = time.Now()

	a.Logger.Printf("Successfully loaded ACL for %d users.", len(a.ACL.Users))
	return nil
}

// getUserByID retrieves the BanUser struct for a given user ID.
func (a *AuthService) getUserByID(userID string) (*BanUser, bool) {
	if a.ACL == nil {
		a.Logger.Println("Warning: getUserByID called before BanACL is initialized.")
		return nil, false
	}

	a.ACL.mux.RLock()
	defer a.ACL.mux.RUnlock()

	// find match by ID
	for _, user := range a.ACL.Users {
		if user.UserData.UserId == userID {
			// safe access via deep copy
			userCopy := *user
			permsCopy := make(map[string]any, len(user.Permissions))
			for k, v := range user.Permissions {
				permsCopy[k] = v
			}
			userCopy.Permissions = permsCopy

			userDataCopy := *user.UserData
			userCopy.UserData = &userDataCopy

			if DebugMode {
				a.Logger.Printf("[DEBUG] getUserByID: Found user with ID %s", maskID(userID))
			}

			return &userCopy, true
		}
	}

	if DebugMode {
		a.Logger.Printf("[DEBUG] getUserByID: User %s not found in ACL.", userID)
	}

	return nil, false
}

// getUserByEmail retrieves the BanUser struct for a given email
func (a *AuthService) getUserByEmail(email string) (*BanUser, bool) {
	if a.ACL == nil {
		a.Logger.Println("Warning: getUserByEmail called before BanACL is initialized.")
		return nil, false
	}

	// safe access
	a.ACL.mux.RLock()
	defer a.ACL.mux.RUnlock()

	user, exists := a.ACL.Users[email]
	if !exists {
		return nil, false
	}

	// deep copy to prevent race conditions
	userCopy := *user
	permsCopy := make(map[string]any, len(user.Permissions))
	for k, v := range user.Permissions {
		permsCopy[k] = v
	}
	userCopy.Permissions = permsCopy

	userDataCopy := *user.UserData
	userCopy.UserData = &userDataCopy

	return &userCopy, true
}

func (a *AuthService) getUserPermissions(userId string) (permissions map[string]any, userRole string, userTier string, err error) {
	userRole = "user"
	userTier = "free"
	permissions = make(map[string]any)

	// try BAN ACL first
	banUser, found := a.getUserByID(userId)
	if found {
		// assign role|tier from BAN ACL
		userRole = banUser.UserData.Role
		userTier = banUser.UserData.Tier

		// deep copy to prevent race conditions
		permsCopy := make(map[string]any, len(banUser.Permissions))
		for k, v := range banUser.Permissions {
			permsCopy[k] = v
		}
		permissions = permsCopy // then assign permissions

		if DebugMode {
			a.Logger.Printf("[DEBUG] getUserPermissions: Found user %s in BAN ACL (Role: %s, Tier: %s)",
				maskEmail(banUser.UserData.Email), userRole, userTier)
		}
		// return permissions, role, tier and empty error
		return permissions, userRole, userTier, nil
	}

	// get user details from Supabase if not in BAN ACL
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	supaUser, supaErr := a.Supabase.Auth.User(ctx, userId)
	if supaErr != nil {
		a.Logger.Printf("Failed to get user details from Supabase for ID %s: %v", maskID(userId), supaErr)
		err = fmt.Errorf("failed to get user details: %w", supaErr)
		return nil, userRole, userTier, err
	}

	// get role/tier from metadata
	if supaUser.UserMetadata != nil {
		if metaRole, ok := supaUser.UserMetadata["role"].(string); ok && metaRole != "" {
			userRole = metaRole
		}
		if metaTier, ok := supaUser.UserMetadata["tier"].(string); ok && metaTier != "" {
			userTier = metaTier
		}
	}

	// set permissions based on role/tier
	setPermErr := setPermissions(userRole, userTier, &permissions)
	if setPermErr != nil {
		a.Logger.Printf("Error setting permissions from role/tier for user %s: %v", maskID(userId), setPermErr)
		err = fmt.Errorf("failed to set permissions based on role/tier: %w", setPermErr)
		return nil, userRole, userTier, err
	}

	if DebugMode {
		a.Logger.Printf("[DEBUG] getUserPermissions: Retrieved permissions for user %s (Role: %s, Tier: %s) from Supabase",
			maskID(userId), userRole, userTier)
	}

	return permissions, userRole, userTier, nil
}

// setPermissions is a helper function to set permission maps based on role and tier
func setPermissions(userRole string, userTier string, permissions *map[string]any) error {
	// Helper to convert string map to interface map
	convertToInterfaceMap := func(m map[string]map[string]map[string]any) map[string]map[string]map[string]any {
		// Create deep copy to maintain the same behavior
		result := make(map[string]map[string]map[string]any)
		for k1, v1 := range m {
			result[k1] = make(map[string]map[string]any)
			for k2, v2 := range v1 {
				result[k1][k2] = make(map[string]any)
				for k3, v3 := range v2 {
					result[k1][k2][k3] = v3
				}
			}
		}
		return result
	}

	getSingleACLPermission := func(name string, aclSection map[string]map[string]map[string]any) map[string]map[string]any {
		if permissions, ok := aclSection[name]; ok {
			return permissions
		}
		return nil
	}

	// Helper to merge two boolean permissions
	mergePermissionFlags := func(permission1, permission2 map[string]string) map[string]string {
		if permission1 == nil && permission2 == nil {
			return make(map[string]string)
		}
		if permission1 == nil {
			permission1 = make(map[string]string)
		}
		if permission2 == nil {
			permission2 = make(map[string]string)
		}

		combined := make(map[string]string)
		allSubKeys := make(map[string]struct{})
		for key := range permission1 {
			allSubKeys[key] = struct{}{}
		}
		for key := range permission2 {
			allSubKeys[key] = struct{}{}
		}

		for subKey := range allSubKeys {
			val1, ok1 := permission1[subKey]
			val2, ok2 := permission2[subKey]
			isVal1True := ok1 && strings.EqualFold(val1, "true")
			isVal2True := ok2 && strings.EqualFold(val2, "true")

			if isVal1True || isVal2True {
				combined[subKey] = "true"
			} else if ok1 || ok2 {
				isVal1False := ok1 && strings.EqualFold(val1, "false")
				isVal2False := ok2 && strings.EqualFold(val2, "false")
				if isVal1False || isVal2False {
					combined[subKey] = "false"
				} else {
					if DevMode {
						log.Printf("[WARNING] mergePermissionFlags: Unrecognized boolean value for subkey '%s': val1='%s', val2='%s'. Defaulting to false.", subKey, val1, val2)
					}
					combined[subKey] = "false"
				}
			}
		}
		return combined
	}

	combinedPermissions := make(map[string]any)
	allRootKeys := make(map[string]struct{})

	tierACL := convertToInterfaceMap(Config.ACL.Tiers)
	if tierACL == nil {
		tierACL = make(map[string]map[string]map[string]any)
	}
	roleACL := convertToInterfaceMap(Config.ACL.Roles)
	if roleACL == nil {
		roleACL = make(map[string]map[string]map[string]any)
	}

	// Get permissions for the specific tier and role
	tierPermissions := getSingleACLPermission(userTier, tierACL)
	rolePermissions := getSingleACLPermission(userRole, roleACL)

	// Populate allRootKeys from both tier and role permissions
	for key := range tierPermissions {
		allRootKeys[key] = struct{}{}
	}
	for key := range rolePermissions {
		allRootKeys[key] = struct{}{}
	}

	for rootKey := range allRootKeys {
		// Get the specific flag maps for this rootKey from both sources
		var tierFlags map[string]string
		var roleFlags map[string]string
		if tierPermissions != nil {
			if ifaceMap, ok := tierPermissions[rootKey]; ok {
				tierFlags = make(map[string]string)
				for k, v := range ifaceMap {
					if strVal, ok := v.(string); ok {
						tierFlags[k] = strVal
					}
				}
			}
		}
		if rolePermissions != nil {
			if ifaceMap, ok := rolePermissions[rootKey]; ok {
				roleFlags = make(map[string]string)
				for k, v := range ifaceMap {
					if strVal, ok := v.(string); ok {
						roleFlags[k] = strVal
					}
				}
			}
		}
		// Determine if this rootKey *actually exists* in either source ACL.
		_, tierKeyExists := tierPermissions[rootKey]
		_, roleKeyExists := rolePermissions[rootKey]
		keyExistsInACL := tierKeyExists || roleKeyExists

		// Merge the sub-flags (if any exist)
		combinedFlagsMap := mergePermissionFlags(tierFlags, roleFlags)

		if keyExistsInACL {
			if len(combinedFlagsMap) > 0 {
				// Key exists AND has sub-flags after merging
				nestedPermissionsMap := make(map[string]any, len(combinedFlagsMap))
				for k, v := range combinedFlagsMap {
					boolVal := false
					if strings.EqualFold(v, "true") {
						boolVal = true
					}
					nestedPermissionsMap[k] = boolVal // Store boolean
				}
				combinedPermissions[rootKey] = nestedPermissionsMap
			} else {
				// Add empty map to signify permission grant
				combinedPermissions[rootKey] = make(map[string]any)
			}
		}
	}
	// Assign the calculated permissions
	*permissions = combinedPermissions

	if DebugMode {
		log.Printf("[DEBUG] setPermissions: effective permissions for Role '%s', Tier '%s' are: '%v'", userRole, userTier, combinedPermissions)
	}
	return nil
}

// isExemptPath checks if a given request path is exempt from authentication checks
func (a *AuthService) isExemptPath(path string) bool {
	if len(path) > 1 && path[len(path)-1] == '/' {
		path = path[:len(path)-1]
	}

	for _, route := range a.Config.ExemptRoutes {
		if len(route) > 1 && route[len(route)-1] == '/' {
			route = route[:len(route)-1]
		}
		if path == route && DebugMode {
			a.Logger.Printf("Path '%s' is exempt (exact match: '%s')", path, route)
			return true
		}
		if path == route {
			return true
		}
	}

	// Check prefix matches
	for _, prefix := range a.Config.ExemptPrefixes {
		if strings.HasPrefix(path, prefix) && DebugMode {
			a.Logger.Printf("Path '%s' is exempt (prefix match: '%s')", path, prefix)
			return true
		}
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	// Check suffix matches
	cleanedPath := strings.Split(path, "?")[0]
	for _, suffix := range a.Config.ExemptSuffixes {
		if strings.HasSuffix(cleanedPath, suffix) && DebugMode {
			a.Logger.Printf("Path '%s' is exempt (suffix match: '%s')", path, suffix)
			return true
		}
		if strings.HasSuffix(cleanedPath, suffix) {
			return true
		}
	}

	// If no match found, the path is not exempt
	return false
}

// ============================================================================================
// AuthService Core Logic Methods
// ============================================================================================

// logWithContext logs messages with request context
func (a *AuthService) logWithContext(r *http.Request, format string, v ...any) {
	if r == nil {
		a.Logger.Println("Warning: No request context provided to logWithContext")
		return
	}

	clientIP := getClientIP(r)
	method := strings.TrimSpace(r.Method)
	path := strings.TrimSpace(r.URL.Path)

	// Get user ID
	userID := a.getUserIDFromRequest(r)

	// Format log message
	contextMsg := fmt.Sprintf("[%s][%s %s][User:%s] %s",
		clientIP, method, path, maskID(userID), format)

	a.Logger.Printf(contextMsg, v...)
}

// getUserIDFromRequest extracts user ID from request context or cookie
func (a *AuthService) getUserIDFromRequest(r *http.Request) string {
	// First try to get UserID from context
	if user, ok := r.Context().Value(userContextKey).(*supabase.User); ok && user != nil {
		return user.ID
	}

	// Then try to get from UserSession if available
	if sessionData := r.Context().Value(userContextKey); sessionData != nil {
		if userSession, ok := sessionData.(*UserSession); ok && userSession != nil && userSession.User != nil {
			return userSession.UserId
		}
	}

	// Fallback to cookie extraction only if absolutely necessary
	if authCookie, err := r.Cookie("auth_token"); err == nil && authCookie.Value != "" {
		parts := strings.Split(authCookie.Value, ".")
		if len(parts) == 3 {
			if payload, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
				var claims map[string]any
				if json.Unmarshal(payload, &claims) == nil {
					if sub, ok := claims["sub"].(string); ok {
						return sub
					}
				}
			}
		}
	}
	return "anonymous"
}

// sendAPISuccess sends a standardized successful API response
func (a *AuthService) sendAPISuccess(w http.ResponseWriter, message string, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: message,
		Data:    data,
	})
}

// setAuthCookies sets both auth and refresh cookies
func (a *AuthService) setAuthCookies(w http.ResponseWriter, r *http.Request, token, refreshToken string, rememberMe bool) {
	// Set auth token
	var maxAge int
	var sameSite http.SameSite

	if rememberMe {
		maxAge = 30 * 24 * 60 * 60 // 30 days
	} else {
		maxAge = 24 * 60 * 60 // 24 hours
	}

	if DebugMode {
		sameSite = http.SameSiteLaxMode
	} else {
		sameSite = http.SameSiteStrictMode
	}

	isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"

	// Set both cookies
	http.SetCookie(w, &http.Cookie{
		Name: authTokenCookie, Value: token, Path: "/", Domain: Config.Auth.Domain,
		MaxAge: maxAge, HttpOnly: true, Secure: isSecure, SameSite: sameSite,
	})

	http.SetCookie(w, &http.Cookie{
		Name: refreshTokenCookie, Value: refreshToken, Path: "/", Domain: Config.Auth.Domain,
		MaxAge: 60 * 24 * 60 * 60, HttpOnly: true, Secure: isSecure, SameSite: sameSite,
	})

	a.logWithContext(r, "Set auth cookies (auth=%dh, refresh=%dh)", maxAge/3600, 60*24)
}

// clearAuthCookies removes all auth cookies
func (a *AuthService) clearAuthCookies(w http.ResponseWriter, r *http.Request) {
	var sameSite http.SameSite
	if DebugMode {
		sameSite = http.SameSiteLaxMode
	} else {
		sameSite = http.SameSiteStrictMode
	}

	isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"

	// Cookie deletion properties
	expiredCookie := func(name string, httpOnly bool) *http.Cookie {
		return &http.Cookie{
			Name: name, Value: "", Path: "/", Domain: Config.Auth.Domain,
			MaxAge: -1, Expires: time.Unix(0, 0),
			HttpOnly: httpOnly, Secure: isSecure, SameSite: sameSite,
		}
	}
	// Clear all auth cookies
	http.SetCookie(w, expiredCookie(authTokenCookie, true))
	http.SetCookie(w, expiredCookie(refreshTokenCookie, true))
	http.SetCookie(w, expiredCookie(csrfTokenCookie, true))

	a.logWithContext(r, "Cleared auth cookies")
}

// parseAndValidateRequest is a generic helper for parsing and validating JSON requests
func (a *AuthService) parseAndValidateRequest(r *http.Request, req any, validator func() *AuthError) *AuthError {
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return &AuthError{
			Code:       "INVALID_REQUEST",
			Message:    "Invalid request body",
			StatusCode: http.StatusBadRequest,
			Internal:   err,
		}
	}

	if validator != nil {
		return validator()
	}

	return nil
}

// withTimeoutContext wraps operations with a timeout context
func withTimeoutContext(parentCtx context.Context, duration time.Duration, operation func(ctx context.Context) error) error {
	ctx, cancel := context.WithTimeout(parentCtx, duration)
	defer cancel()
	return operation(ctx)
}

// performSupabaseAuth executes authentication with Supabase
func (a *AuthService) performSupabaseAuth(ctx context.Context, email, password string) (*supabase.AuthenticatedDetails, *supabase.User, error) {
	var authResponse *supabase.AuthenticatedDetails
	var userInfo *supabase.User

	// Create timeout context
	authCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// supabase auth
	err := func() error {
		resp, err := a.Supabase.Auth.SignIn(authCtx, supabase.UserCredentials{
			Email:    email,
			Password: password,
		})

		if err != nil {
			if DebugMode {
				a.Logger.Printf("[DEBUG] Supabase authentication failed for %s: %v", maskEmail(email), err)
			}

			// Categorize error types for better client feedback
			errMsg := strings.ToLower(err.Error())
			if strings.Contains(errMsg, "invalid") || strings.Contains(errMsg, "credentials") {
				return &AuthError{
					Code:       "INVALID_CREDENTIALS",
					Message:    "Invalid email or password",
					StatusCode: http.StatusUnauthorized,
					Internal:   err,
				}
			}

			return &AuthError{
				Code:       "AUTH_FAILED",
				Message:    "Authentication failed",
				StatusCode: http.StatusUnauthorized,
				Internal:   err,
			}
		}

		authResponse = resp
		return nil
	}()

	if err != nil {
		return nil, nil, err
	}

	// Then get user information using the token
	err = func() error {
		// Create separate context for user info request
		userCtx, userCancel := context.WithTimeout(ctx, 5*time.Second)
		defer userCancel()

		user, err := a.Supabase.Auth.User(userCtx, authResponse.AccessToken)
		if err != nil {
			return &AuthError{
				Code:       "USER_FETCH_FAILED",
				Message:    "Could not retrieve user data after login",
				StatusCode: http.StatusInternalServerError,
				Internal:   err,
			}
		}

		if user == nil {
			return &AuthError{
				Code:       "USER_NOT_FOUND",
				Message:    "User data not found after login",
				StatusCode: http.StatusInternalServerError,
			}
		}

		userInfo = user
		return nil
	}()

	if err != nil {
		return nil, nil, err
	}

	return authResponse, userInfo, nil
}

// authenticateUser is the public interface that uses performSupabaseAuth
func (a *AuthService) authenticateUser(r *http.Request, email, password string) (*supabase.AuthenticatedDetails, *supabase.User, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	return a.performSupabaseAuth(ctx, email, password)
}

// createUserResponse builds a standardized user response
func (a *AuthService) createUserResponse(userInfo *supabase.User, expiresAt int64, csrfToken string) UserResponse {
	return UserResponse{
		UserId:    userInfo.ID,
		Email:     userInfo.Email,
		Tier:      userInfo.UserMetadata["tier"].(string),
		ExpiresAt: expiresAt,
		CSRFToken: csrfToken,
	}
}

// LoginAPI handles POST requests to the API login endpoint
func (a *AuthService) LoginAPI(w http.ResponseWriter, r *http.Request) {
	a.logWithContext(r, "LoginAPI attempt")
	defer r.Body.Close()

	var req LoginRequest

	// Parse and validate request
	if authErr := a.parseAndValidateRequest(r, &req, func() *AuthError {
		if req.Email == "" || req.Password == "" {
			return &AuthError{
				Code:       "MISSING_CREDENTIALS",
				Message:    "Email and password are required",
				StatusCode: http.StatusBadRequest,
			}
		}
		return nil
	}); authErr != nil {
		a.handleError(w, r, *authErr)
		return
	}

	// Authenticate with auth provider
	authResponse, userInfo, authErrInternal := a.authenticateUser(r, req.Email, req.Password)
	if authErrInternal != nil {
		// Try to cast to AuthError for specific codes
		var authErr AuthError
		if errors.As(authErrInternal, &authErr) {
			a.handleError(w, r, authErr)
		} else {
			// Generic auth failed
			a.handleError(w, r, AuthError{
				Code:       "AUTH_FAILED",
				Message:    "Authentication failed",
				StatusCode: http.StatusUnauthorized,
				Internal:   authErrInternal,
			})
		}
		return
	}

	if DebugMode {
		a.logWithContext(r, "[DEBUG] LoginAPI: Authentication successful for %s", maskEmail(req.Email))
	}

	// Generate CSRF token
	csrfToken, csrfErr := a.generateCSRFToken(userInfo.ID)
	if csrfErr != nil {
		a.logWithContext(r, "[ERROR] LoginAPI: Failed to generate CSRF token: %v", csrfErr)
		a.handleError(w, r, AuthError{
			Code:       "CSRF_TOKEN_GENERATION_FAILED",
			Message:    "Failed to generate CSRF token",
			StatusCode: http.StatusInternalServerError,
			Internal:   csrfErr,
		})
		return
	}

	if DebugMode {
		a.logWithContext(r, "[DEBUG] LoginAPI: CSRF token generated.")
	}

	// Set auth cookies
	a.setAuthCookies(w, r, authResponse.AccessToken, authResponse.RefreshToken, req.Remember)

	// Get user data from banUser
	banUser, found := a.getUserByID(userInfo.ID)
	if !found {
		a.logWithContext(r, "[ERROR] LoginAPI: User authenticated (%s) but banUser data not found for ID %s", maskEmail(req.Email), maskID(userInfo.ID))
		a.clearAuthCookies(w, r)
		a.handleError(w, r, AuthError{
			Code:       "USER_DATA_NOT_FOUND",
			Message:    "User profile data missing. Please contact support.",
			StatusCode: http.StatusInternalServerError,
		})
		return
	}

	if DebugMode {
		a.logWithContext(r, "[DEBUG] LoginAPI: Fetched banUser data for %s. Role: %s, Tier: %s", maskID(userInfo.ID), banUser.UserData.Role, banUser.UserData.Tier)
	}

	permissions, userRole, userTier, err := a.getUserPermissions(userInfo.ID)
	if err != nil {
		a.logWithContext(r, "[ERROR] LoginAPI: Failed to get user permissions for %s: %v", maskID(userInfo.ID), err)
	}

	// Create a complete session object
	finalSessionData := &UserSession{
		UserId:     userInfo.ID,
		CreatedAt:  time.Now(),
		LastActive: time.Now(),
		User: &UserData{
			UserId: userInfo.ID,
			Email:  banUser.UserData.Email,
			Role:   userRole,
			Tier:   userTier,
		},
		Permissions: permissions,
		Metadata:    userInfo.UserMetadata,
		Tokens: &AuthTokens{
			CSRFToken: csrfToken,
			AccessToken: &AccessToken{
				Token:     authResponse.AccessToken,
				ExpiresAt: time.Now().Add(time.Duration(authResponse.ExpiresIn) * time.Second).Unix(),
			},
			RefreshToken: func() *RefreshToken {
				if authResponse.RefreshToken != "" {
					refreshExpiresIn := authResponse.ExpiresIn
					if refreshExpiresIn == 0 {
						a.logWithContext(r, "[WARN] LoginAPI: Refresh token provided for %s, but expiration is missing or zero in authResponse. Setting very long default expiry.", maskID(userInfo.ID))
						refreshExpiresIn = 365 * 24 * 3600 // 1 year default if not provided
					}
					return &RefreshToken{
						Token:     authResponse.RefreshToken,
						ExpiresAt: time.Now().Add(time.Duration(refreshExpiresIn) * time.Second).Unix(),
					}
				}
				return nil
			}(),
		},
	}

	// Cache the session
	if a.SessionCache != nil {
		cacheSetStart := time.Now()
		err := a.SessionCache.Set(finalSessionData)
		cacheSetDuration := time.Since(cacheSetStart)
		if err != nil {
			a.logWithContext(r, "[ERROR] LoginAPI: Failed to set session in cache for user %s: %v", maskID(userInfo.ID), err)
			// Log error, but continue as user has cookies
		} else if DebugMode {
			a.logWithContext(r, "[DEBUG] LoginAPI: Successfully set session in cache for user %s in %v", maskID(userInfo.ID), cacheSetDuration)
		}
	} else {
		a.logWithContext(r, "[WARN] LoginAPI: SessionCache is nil, unable to cache session for user %s", maskID(userInfo.ID))
	}

	// Prepare and send API response
	userResponseData := UserResponse{
		UserId:    finalSessionData.UserId,
		Email:     finalSessionData.User.Email,
		Tier:      finalSessionData.User.Tier,
		Role:      finalSessionData.User.Role,
		ExpiresAt: finalSessionData.Tokens.AccessToken.ExpiresAt,
		CSRFToken: finalSessionData.Tokens.CSRFToken,
	}

	a.logWithContext(r, "LoginAPI successful for %s (Tier: %s, Role: %s)", maskEmail(req.Email), userResponseData.Tier, userResponseData.Role)
	a.sendAPISuccess(w, "Login successful", userResponseData)
}

// SignupAPI handles POST requests to the API signup endpoint
func (a *AuthService) SignupAPI(w http.ResponseWriter, r *http.Request) {
	a.logWithContext(r, "SignupAPI attempt")

	var req SignupRequest
	validator := func() *AuthError {
		if req.Email == "" || req.Password == "" {
			return &AuthError{
				Code:       "MISSING_CREDENTIALS",
				Message:    "Email and password are required",
				StatusCode: http.StatusBadRequest,
			}
		}
		return nil
	}

	if authErr := a.parseAndValidateRequest(r, &req, validator); authErr != nil {
		a.handleError(w, r, *authErr)
		return
	}

	// Create the user in Supabase
	if req.UserData == nil {
		req.UserData = make(map[string]any)
	}
	if _, ok := req.UserData["tier"]; !ok {
		req.UserData["tier"] = "free"
	}

	// Sign Up
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	user, err := a.Supabase.Auth.SignUp(ctx, supabase.UserCredentials{
		Email:    req.Email,
		Password: req.Password,
		Data:     req.UserData,
	})

	if err != nil || user == nil {
		a.logWithContext(r, "SignupAPI failed for %s: %v", maskEmail(req.Email), err)
		errMsg := strings.ToLower(err.Error())
		if strings.Contains(errMsg, "user already registered") || strings.Contains(errMsg, "email address is already confirmed") {
			a.handleError(w, r, ErrEmailTaken)
		} else {
			a.handleError(w, r, AuthError{Code: "SIGNUP_FAILED", Message: "Failed to create account", StatusCode: http.StatusInternalServerError, Internal: err})
		}
		return
	}
	// attempt Auto-Login after successful signup
	ctx = r.Context()
	authResponse, userInfo, _ := a.performSupabaseAuth(ctx, req.Email, req.Password)
	if authResponse != nil && userInfo != nil {
		csrfToken, err := a.generateCSRFToken(userInfo.ID)
		if err != nil {
			a.handleError(w, r, AuthError{Code: "CSRF_TOKEN_GENERATION_FAILED", Message: "Failed to generate CSRF token", StatusCode: http.StatusInternalServerError, Internal: err})
			return
		}
		expiresAt := time.Now().Add(time.Duration(authResponse.ExpiresIn) * time.Second).Unix()
		userResponse := a.createUserResponse(userInfo, expiresAt, csrfToken)

		a.logWithContext(r, "SignupAPI successful for %s, auto-login succeeded.", maskEmail(req.Email))
		a.sendAPISuccess(w, "Account created and logged in successfully.", userResponse)
	} else {
		a.logWithContext(r, "Auto-login after signup failed for %s", maskEmail(req.Email))
	}
}

// LogoutAPI handles POST requests to the API logout endpoint
func (a *AuthService) LogoutAPI(w http.ResponseWriter, r *http.Request) {
	a.logWithContext(r, "LogoutAPI attempt")

	userEmail := "anonymous"
	userSession := getUserSessionFromContext(r)
	if userSession != nil && userSession.User != nil {
		userEmail = userSession.User.Email
		a.logWithContext(r, "LogoutAPI: Found session for %s in context.", maskEmail(userEmail))
	} else {
		a.logWithContext(r, "LogoutAPI: No user session found in context.")
	}

	tokenToInvalidate := extractAuthToken(r)

	if tokenToInvalidate != "" {
		withTimeoutContext(r.Context(), 5*time.Second, func(ctx context.Context) error {
			if err := a.Supabase.Auth.SignOut(ctx, tokenToInvalidate); err != nil {
				a.logWithContext(r, "Supabase SignOut error for %s: %v", maskEmail(userEmail), err)
			} else {
				a.logWithContext(r, "Supabase SignOut successful for %s", maskEmail(userEmail))
			}
			return nil
		})
	} else {
		a.logWithContext(r, "LogoutAPI attempted without auth token (cookie or header).")
	}
	a.clearAuthCookies(w, r)

	a.sendAPISuccess(w, "Logout successful", map[string]any{"redirectTo": "/"})
}

// RefreshTokenAPI handles POST requests to explicitly refresh the session tokens
func (a *AuthService) RefreshTokenAPI(w http.ResponseWriter, r *http.Request) {
	a.logWithContext(r, "RefreshTokenAPI attempt")

	// Get refresh token from cookie
	refreshCookie, refreshErr := r.Cookie("refresh_token")
	if refreshErr != nil || refreshCookie.Value == "" {
		a.logWithContext(r, "RefreshTokenAPI failed: Missing refresh_token cookie.")
		a.handleError(w, r, ErrMissingToken)
		return
	}
	refreshToken := refreshCookie.Value

	newSession, err := a.refreshAuthTokens(r, w, refreshToken, "")
	if err != nil {
		a.handleError(w, r, AuthError{
			Code:       "REFRESH_TOKEN_FAILED",
			Message:    "Failed to refresh tokens",
			StatusCode: http.StatusInternalServerError,
			Internal:   err,
		})
		return
	}

	// Generate and Set CSRF Token
	csrfToken, err := a.generateCSRFToken(newSession.User.ID)
	if err != nil {
		a.handleError(w, r, AuthError{
			Code:       "CSRF_TOKEN_GENERATION_FAILED",
			Message:    "Failed to generate CSRF token",
			StatusCode: http.StatusInternalServerError,
			Internal:   err,
		})
		return
	}

	// Calculate expiry time
	expiresAt := time.Now().Add(time.Duration(newSession.ExpiresIn) * time.Second).Unix()
	userResponse := a.createUserResponse(&newSession.User, expiresAt, csrfToken)

	a.sendAPISuccess(w, "Token refreshed successfully", userResponse)
}

// GetUserAPI handles GET requests to fetch the current authenticated user's info
func (a *AuthService) GetUserAPI(w http.ResponseWriter, r *http.Request) {
	a.logWithContext(r, "GetUserAPI attempt")

	// Prioritize getting the validated user session from context
	userSession := getUserSessionFromContext(r)
	var userInfo *supabase.User
	var accessToken string

	if userSession != nil && userSession.User != nil {
		userInfo = &supabase.User{
			ID:    userSession.User.UserId,
			Email: userSession.User.Email,
			UserMetadata: map[string]any{
				"role": userSession.User.Role,
				"tier": userSession.User.Tier,
			},
		}
		a.logWithContext(r, "GetUserAPI: Using session from context for user %s", maskID(userInfo.ID))
	} else {
		// If no session in context, fall back to attempting refresh via cookies
		a.logWithContext(r, "GetUserAPI: No session in context, attempting refresh via cookies.")

		refreshCookie, refreshErr := r.Cookie("refresh_token")
		if refreshErr != nil || refreshCookie.Value == "" {
			a.logWithContext(r, "GetUserAPI failed: No session in context and missing refresh_token cookie.")
			a.handleError(w, r, ErrMissingToken)
			return
		}
		refreshToken := refreshCookie.Value

		// Get the current auth token from cookie to pass to refresh (Supabase needs it)
		authCookie, authErr := r.Cookie("auth_token")
		if authErr == nil && authCookie.Value != "" {
			accessToken = authCookie.Value
		}

		newSession, err := a.refreshAuthTokens(r, w, refreshToken, accessToken)
		if err != nil {
			a.handleError(w, r, AuthError{
				Code:       "REFRESH_TOKEN_FAILED",
				Message:    "Failed to refresh tokens",
				StatusCode: http.StatusInternalServerError,
				Internal:   err,
			})
			return
		}
		userInfo = &newSession.User // newSession.User is a supabase.User
		// Tokens are already set as cookies by refreshAuthTokens
	}

	// Check if user is authenticated after all attempts
	if userInfo == nil {
		a.logWithContext(r, "GetUserAPI failed: No valid session found after all attempts.")
		a.handleError(w, r, ErrMissingToken)
		return
	}

	// Generate and Set CSRF Token
	csrfToken, genErr := a.generateCSRFToken(userInfo.ID)
	if genErr != nil {
		a.handleError(w, r, AuthError{
			Code:       "CSRF_TOKEN_GENERATION_FAILED",
			Message:    "Failed to generate CSRF token",
			StatusCode: http.StatusInternalServerError,
			Internal:   genErr,
		})
		return
	}
	// Estimate session expiry
	expiresAt := time.Now().Add(24 * time.Hour).Unix()
	if authCookie, err := r.Cookie("auth_token"); err == nil && authCookie.Value != "" {
		// Attempt to get actual expiry from token if available
		parts := strings.Split(authCookie.Value, ".")
		if len(parts) == 3 {
			if payload, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
				var claims map[string]any
				if json.Unmarshal(payload, &claims) == nil {
					if exp, ok := claims["exp"].(float64); ok {
						expiresAt = int64(exp)
					}
				}
			}
		}
	}

	userResponse := a.createUserResponse(userInfo, expiresAt, csrfToken)

	a.sendAPISuccess(w, "User data retrieved successfully", userResponse)
}

// refreshAuthTokens refreshes the auth tokens
func (a *AuthService) refreshAuthTokens(r *http.Request, w http.ResponseWriter, refreshToken, accessToken string) (*supabase.AuthenticatedDetails, error) {
	if refreshToken == "" {
		return nil, &AuthError{
			Code:       "MISSING_REFRESH_TOKEN",
			Message:    "No refresh token provided",
			StatusCode: http.StatusUnauthorized,
		}
	}

	ctx := r.Context()
	var newSession *supabase.AuthenticatedDetails

	err := withTimeoutContext(ctx, 10*time.Second, func(timeoutCtx context.Context) error {
		session, err := a.Supabase.Auth.RefreshUser(timeoutCtx, accessToken, refreshToken)
		if err == nil {
			newSession = session
		}
		return err
	})

	if err != nil || newSession == nil {
		a.logWithContext(r, "Token refresh failed: %v", err)

		// Clean auth cookies
		a.clearAuthCookies(w, r)

		return nil, &ErrSessionExpired
	}

	// Set New Cookies with new tokens
	a.setAuthCookies(w, r, newSession.AccessToken, newSession.RefreshToken, true)

	// Log success
	a.logWithContext(r, "Successfully refreshed auth tokens")

	return newSession, nil
}

// ForgotPasswordAPI handles POST requests to initiate password reset
func (a *AuthService) ForgotPasswordAPI(w http.ResponseWriter, r *http.Request) {
	a.logWithContext(r, "ForgotPasswordAPI attempt")

	// Decode Request Body
	var req PasswordResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.handleError(w, r, AuthError{Code: "INVALID_REQUEST", Message: "Invalid request body", StatusCode: http.StatusBadRequest, Internal: err})
		return
	}

	// Basic Validation
	if req.Email == "" {
		a.handleError(w, r, AuthError{Code: "MISSING_EMAIL", Message: "Email is required", StatusCode: http.StatusBadRequest})
		return
	}

	// Request Password Reset from Supabase
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	redirectTo := "/auth/reset-password"
	err := a.Supabase.Auth.ResetPasswordForEmail(ctx, req.Email, redirectTo)

	// Handle Response
	if err != nil {
		a.logWithContext(r, "Supabase ResetPasswordForEmail failed for %s: %v", maskEmail(req.Email), err)
	}

	a.logWithContext(r, "Password reset email requested for %s", maskEmail(req.Email))
	a.sendAPISuccess(w, "If an account exists for this email, password reset instructions have been sent.", nil)
}

// ============================================================================================
// Middleware Methods
// ============================================================================================

// responseWriter wraps http.ResponseWriter to capture the status code for logging
type responseWriter struct {
	http.ResponseWriter
	status int
}

// newResponseWriter wraps http.ResponseWriter to capture the status code for logging
func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{w, http.StatusOK}
}

// WriteHeader captures the status code for logging
func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// Recover middleware catches panics, logs them, and returns a generic server error
func (a *AuthService) Recover(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// Log stack trace
				buf := make([]byte, 1<<16)
				n := runtime.Stack(buf, true)
				a.Logger.Printf("PANIC recovered: %v\nRequest: %s %s\nStack trace:\n%s", err, r.Method, r.URL.Path, buf[:n])

				// Check if headers were already written
				if rw, ok := w.(*responseWriter); ok && rw.status != 0 {
					// Headers already written, just log
					a.Logger.Println("Headers already written, cannot send JSON error after panic")
				} else {
					apiErr := ErrServerError
					apiErr.Internal = fmt.Errorf("panic: %v", err)
					a.handleError(w, r, apiErr)
				}
			}
		}()
		next(w, r)
	}
}

// RequestLogger middleware logs the start and end of each request
func (a *AuthService) RequestLogger(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		isNextAsset := strings.HasPrefix(r.URL.Path, "/_next/")

		if !isNextAsset {
			a.logWithContext(r, "Request started")
		}

		// Capture status code and process the request
		rw := newResponseWriter(w)
		next(rw, r) // Execute the actual handler

		duration := time.Since(start)
		status := rw.status
		// Default to 200 if status wasn't explicitly set
		if status == 0 {
			status = http.StatusOK
		}

		if !isNextAsset {
			a.logWithContext(r, "Request completed: status=%d duration=%v", status, duration)
		}
	}
}

// RateLimitAuth middleware applies rate limiting based
func (a *AuthService) RateLimitAuth(limiter *rateLimiter) Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Extract client IP
			userIP, err := IpAddress(r)
			if err != nil {
				a.logWithContext(r, "[ERROR] Failed to extract IP address: %v", err)
				a.handleError(w, r, ErrServerError)
				return
			}
			ipString := userIP.String()

			// Check endpoint-specific limiter first
			if !limiter.Allow(ipString) {
				if DebugMode {
					a.logWithContext(r, "[DEBUG] Endpoint rate limit exceeded for %s on %s", ipString, r.URL.Path)
				}
				a.handleError(w, r, ErrRateLimitExceeded)
				return
			}

			// Check user-specific limiter
			if !limiter.Allow(ipString) {
				if DebugMode {
					a.logWithContext(r, "[DEBUG] User rate limit exceeded for %s on %s", ipString, r.URL.Path)
				}
				a.handleError(w, r, ErrRateLimitExceeded)
				return
			}

			// Request is within rate limits
			next(w, r)
		}
	}
}

func (a *AuthService) AuthContext(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		if DebugMode {
			a.logWithContext(r, "[AuthContext] %s request received for path: %s", r.Method, r.URL.Path)
		}
		var finalSessionData *UserSession
		ctx := r.Context()
		justRefreshed := false

		// Extract auth token from request
		token := extractAuthToken(r)
		if token == "" {
			if DebugMode {
				a.logWithContext(r, "[AuthContext] No auth token found in request.")
			}
			next(w, r.WithContext(ctx))
			return
		}
		// Extract user ID from token
		cookieObj, err := r.Cookie("auth_token")
		if err != nil || cookieObj.Value == "" {
			if DebugMode {
				a.logWithContext(r, "[AuthContext] No auth token cookie found in request.")
			}
			a.clearAuthCookies(w, r)
			next(w, r.WithContext(ctx))
			return
		}
		userID := extractUserIDFromToken(cookieObj.Value)

		// Try to get user session from cache
		cacheCheckStart := time.Now()
		if DebugMode {
			a.logWithContext(r, "[AuthContext] Checking cache for user %s", userID)
		}
		cachedSession, found := a.SessionCache.Get(userID)
		cacheCheckDuration := time.Since(cacheCheckStart)
		if DebugMode {
			a.logWithContext(r, "[AuthContext] Cache hit:%v time:%v", found, cacheCheckDuration)
		}

		// If we have a valid cached session, check if we need to refresh or can use it directly
		if found && cachedSession != nil && cachedSession.User != nil && cachedSession.User.UserId != "" {
			// Check if the session has a refresh token and might need refreshing
			if cachedSession.Tokens != nil &&
				cachedSession.Tokens.RefreshToken != nil &&
				cachedSession.Tokens.RefreshToken.Token != "" {
				if DebugMode {
					a.logWithContext(r, "[DEBUG] Found session with refresh token in cache for user %s", maskID(userID))
				}

				// Get current access token if available
				currentAccessToken := ""
				if cachedSession.Tokens.AccessToken != nil {
					currentAccessToken = cachedSession.Tokens.AccessToken.Token
					if DebugMode {
						a.logWithContext(r, "[DEBUG] Found access token in session cache for user %s", maskID(userID))
					}
				}

				// Attempt to refresh tokens
				refreshStart := time.Now()
				refreshToken := cachedSession.Tokens.RefreshToken.Token
				newSession, err := a.refreshAuthTokens(r, w, refreshToken, currentAccessToken)
				refreshDuration := time.Since(refreshStart)
				if DebugMode {
					a.logWithContext(r, "[DEBUG] Token refresh completed in %v, success: %v", refreshDuration, err == nil)
				}

				if err == nil && newSession != nil && newSession.User.ID != "" {
					// Refresh successful - create new session and update cache
					finalSessionData = a.createSession(&newSession.User, newSession.AccessToken, newSession.RefreshToken, newSession.ExpiresIn, r)
					if _, alreadyRefreshed := r.URL.Query()["refreshed"]; !alreadyRefreshed && finalSessionData != nil {
						a.SessionCache.Set(finalSessionData)
						justRefreshed = true
						if DebugMode {
							a.logWithContext(r, "[DEBUG] Refreshed session and updated cache for user %s", maskID(userID))
						}
						// Add query param to indicate this is a redirected request
						redirectURL := r.URL
						q := redirectURL.Query()
						q.Set("refreshed", "true")
						redirectURL.RawQuery = q.Encode()
						if DebugMode {
							a.logWithContext(r, "[DEBUG] Redirecting to %s", redirectURL.String())
						}
						ctx = context.WithValue(ctx, userContextKey, finalSessionData)
						next(w, r.WithContext(ctx))
						return
					}
				} else {
					// Refresh failed - will use cached session if it's still valid
					if DebugMode {
						a.logWithContext(r, "[DEBUG] Token refresh failed for user %s, will use cached session if valid", maskID(userID))
					}
				}
			} else {
				if DebugMode {
					a.logWithContext(r, "[DEBUG] Cached session found without refresh token for user %s (normal for non-refreshable tokens)", maskID(userID))
				}
			}
			// Use the cached session if we didn't refresh or refresh failed
			if !justRefreshed {
				if DebugMode {
					a.logWithContext(r, "[DEBUG] Using cached session for user %s", maskID(userID))
				}

				finalSessionData = cachedSession
				ctx = context.WithValue(ctx, userContextKey, finalSessionData)

				duration := time.Since(startTime)
				if DebugMode {
					a.logWithContext(r, "[DEBUG] Middleware completed in %v for path %s (using cache)", duration, r.URL.Path)
				}

				next(w, r.WithContext(ctx))
				return
			}
		} else {
			// No valid cached session found
			if found {
				a.logWithContext(r, "[DEBUG] Cache hit but session invalid for user %s", maskID(userID))
			} else {
				a.logWithContext(r, "[DEBUG] No cached session found for user %s", maskID(userID))
			}
		}

		// If we reached here, we need to validate the token
		log.Printf("[%s] AuthContext: Beginning token validation for user %s",
			time.Now().Format(time.RFC3339), maskID(userID))
		validationStart := time.Now()

		validatedUser, valid := validateAuthToken(a, ctx, token)
		validationDuration := time.Since(validationStart)
		log.Printf("[%s] AuthContext: Token validation completed in %v, valid: %v",
			time.Now().Format(time.RFC3339), validationDuration, valid)

		if !valid || validatedUser == nil {
			if DebugMode {
				a.logWithContext(r, "[%s][DEBUG] AuthContext: Token validation failed or returned nil user.",
					time.Now().Format(time.RFC3339))
			}
			log.Printf("[%s] AuthContext: Token validation failed for user %s",
				time.Now().Format(time.RFC3339), maskID(userID))

			if !justRefreshed {
				log.Printf("[%s] AuthContext: Clearing cookies and cache for user %s",
					time.Now().Format(time.RFC3339), maskID(userID))
				a.clearAuthCookies(w, r)
				a.SessionCache.Delete(userID)
			}
			next(w, r.WithContext(ctx))
			return
		}

		// Validation successful - create and cache session
		log.Printf("[%s] AuthContext: Token validation successful, creating session", time.Now().Format(time.RFC3339))
		finalSessionData = a.createSession(validatedUser, token, "", 0, r)

		if finalSessionData == nil {
			a.logWithContext(r, "[%s][ERROR] AuthContext: Failed to create session data after validation for user %s.",
				time.Now().Format(time.RFC3339), maskID(userID))
			log.Printf("[%s] AuthContext: Session creation failed after validation", time.Now().Format(time.RFC3339))
			a.clearAuthCookies(w, r)
			a.handleError(w, r, ErrServerError)
			return
		}

		if finalSessionData.User != nil && (finalSessionData.User.Role == "admin" || finalSessionData.User.Role == "root") {
			if spoofedTier, tierOK := finalSessionData.Metadata["spoofed_tier"].(string); tierOK && spoofedTier != "" {
				finalSessionData.Metadata["original_tier"] = finalSessionData.User.Tier
				finalSessionData.User.Tier = spoofedTier
				if DebugMode {
					log.Printf("[DEBUG] AuthContext: Applying spoofed tier '%s' for user %s", spoofedTier, maskID(finalSessionData.User.UserId))
				}
			}
			finalSessionData.Metadata["spoof_enabled"] = true
		}

		// Add session to context and proceed
		log.Printf("[%s] AuthContext: Adding validated session to cache for user %s",
			time.Now().Format(time.RFC3339), maskID(userID))
		a.SessionCache.Set(finalSessionData)
		ctx = context.WithValue(ctx, userContextKey, finalSessionData)

		duration := time.Since(startTime)
		log.Printf("[%s] AuthContext: Middleware completed in %v for path %s (using validation)",
			time.Now().Format(time.RFC3339), duration, r.URL.Path)

		next(w, r.WithContext(ctx))
	}
}

// AuthRequired middleware enforces authentication for protected routes
func (a *AuthService) AuthRequired(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Fast path: check for exempt paths
		if a.isExemptPath(path) {
			if DebugMode {
				a.logWithContext(r, "[DEBUG] AuthRequired: Path exempt from enforcement: %s", path)
			}
			next(w, r)
			return
		}

		if DebugMode {
			a.logWithContext(r, "[DEBUG] AuthRequired: Enforcing auth for path: %s", path)
		}

		// Get user session from context
		userSession := getUserSessionFromContext(r)
		if userSession == nil {
			if DebugMode {
				a.logWithContext(r, "[DEBUG] AuthRequired: No valid session for path %s", path)
			}
			a.handleError(w, r, ErrMissingToken)
			return
		}

		// Check user permissions for this route
		requiredPermission := a.findRequiredPermission(path)
		if requiredPermission == "" {
			// No specific permission needed for this path, just auth is enough
			if DebugMode {
				a.logWithContext(r, "[DEBUG] AuthRequired: No specific permission needed for %s", path)
			}
			next(w, r.WithContext(r.Context()))
			return
		}

		// Check if user has required permission
		if !a.hasPermission(userSession, requiredPermission) {
			// User doesn't have required permission
			if DebugMode {
				userID := getUserID(userSession)
				a.logWithContext(r, "[DEBUG] AuthRequired: Permission DENIED for user %s on path %s (requires %s)",
					userID, path, requiredPermission)
			}
			a.handleError(w, r, ErrPermissionDenied)
			return
		}

		// User has permission, proceed
		if DebugMode {
			userID := getUserID(userSession)
			a.logWithContext(r, "[DEBUG] AuthRequired: Permission GRANTED for user %s on path %s", userID, path)
		}
		next(w, r.WithContext(r.Context()))
	}
}

// handleError sends a standardized error API response
func (a *AuthService) handleError(w http.ResponseWriter, r *http.Request, err AuthError) {
	if err.Internal != nil && DebugMode {
		a.logWithContext(r, "API Error Internal (%s - %d): %v", err.Code, err.StatusCode, err.Internal)
	} else {
		a.logWithContext(r, "API Error (%s - %d): %s", err.Code, err.StatusCode, err.Message)
	}

	// For API requests - respond with JSON
	if strings.HasPrefix(r.URL.Path, "/api/") ||
		strings.HasPrefix(r.URL.Path, "/next-api/") ||
		strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(err.StatusCode)
		json.NewEncoder(w).Encode(APIResponse{
			Success: false,
			Error:   err.Message,
			Code:    err.Code,
		})
		return
	}

	// redirect to error page
	errorURL := "/error/" + err.Code
	http.Redirect(w, r, errorURL, http.StatusFound)
}

func (a *AuthService) createSession(user *supabase.User, accessToken, refreshToken string, expiresIn int, r *http.Request) *UserSession {
	if user == nil || user.ID == "" {
		a.logWithContext(r, "[ERROR] createSession: Attempted to create session for nil or empty user ID.")
		return nil
	}

	permissions, userRole, userTier, permErr := a.getUserPermissions(user.ID)
	if permErr != nil {
		a.logWithContext(r, "[ERROR] createSession: Failed to get permissions/role/tier for user %s: %v. Aborting session creation.", maskID(user.ID), permErr)
		return nil
	}
	if DebugMode {
		a.logWithContext(r, "[DEBUG] createSession: Using Role=%s, Tier=%s obtained from getUserPermissions for user %s", userRole, userTier, maskID(user.ID))
	}

	csrfToken, csrfErr := a.generateCSRFToken(user.ID)
	if csrfErr != nil {
		a.logWithContext(r, "[ERROR] createSession: Failed to generate CSRF token for user %s: %v", maskID(user.ID), csrfErr)
		csrfToken = ""
	}

	session := &UserSession{
		UserId:     user.ID,
		CreatedAt:  time.Now(),
		LastActive: time.Now(),
		User: &UserData{
			UserId: user.ID,
			Email:  user.Email,
			Role:   userRole,
			Tier:   userTier,
		},
		Permissions: permissions,
		Metadata:    make(map[string]any),
		Tokens: &AuthTokens{
			CSRFToken: csrfToken,
		},
	}

	if user.UserMetadata != nil {
		for k, v := range user.UserMetadata {
			if k != "role" && k != "tier" {
				session.Metadata[k] = v
			}
		}

		if metaRole, ok := user.UserMetadata["role"].(string); ok && metaRole != userRole && DebugMode {
			a.logWithContext(r, "[DEBUG] createSession: Supabase UserMetadata role '%s' differs from determined role '%s' for user %s", metaRole, userRole, maskID(user.ID))
		}
		if metaTier, ok := user.UserMetadata["tier"].(string); ok && metaTier != userTier && DebugMode {
			a.logWithContext(r, "[DEBUG] createSession: Supabase UserMetadata tier '%s' differs from determined tier '%s' for user %s", metaTier, userTier, maskID(user.ID))
		}
	}

	// Set Access/Refresh tokens if provided
	if accessToken != "" {
		accessExpiresAt := calculateExpiresAt(time.Now(), time.Duration(expiresIn)*time.Second)
		session.Tokens.AccessToken = &AccessToken{
			Token:     accessToken,
			ExpiresAt: accessExpiresAt,
		}

		if refreshToken != "" {
			refreshDuration := a.Config.SignatureTTL
			refreshExpiresAt := calculateExpiresAt(time.Now(), time.Duration(refreshDuration)*time.Second)
			session.Tokens.RefreshToken = &RefreshToken{
				Token:     refreshToken,
				ExpiresAt: refreshExpiresAt,
			}
		}
	} else if DebugMode {
		a.logWithContext(r, "[DEBUG] createSession: No access token provided during session creation for user %s", maskID(user.ID))
	}

	if DebugMode {
		a.logWithContext(r, "[DEBUG] createSession: Final session object created for user %s: Role=%s, Tier=%s", maskID(user.ID), session.User.Role, session.User.Tier)
	}

	return session
}

// findRequiredPermission finds the permission key required for a path
func (a *AuthService) findRequiredPermission(path string) string {
	for key, nav := range a.Navs {
		if nav.Link == path || slices.Contains(nav.SubPages, path) {
			return key
		}
	}
	return ""
}

// hasPermission provides a consistent method for checking user permissions
func (a *AuthService) hasPermission(userSession *UserSession, permission string) bool {
	if userSession == nil || userSession.Permissions == nil {
		return false
	}

	// Check for explicit permission
	if _, ok := userSession.Permissions[permission]; ok {
		return true
	}

	// Check for wildcard permissions
	if _, ok := userSession.Permissions["*"]; ok {
		return true
	}

	if DebugMode {
		if userSession.User != nil {
			a.Logger.Printf("[DEBUG] hasPermission: User %s (Role: %s) lacks permission '%s'",
				maskEmail(userSession.User.Email), userSession.User.Role, permission)
		} else {
			a.Logger.Printf("[DEBUG] hasPermission: Anonymous user lacks permission '%s'", permission)
		}
	}

	return false
}

// getUserID extracts a user ID for logging
func getUserID(session *UserSession) string {
	if session == nil || session.UserId == "" {
		return "unknown"
	}
	return maskID(session.UserId)
}

// isExemptMethod returns true if the HTTP method doesn't need CSRF protection
func isExemptMethod(method string) bool {
	return method == "GET" || method == "HEAD" || method == "OPTIONS"
}

// getUserSessionFromContext extracts the UserSession from a request's context
func getUserSessionFromContext(r *http.Request) *UserSession {
	sessionData := r.Context().Value(userContextKey)
	if sessionData == nil {
		return nil
	}

	userSession, ok := sessionData.(*UserSession)
	if !ok || userSession == nil {
		return nil
	}

	return userSession
}

// ============================================================================================
// Asset Serving
// ============================================================================================

// handleAuthAsset serves static assets from the embedded NextJs FS
func (a *AuthService) handleAuthAsset(w http.ResponseWriter, r *http.Request) {
	requestPath := r.URL.Path
	var relativePath string
	var baseEmbedDir string
	var isNextAsset bool

	// Determine prefix and base directory in embed FS
	if strings.HasPrefix(requestPath, "/_next/") {
		// For /_next/ assets, the path inside embed is directly under nextAuth/out/_next
		relativePath = strings.TrimPrefix(requestPath, "/_next")
		baseEmbedDir = "nextAuth/out/_next"
		isNextAsset = true
	} else if strings.HasPrefix(requestPath, "/auth/") {
		// For /auth/ assets, the path inside embed is relative to nextAuth/out
		relativePath = strings.TrimPrefix(requestPath, "/auth")
		baseEmbedDir = "nextAuth/out"
		isNextAsset = false
	} else {
		a.logWithContext(r, "handleAuthAsset: Unexpected path prefix: %s", requestPath)
		http.NotFound(w, r)
		return
	}

	if !isNextAsset && (relativePath == "" || relativePath == "/") {
		a.logWithContext(r, "handleAuthAsset: Empty path for /auth/, serving default index.html")
		relativePath = "/index.html"
	}

	fsPath := path.Join(baseEmbedDir, strings.TrimPrefix(relativePath, "/"))
	ext := filepath.Ext(relativePath)
	contentType := contentTypeMap[ext]

	if contentType == "" {
		switch ext {
		case ".js":
			contentType = "application/javascript"
		case ".css":
			contentType = "text/css"

		default:
			contentType = "application/octet-stream" // Fallback for truly unknown types
			// Log if defaulting for a non-_next asset
			if !isNextAsset && DebugMode {
				a.logWithContext(r, "[DEBUG] handleAuthAsset: Unknown content type for '%s', defaulting to octet-stream", ext)
			}
		}
	}
	w.Header().Set("Content-Type", contentType)

	data, err := authAssets.ReadFile(fsPath)
	if err != nil {
		// Specific handling for /auth page routes needing .html appended
		if !isNextAsset && ext == "" && !strings.Contains(relativePath, ".") { // Check if it looks like a page route
			fsPathHTML := fsPath + ".html"
			dataHTML, errHTML := authAssets.ReadFile(fsPathHTML)
			if errHTML == nil {
				w.Header().Set("Content-Type", "text/html")
				w.Write(dataHTML)
				return
			}
			// Log original error if .html fallback also failed
			a.logWithContext(r, "handleAuthAsset: Asset not found (and .html fallback failed): %s -> %s. Error: %v", requestPath, fsPath, err)
		} else {
			// Log standard file not found error
			a.logWithContext(r, "handleAuthAsset: Asset not found: %s -> %s. Error: %v", requestPath, fsPath, err)
		}

		http.NotFound(w, r)
		return
	}

	if DebugMode && !isNextAsset {
		a.logWithContext(r, "[DEBUG] handleAuthAsset: Successfully served: %s -> %s", requestPath, fsPath)
	}
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// getTierFromUser extracts tier from user metadata
func getTierFromUser(userInfo *supabase.User) string {
	if userInfo.UserMetadata != nil {
		if tierVal, ok := userInfo.UserMetadata["tier"].(string); ok && tierVal != "" {
			return tierVal
		}
	}
	return "free" // Default tier
}

// Helper function to extract user ID from token
func extractUserIDFromToken(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) == 3 {
		if payload, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
			var claims map[string]any
			if json.Unmarshal(payload, &claims) == nil {
				if sub, ok := claims["sub"].(string); ok {
					return sub
				}
			}
		}
	}
	return ""
}

// extractAuthToken extracts the auth token from the request
func extractAuthToken(r *http.Request) string {
	// Try cookie first
	if authCookie, err := r.Cookie("auth_token"); err == nil && authCookie.Value != "" {
		return authCookie.Value
	}

	// Then try Authorization header
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	// Try query parameter for API use (mostly)
	if token := r.URL.Query().Get("access_token"); token != "" {
		return token
	}

	return ""
}

// Helper function to validate token
func validateAuthToken(a *AuthService, ctx context.Context, token string) (*supabase.User, bool) {
	if token == "" {
		if DebugMode {
			a.Logger.Printf("[DEBUG] validateAuthToken: Empty token provided")
		}
		return nil, false
	}

	// Check token format
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		if DebugMode {
			a.Logger.Printf("[DEBUG] validateAuthToken: Invalid token format")
		}
		return nil, false
	}

	// Create timeout context
	validateCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Validate token with Supabase
	user, err := a.Supabase.Auth.User(validateCtx, token)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "expired") {
			if DebugMode {
				a.Logger.Printf("[DEBUG] validateAuthToken: Token expired")
			}
			return nil, false
		}
		if DebugMode {
			a.Logger.Printf("[DEBUG] validateAuthToken: Token validation failed: %v", err)
		}
		return nil, false
	}

	if user == nil {
		if DebugMode {
			a.Logger.Printf("[DEBUG] validateAuthToken: Token validated but user object is nil")
		}
		return nil, false
	}

	if DebugMode {
		a.Logger.Printf("[DEBUG] validateAuthToken: Valid user found via token: %s (ID: %s)",
			maskEmail(user.Email), maskID(user.ID))
	}

	return user, true
}

// calculateExpiresAt calculates the expiration time for a token
func calculateExpiresAt(createdAt time.Time, duration time.Duration) int64 {
	return createdAt.Add(duration).Unix()
}
