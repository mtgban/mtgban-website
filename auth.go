package main

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	supabase "github.com/nedpals/supabase-go"
	"golang.org/x/exp/slices"
	"golang.org/x/time/rate"
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
	aclContextKey   ctxKey = "acl"
	spoofContextKey ctxKey = "spoof"
	MTGBAN_ROLE     ctxKey = "mtgban_website"
)

// session cache settings
const (
	sessionCacheTTL     = 3 * time.Hour
	sessionCacheMaxSize = 2000
	cacheCleanInterval  = 1 * time.Hour
)

// Session cache to reduce backend lookups
var (
	userSessionCache      = make(map[string]*UserSession)
	userSessionCacheMutex sync.RWMutex
	cacheCleanerStarted   sync.Once
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
	SupabaseURL     string   `json:"supabase_url"`
	SupabaseAnonKey string   `json:"supabase_anon_key"`
	SupabaseRoleKey string   `json:"supabase_role_key"`
	SupabaseSecret  string   `json:"supabase_jwt_secret"`
	DebugMode       bool     `json:"debug_mode"`
	LogPrefix       string   `json:"log_prefix"`
	ExemptRoutes    []string `json:"exempt_routes"`
	ExemptPrefixes  []string `json:"exempt_prefixes"`
	ExemptSuffixes  []string `json:"exempt_suffixes"`
	CSRFPath        string   `json:"csrf_path"`
	CSRFInterval    int      `json:"csrf_interval"`
}

// AuthService handles all authentication-related functionality
type AuthService struct {
	Logger     *log.Logger
	Supabase   *supabase.Client
	MTGBAN     *supabase.Client
	Config     AuthConfig
	CSRF       *CSRF
	ACL        *BanACL
	Navs       map[string]*NavElem
	IPLimiters sync.Map
}

// AuthToken represents the authentication token for a user
type AuthToken struct {
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
	AccessToken  *AuthToken    `json:"access_token"`
	RefreshToken *RefreshToken `json:"refresh_token"`
	CSRFToken    string        `json:"csrf_token"`
}

// UserSession represents cached user data and permissions for authentication
type UserSession struct {
	UserId      string                 `json:"user_id"`
	Tokens      *AuthTokens            `json:"tokens"`
	User        *UserData              `json:"user"`
	Permissions map[string]interface{} `json:"permissions"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
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
	Success    bool        `json:"success"`
	Message    string      `json:"message,omitempty"`
	Error      string      `json:"error,omitempty"`
	Code       string      `json:"code,omitempty"`
	Data       interface{} `json:"data,omitempty"`
	RedirectTo string      `json:"redirectTo,omitempty"`
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
	UserData    *UserData              `json:"user"`
	Permissions map[string]interface{} `json:"permissions"`
}

// BanACL holds the Access Control List, mapping emails to user permissions
type BanACL struct {
	Users map[string]*BanUser

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
		Email    string                 `json:"email"`
		Password string                 `json:"password"`
		UserData map[string]interface{} `json:"userData"`
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

// DefaultAuthConfig returns the default configuration
func DefaultAuthConfig() AuthConfig {
	return AuthConfig{
		LogPrefix: "AUTH ",
		ExemptRoutes: []string{
			"/",
			"/home",
			"/search",
			"/favicon.ico",
		},
		ExemptPrefixes: []string{
			"/auth/",
			"/next-api/auth/",
			"/api/search/",
			"/api/suggest/",
			"/css/",
			"/js/",
			"/img/",
		},
		ExemptSuffixes: []string{
			".css", ".js", ".ico", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".map",
		},
	}
}

// LoadAuthConfig loads auth configuration from a file, falling back to defaults
func LoadAuthConfig(filePath string) (AuthConfig, error) {
	config := DefaultAuthConfig()

	if filePath == "" {
		return config, nil
	}

	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Auth config file '%s' not found, using defaults.", filePath)
			return config, nil
		}
		return config, fmt.Errorf("failed to open auth config file '%s': %w", filePath, err)
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(&config); err != nil {
		log.Printf("Warning: Failed to parse auth config file '%s', continuing with potential defaults: %v", filePath, err)
		return DefaultAuthConfig(), fmt.Errorf("failed to parse auth config file '%s': %w", filePath, err)
	}

	return config, nil
}

// Validation checks
func (c AuthConfig) Validate() error {
	if c.SupabaseURL == "" {
		return errors.New("AuthConfig: SupabaseURL is required")
	}
	if c.SupabaseAnonKey == "" {
		return errors.New("AuthConfig: SupabaseAnonKey is required (for client-side interaction)")
	}
	if c.SupabaseSecret == "" {
		log.Println("Warning: AuthConfig: SupabaseSecret is not set. Backend operations requiring admin privileges might fail.")
	}
	return nil
}

// NewAuthService creates and initializes a new AuthService instance
func NewAuthService(config AuthConfig, extraNavs map[string]*NavElem) (*AuthService, error) {
	// Validate config first
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid auth config: %w", err)
	}
	// Setup logging
	var logger *log.Logger
	logFilePath := path.Join(LogDir, "auth.log")
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0660)
	if err != nil {
		// Fallback to stdout if file cannot be opened
		log.Printf("Warning: Failed to open log file '%s', falling back to stdout: %v", logFilePath, err)
		logger = log.New(os.Stdout, config.LogPrefix, log.LstdFlags|log.Lshortfile)
		logger.Println("Logger initialized to stdout.")
	} else {
		logger = log.New(logFile, config.LogPrefix, log.LstdFlags|log.Lshortfile)
		logger.Printf("Logging to file: %s", logFilePath)
		logger.Println("Logger initialized to file.")
	}

	// Initialize Supabase clients
	supabaseClient := supabase.CreateClient(config.SupabaseURL, config.SupabaseAnonKey)
	if supabaseClient == nil {
		return nil, errors.New("failed to create Supabase client")
	}

	// Initialize MTGBAN client
	mtgbanClient, err := CustomRoleClient(config.SupabaseURL, config.SupabaseRoleKey, string(MTGBAN_ROLE))
	if err != nil {
		return nil, fmt.Errorf("failed to create MTGBAN client: %w", err)
	}

	logger.Printf("Supabase client initialized for URL: %s", config.SupabaseURL)

	// Create the service instance
	service := &AuthService{
		Logger:     logger,
		Supabase:   supabaseClient,
		MTGBAN:     mtgbanClient,
		Config:     config,
		CSRF:       nil,
		ACL:        &BanACL{Users: make(map[string]*BanUser)},
		Navs:       extraNavs,
		IPLimiters: sync.Map{},
	}

	csrf, err := NewCSRF(config.CSRFPath, service.Logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSRF: %w", err)
	}

	service.CSRF = csrf

	service.Logger.Printf("AuthService created successfully.")
	if config.DebugMode {
		service.Logger.Println("Debug mode enabled. Printing embedded auth assets:")
		service.printEmbeddedFS(authAssets, "nextAuth/out", "")
	}

	return service, nil
}

// LoadBanACL fetches ACL data from the Supabase DB and populates the service's BanACL struct
func (a *AuthService) LoadBanACL() error {
	a.Logger.Println("Loading BAN ACL data...")
	var banUsersData []struct {
		UserId      string                 `json:"user_id"`
		Email       string                 `json:"email"`
		Tier        string                 `json:"tier"`
		Role        string                 `json:"role"`
		Permissions map[string]interface{} `json:"permissions"`
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err := a.MTGBAN.DB.From("acl").Select("user_id,email,tier,role,permissions").ExecuteWithContext(ctx, &banUsersData)
	if err != nil {
		a.Logger.Printf("Error fetching BAN ACL data: %v", err)
		return fmt.Errorf("failed to fetch ban_acl data from Supabase: %w", err)
	}

	a.ACL.mux.Lock()
	defer a.ACL.mux.Unlock()

	// create a new map
	newUsers := make(map[string]*BanUser)

	for _, userData := range banUsersData {
		permsCopy := make(map[string]interface{})
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
			permsCopy := make(map[string]interface{}, len(user.Permissions))
			for k, v := range user.Permissions {
				permsCopy[k] = v
			}
			userCopy.Permissions = permsCopy

			userDataCopy := *user.UserData
			userCopy.UserData = &userDataCopy

			if a.Config.DebugMode {
				a.Logger.Printf("[DEBUG] getUserByID: Found user with ID %s", maskID(userID))
			}

			return &userCopy, true
		}
	}

	if a.Config.DebugMode {
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
	permsCopy := make(map[string]interface{}, len(user.Permissions))
	for k, v := range user.Permissions {
		permsCopy[k] = v
	}
	userCopy.Permissions = permsCopy

	userDataCopy := *user.UserData
	userCopy.UserData = &userDataCopy

	return &userCopy, true
}

// getUserPermissions retrieves the effective permissions for a user by ID
func (a *AuthService) getUserPermissions(userId string) (map[string]interface{}, error) {
	userRole := "user"
	userTier := "free"
	permissions := make(map[string]interface{})

	// try BAN ACL first
	banUser, banFound := a.getUserByID(userId)
	if banFound {
		userRole = banUser.UserData.Role
		userTier = banUser.UserData.Tier

		// deep copy to prevent race conditions
		permsCopy := make(map[string]interface{}, len(banUser.Permissions))
		for k, v := range banUser.Permissions {
			permsCopy[k] = v
		}
		permissions = permsCopy

		if a.Config.DebugMode {
			a.Logger.Printf("[DEBUG] getUserPermissions: Found user %s in BAN ACL (Role: %s, Tier: %s)",
				maskEmail(banUser.UserData.Email), userRole, userTier)
		}
		return permissions, nil
	}

	// get user details from Supabase if not in ACL
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	user, err := a.Supabase.Auth.User(ctx, userId)
	if err != nil {
		a.Logger.Printf("Failed to get user details from Supabase for ID %s: %v", maskID(userId), err)
		return nil, fmt.Errorf("failed to get user details: %w", err)
	}

	// get role/tier from metadata
	if user.UserMetadata != nil {
		if metaRole, ok := user.UserMetadata["role"].(string); ok && metaRole != "" {
			userRole = metaRole
		}
		if metaTier, ok := user.UserMetadata["tier"].(string); ok && metaTier != "" {
			userTier = metaTier
		}
	}

	// get permissions based on role/tier
	err = a.setPermissions(userRole, userTier, &permissions)
	if err != nil {
		a.Logger.Printf("Error setting permissions from role/tier for user %s: %v", maskID(userId), err)
	}

	if a.Config.DebugMode {
		a.Logger.Printf("[DEBUG] getUserPermissions: Retrieved permissions for user %s (Role: %s, Tier: %s) from Supabase",
			maskID(userId), userRole, userTier)
	}

	return permissions, nil
}

// setPermissions is a helper function to set permissions based on role and tier
func (a *AuthService) setPermissions(userRole string, userTier string, permissions *map[string]interface{}) error {
	// try tier permissions first
	tierPerms, tierName, tierFound := a.getACLDataByTierRole(userTier)
	if tierFound {
		// Copy permissions
		for k, v := range tierPerms {
			(*permissions)[k] = v
		}

		if a.Config.DebugMode {
			a.Logger.Printf("[DEBUG] setPermissions: Applied tier permissions for %s", tierName)
		}
	}

	// Add role permissions (these can override tier permissions)
	rolePerms, roleName, roleFound := a.getACLDataByTierRole(userRole)
	if roleFound {
		// Copy permissions
		for k, v := range rolePerms {
			(*permissions)[k] = v
		}

		if a.Config.DebugMode {
			a.Logger.Printf("[DEBUG] setPermissionsFromRoleTier: Applied role permissions for %s", roleName)
		}
	}

	// If neither found, use default user permissions
	if !tierFound && !roleFound {
		defaultPerms, _, defaultFound := a.getACLDataByTierRole("user")
		if defaultFound {
			for k, v := range defaultPerms {
				(*permissions)[k] = v
			}

			if a.Config.DebugMode {
				a.Logger.Printf("[DEBUG] setPermissionsFromRoleTier: Applied default user permissions")
			}
		} else {
			return fmt.Errorf("no permissions found for role %s, tier %s, or default user", userRole, userTier)
		}
	}

	return nil
}

// getACLDataByTierRole retrieves the effective permissions for a given tier or role name.
func (a *AuthService) getACLDataByTierRole(name string) (map[string]interface{}, string, bool) {
	if tierData, exists := Config.ACL.Tiers[name]; exists {
		perms := make(map[string]interface{})
		for _, settings := range tierData {
			for key, value := range settings {
				perms[key] = value
			}
		}
		return perms, name, true
	}

	// Check Roles if not found as a Tier
	if roleData, exists := Config.ACL.Roles[name]; exists {
		perms := make(map[string]interface{})
		for _, settings := range roleData {
			for key, value := range settings {
				perms[key] = value
			}
		}
		return perms, name, true
	}

	// name not found as a tier or role
	return nil, "", false
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
		if path == route && a.Config.DebugMode {
			a.Logger.Printf("Path '%s' is exempt (exact match: '%s')", path, route)
			return true
		}
		if path == route {
			return true
		}
	}

	// Check prefix matches
	for _, prefix := range a.Config.ExemptPrefixes {
		if strings.HasPrefix(path, prefix) && a.Config.DebugMode {
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
		if strings.HasSuffix(cleanedPath, suffix) && a.Config.DebugMode {
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

// Debug function to print embedded FS structure
func (a *AuthService) printEmbeddedFS(fsys embed.FS, dir string, indent string) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		a.Logger.Printf("%sError reading dir %s: %v", indent, dir, err)
		return
	}

	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())

		if entry.IsDir() {
			a.Logger.Printf("%s[DIR] %s", indent, path)
		} else {
			a.Logger.Printf("%s[FILE] %s", indent, path)
		}
	}
}

// ============================================================================================
// AuthService Core Logic Methods
// ============================================================================================

// logWithContext logs messages with request context
func (a *AuthService) logWithContext(r *http.Request, format string, v ...interface{}) {
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
				var claims map[string]interface{}
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
func (a *AuthService) sendAPISuccess(w http.ResponseWriter, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: message,
		Data:    data,
	})
}

// handleAPIError sends a standardized error API response
func (a *AuthService) handleAPIError(w http.ResponseWriter, r *http.Request, err AuthError) {
	// Log internal error details if present and in debug mode
	if err.Internal != nil && a.Config.DebugMode {
		a.logWithContext(r, "API Error Internal (%s - %d): %v", err.Code, err.StatusCode, err.Internal)
	} else {
		a.logWithContext(r, "API Error (%s - %d): %s", err.Code, err.StatusCode, err.Message)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.StatusCode)
	json.NewEncoder(w).Encode(APIResponse{
		Success: false,
		Error:   err.Message,
		Code:    err.Code,
	})
}

// setAuthCookies sets the necessary authentication cookies
func (a *AuthService) setAuthCookies(w http.ResponseWriter, r *http.Request, token, refreshToken string, rememberMe bool) {
	// Determine cookie security settings
	isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	sameSiteMode := a.getCookieSameSiteMode()

	// Set auth token cookie
	maxAge := 0
	if rememberMe {
		maxAge = 30 * 24 * 60 * 60 // 30 days
	} else {
		maxAge = 24 * 60 * 60 // 24 hours
	}
	a.setCookie(w, "auth_token", token, maxAge, true, isSecure, http.SameSiteLaxMode)

	// Set refresh token with longer expiry
	refreshMaxAge := 60 * 24 * 60 * 60 // 60 days
	a.setCookie(w, "refresh_token", refreshToken, refreshMaxAge, true, isSecure, sameSiteMode)

	a.logWithContext(r, "Set auth cookies (MaxAge: %ds, RefreshMaxAge: %ds, Secure: %v, SameSite: %v)",
		maxAge, refreshMaxAge, isSecure, sameSiteMode)
}

// clearAuthCookies removes authentication cookies
func (a *AuthService) clearAuthCookies(w http.ResponseWriter, r *http.Request) {
	// Determine cookie security setting
	isSecure := r.TLS != nil || !a.Config.DebugMode

	// Remove multiple cookies in one go
	cookieNames := []string{"auth_token", "refresh_token", "csrf_token"}
	for _, name := range cookieNames {
		a.setCookie(w, name, "", -1, name != "csrf_token", isSecure, http.SameSiteLaxMode)
	}

	a.logWithContext(r, "Cleared auth cookies (auth_token, refresh_token, csrf_token)")
}

// setCookie is a helper function to create and set a cookie
func (a *AuthService) setCookie(w http.ResponseWriter, name, value string, maxAge int, httpOnly, secure bool, sameSite http.SameSite) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   Config.Auth.Domain,
		HttpOnly: httpOnly,
		MaxAge:   maxAge,
		Secure:   secure,
		SameSite: sameSite,
	}

	// Set expires time if removing cookie
	if maxAge < 0 {
		cookie.Expires = time.Unix(0, 0)
	}

	http.SetCookie(w, cookie)
}

// getCookieSameSiteMode returns the appropriate SameSite mode based on configuration
func (a *AuthService) getCookieSameSiteMode() http.SameSite {
	if a.Config.DebugMode {
		return http.SameSiteLaxMode
	}
	return http.SameSiteStrictMode
}

// parseAndValidateRequest is a generic helper for parsing and validating JSON requests
func (a *AuthService) parseAndValidateRequest(r *http.Request, req interface{}, validator func() *AuthError) *AuthError {
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
			if a.Config.DebugMode {
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
		a.handleAPIError(w, r, *authErr)
		return
	}

	authResponse, userInfo, authErrInternal := a.authenticateUser(r, req.Email, req.Password)
	if authErrInternal != nil {
		// Try to cast to AuthError for specific codes
		var authErr AuthError
		if errors.As(authErrInternal, &authErr) {
			a.handleAPIError(w, r, authErr)
		} else {
			// Generic auth failed
			a.handleAPIError(w, r, AuthError{
				Code:       "AUTH_FAILED",
				Message:    "Authentication failed",
				StatusCode: http.StatusUnauthorized,
				Internal:   authErrInternal,
			})
		}
		return
	}

	a.logWithContext(r, "[DEBUG] LoginAPI: Authentication successful for %s", maskEmail(req.Email))

	csrfToken, csrfErr := a.generateCSRFToken(userInfo.ID)
	if csrfErr != nil {
		a.logWithContext(r, "[ERROR] LoginAPI: Failed to generate CSRF token: %v", csrfErr)
		a.handleAPIError(w, r, AuthError{
			Code:       "CSRF_TOKEN_GENERATION_FAILED",
			Message:    "Failed to generate CSRF token",
			StatusCode: http.StatusInternalServerError,
			Internal:   csrfErr,
		})
		return
	}
	a.logWithContext(r, "[DEBUG] LoginAPI: CSRF token generated.")
	a.setAuthCookies(w, r, authResponse.AccessToken, authResponse.RefreshToken, req.Remember)
	a.setCSRFCookie(w, r, csrfToken)

	a.logWithContext(r, "[DEBUG] LoginAPI: Finished attempting to set cookies.")

	expiresAt := time.Now().Add(time.Duration(authResponse.ExpiresIn) * time.Second).Unix()
	userResponseData := UserResponse{
		UserId:    userInfo.ID,
		Email:     userInfo.Email,
		Tier:      getTierFromUser(userInfo),
		ExpiresAt: expiresAt,
		CSRFToken: csrfToken,
	}

	a.logWithContext(r, "LoginAPI successful for %s (Tier: %s, Role: %s)", maskEmail(req.Email), userResponseData.Tier, userResponseData.Role)
	// Pass userResponseData directly as Data
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
		a.handleAPIError(w, r, *authErr)
		return
	}

	// Create the user in Supabase
	if req.UserData == nil {
		req.UserData = make(map[string]interface{})
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
			a.handleAPIError(w, r, ErrEmailTaken)
		} else {
			a.handleAPIError(w, r, AuthError{Code: "SIGNUP_FAILED", Message: "Failed to create account", StatusCode: http.StatusInternalServerError, Internal: err})
		}
		return
	}
	// attempt Auto-Login after successful signup
	ctx = r.Context()
	authResponse, userInfo, _ := a.performSupabaseAuth(ctx, req.Email, req.Password)
	if authResponse != nil && userInfo != nil {
		csrfToken, err := a.generateCSRFToken(userInfo.ID)
		if err != nil {
			a.handleAPIError(w, r, AuthError{Code: "CSRF_TOKEN_GENERATION_FAILED", Message: "Failed to generate CSRF token", StatusCode: http.StatusInternalServerError, Internal: err})
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

	a.sendAPISuccess(w, "Logout successful", map[string]interface{}{"redirectTo": "/"})
}

// RefreshTokenAPI handles POST requests to explicitly refresh the session tokens
func (a *AuthService) RefreshTokenAPI(w http.ResponseWriter, r *http.Request) {
	a.logWithContext(r, "RefreshTokenAPI attempt")

	// Get refresh token from cookie
	refreshCookie, refreshErr := r.Cookie("refresh_token")
	if refreshErr != nil || refreshCookie.Value == "" {
		a.logWithContext(r, "RefreshTokenAPI failed: Missing refresh_token cookie.")
		a.handleAPIError(w, r, ErrMissingToken)
		return
	}
	refreshToken := refreshCookie.Value

	newSession, err := a.refreshAuthTokens(r, w, refreshToken, "")
	if err != nil {
		a.handleAPIError(w, r, AuthError{
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
		a.handleAPIError(w, r, AuthError{
			Code:       "CSRF_TOKEN_GENERATION_FAILED",
			Message:    "Failed to generate CSRF token",
			StatusCode: http.StatusInternalServerError,
			Internal:   err,
		})
		return
	}
	a.setCSRFCookie(w, r, csrfToken)

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
			UserMetadata: map[string]interface{}{
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
			a.handleAPIError(w, r, ErrMissingToken)
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
			a.handleAPIError(w, r, AuthError{
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
		a.handleAPIError(w, r, ErrMissingToken)
		return
	}

	// Generate and Set CSRF Token
	csrfToken, genErr := a.generateCSRFToken(userInfo.ID)
	if genErr != nil {
		a.handleAPIError(w, r, AuthError{
			Code:       "CSRF_TOKEN_GENERATION_FAILED",
			Message:    "Failed to generate CSRF token",
			StatusCode: http.StatusInternalServerError,
			Internal:   genErr,
		})
		return
	}
	a.setCSRFCookie(w, r, csrfToken)

	// Estimate session expiry
	expiresAt := time.Now().Add(24 * time.Hour).Unix()
	if authCookie, err := r.Cookie("auth_token"); err == nil && authCookie.Value != "" {
		// Attempt to get actual expiry from token if available
		parts := strings.Split(authCookie.Value, ".")
		if len(parts) == 3 {
			if payload, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
				var claims map[string]interface{}
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
		a.handleAPIError(w, r, AuthError{Code: "INVALID_REQUEST", Message: "Invalid request body", StatusCode: http.StatusBadRequest, Internal: err})
		return
	}

	// Basic Validation
	if req.Email == "" {
		a.handleAPIError(w, r, AuthError{Code: "MISSING_EMAIL", Message: "Email is required", StatusCode: http.StatusBadRequest})
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
					a.handleAPIError(w, r, apiErr)
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

// RateLimitAuth middleware applies rate limiting based on IP address for auth-related actions
func (a *AuthService) RateLimitAuth(limiter *rate.Limiter) Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Extract client IP once
			ip := getClientIP(r)

			// Check endpoint-specific limiter first (most restrictive)
			if !limiter.Allow() {
				if a.Config.DebugMode {
					a.logWithContext(r, "[DEBUG] Rate limit exceeded for endpoint %s", r.URL.Path)
				}
				a.handleAPIError(w, r, ErrRateLimitExceeded)
				return
			}

			// Then check IP-based general limiter
			ipLimiter := a.getIPLimiter(ip)
			if !ipLimiter.Allow() {
				if a.Config.DebugMode {
					a.logWithContext(r, "[DEBUG] IP-based rate limit exceeded for %s on %s", ip, r.URL.Path)
				}
				a.handleAPIError(w, r, ErrRateLimitExceeded)
				return
			}

			// Request is within rate limits
			next(w, r)
		}
	}
}

// getIPLimiter retrieves or creates a rate limiter for a specific IP address
func (a *AuthService) getIPLimiter(ip string) *rate.Limiter {
	// Default rate: 20 requests per 2 seconds (100ms interval)
	const defaultRate = 100 * time.Millisecond
	const defaultBurst = 20

	// Get existing limiter or create a new one
	limiterI, _ := a.IPLimiters.LoadOrStore(ip, rate.NewLimiter(rate.Every(defaultRate), defaultBurst))
	return limiterI.(*rate.Limiter)
}

// getStringFromMetadata safely gets a string from metadata
func getStringFromMetadata(metadata map[string]interface{}, key, defaultValue string) string {
	if metadata == nil {
		return defaultValue
	}

	if value, ok := metadata[key].(string); ok && value != "" {
		return value
	}

	return defaultValue
}

// calculateExpiresAt calculates the expiration time for a token
func calculateExpiresAt(createdAt time.Time, duration time.Duration) int64 {
	return createdAt.Add(duration).Unix()
}

// AuthContext middleware attempts to authenticate the user via cache, refresh, or token validation
func (a *AuthService) AuthContext(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var finalSessionData *UserSession
		ctx := r.Context()

		// Extract auth token from request
		token := extractAuthToken(r)
		if token == "" {
			if a.Config.DebugMode {
				a.logWithContext(r, "[DEBUG] AuthContext: No auth token found in request.")
			}
			// Proceed without user context if no token is present
			next(w, r.WithContext(ctx))
			return
		}

		// Extract user ID from token
		userID := extractUserIDFromToken(token)
		if userID == "" {
			if a.Config.DebugMode {
				a.logWithContext(r, "[DEBUG] AuthContext: Could not extract UserID from token.")
			}
			a.clearAuthCookies(w, r)
			next(w, r.WithContext(ctx))
			return
		}

		// Try to get user session from cache
		cachedSession, found := getUserSessionFromCache(userID)
		if found && cachedSession.Tokens != nil &&
			cachedSession.Tokens.RefreshToken != nil &&
			cachedSession.Tokens.RefreshToken.Token != "" {

			if a.Config.DebugMode {
				a.logWithContext(r, "[DEBUG] AuthContext: Found session in cache for user %s", maskID(userID))
			}

			// Get current access token if available
			currentAccessToken := ""
			if cachedSession.Tokens.AccessToken != nil {
				currentAccessToken = cachedSession.Tokens.AccessToken.Token
			}

			// Attempt to refresh tokens
			if a.Config.DebugMode {
				a.logWithContext(r, "[DEBUG] AuthContext: Attempting token refresh for cached user %s", maskID(userID))
			}

			refreshToken := cachedSession.Tokens.RefreshToken.Token
			newSession, err := a.refreshAuthTokens(r, w, refreshToken, currentAccessToken)

			if err == nil && newSession != nil && newSession.User.ID != "" {
				// Refresh successful and user object is valid
				finalSessionData = createSession(&newSession.User, newSession.AccessToken, newSession.RefreshToken, newSession.ExpiresIn, a, r)

				if finalSessionData != nil {
					cacheUserSession(finalSessionData)
					if a.Config.DebugMode {
						a.logWithContext(r, "[DEBUG] AuthContext: Successfully refreshed and cached session for user %s (Role: %s)",
							maskID(userID), finalSessionData.User.Role)
					}

					// Add session to context and proceed
					ctx = context.WithValue(ctx, userContextKey, finalSessionData)
					next(w, r.WithContext(ctx))
					return
				}
			} else {
				// Refresh failed
				if a.Config.DebugMode {
					logMsg := "[DEBUG] AuthContext: Refresh failed for cached session %s."
					if err != nil {
						logMsg += " Error: " + err.Error()
					}
					a.logWithContext(r, logMsg, maskID(userID))
				}
				removeSessionFromCache(userID)
			}
		} else if found {
			// Cache hit, but no refresh token
			if a.Config.DebugMode {
				a.logWithContext(r, "[DEBUG] AuthContext: Session found in cache for %s but no refresh token. Forcing validation.", maskID(userID))
			}
			removeSessionFromCache(userID) // Remove incomplete cache entry
		}

		// If we reached here, we need to validate the token
		validatedUser, valid := validateAuthToken(a, ctx, token)
		if !valid || validatedUser == nil {
			if a.Config.DebugMode {
				a.logWithContext(r, "[DEBUG] AuthContext: Token validation failed or returned nil user.")
			}
			a.clearAuthCookies(w, r)
			removeSessionFromCache(userID)
			next(w, r.WithContext(ctx))
			return
		}

		// Validation successful
		finalSessionData = createSession(validatedUser, token, "", 0, a, r)
		if finalSessionData == nil {
			a.logWithContext(r, "[ERROR] AuthContext: Failed to create session data after validation for user %s.", maskID(userID))
			a.clearAuthCookies(w, r)
			a.handleAPIError(w, r, ErrServerError)
			return
		}
		// Add session to context and proceed
		ctx = context.WithValue(ctx, userContextKey, finalSessionData)
		next(w, r.WithContext(ctx))
	}
}

// Helper function to create a UserSession from a Supabase User
func createSession(user *supabase.User, accessToken, refreshToken string, expiresIn int, a *AuthService, r *http.Request) *UserSession {
	if user == nil || user.ID == "" {
		return nil
	}
	// Determine role and tier
	authRole := getStringFromMetadata(user.UserMetadata, "role", "user")
	authTier := getStringFromMetadata(user.UserMetadata, "tier", "free")

	// Check for overrides in BAN ACL
	banUser, found := a.getUserByID(user.ID)
	if found {
		authRole = banUser.UserData.Role
		authTier = banUser.UserData.Tier
		if a.Config.DebugMode {
			a.logWithContext(r, "[DEBUG] AuthContext: User %s found in BAN ACL, using Role: %s, Tier: %s",
				maskID(user.ID), authRole, authTier)
		}
	}

	// Fetch permissions
	permissions, permErr := a.getUserPermissions(user.ID)
	if permErr != nil {
		a.logWithContext(r, "[WARN] AuthContext: Failed to get permissions for %s (Role: %s): %v",
			maskID(user.ID), authRole, permErr)
		permissions = make(map[string]interface{})
	}

	csrfToken, err := a.generateCSRFToken(user.ID)
	if err != nil {
		a.logWithContext(r, "[ERROR] AuthContext: Failed to generate CSRF token for user %s: %v",
			maskID(user.ID), err)
	}

	// Create session data
	session := &UserSession{
		UserId: user.ID,
		Tokens: &AuthTokens{
			AccessToken: &AuthToken{
				Token:     accessToken,
				ExpiresAt: calculateExpiresAt(time.Now(), time.Duration(expiresIn)*time.Second),
			},
			RefreshToken: &RefreshToken{
				Token:     refreshToken,
				ExpiresAt: calculateExpiresAt(time.Now(), time.Duration(expiresIn)*time.Second),
			},
		},
		User: &UserData{
			UserId: user.ID,
			Email:  user.Email,
			Role:   authRole,
			Tier:   authTier,
		},
		Permissions: permissions,
		Metadata:    make(map[string]interface{}),
		CreatedAt:   time.Now(),
	}

	// Copy metadata if available
	if user.UserMetadata != nil {
		session.Metadata = user.UserMetadata
	}

	// Set tokens if provided
	if accessToken != "" {
		expires := time.Now().Add(time.Duration(expiresIn) * time.Second).Unix()
		session.Tokens = &AuthTokens{
			AccessToken: &AuthToken{Token: accessToken, ExpiresAt: expires},
		}

		if refreshToken != "" {
			session.Tokens.RefreshToken = &RefreshToken{
				Token:     refreshToken,
				ExpiresAt: calculateExpiresAt(time.Now(), time.Duration(expiresIn)*time.Second),
			}
		}

		if csrfToken != "" {
			session.Tokens.CSRFToken = csrfToken
		}
	}
	return session
}

// AuthRequired middleware enforces authentication for protected routes
func (a *AuthService) AuthRequired(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Fast path: check for exempt paths
		if a.isExemptPath(path) {
			if a.Config.DebugMode {
				a.logWithContext(r, "[DEBUG] AuthRequired: Path exempt from enforcement: %s", path)
			}
			next(w, r)
			return
		}

		if a.Config.DebugMode {
			a.logWithContext(r, "[DEBUG] AuthRequired: Enforcing auth for path: %s", path)
		}

		// Get user session from context
		userSession := getUserSessionFromContext(r)
		if userSession == nil {
			if a.Config.DebugMode {
				a.logWithContext(r, "[DEBUG] AuthRequired: No valid session for path %s", path)
			}
			a.handleAPIError(w, r, ErrMissingToken)
			return
		}

		// Check user permissions for this route
		requiredPermission := a.findRequiredPermission(path)
		if requiredPermission == "" {
			// No specific permission needed for this path, just auth is enough
			if a.Config.DebugMode {
				a.logWithContext(r, "[DEBUG] AuthRequired: No specific permission needed for %s", path)
			}
			next(w, r.WithContext(r.Context()))
			return
		}

		// Check if user has required permission
		if !a.hasPermission(userSession, requiredPermission) {
			// User doesn't have required permission
			if a.Config.DebugMode {
				userID := getUserID(userSession)
				a.logWithContext(r, "[DEBUG] AuthRequired: Permission DENIED for user %s on path %s (requires %s)",
					userID, path, requiredPermission)
			}
			a.handleAPIError(w, r, ErrPermissionDenied)
			return
		}

		// User has permission, proceed
		if a.Config.DebugMode {
			userID := getUserID(userSession)
			a.logWithContext(r, "[DEBUG] AuthRequired: Permission GRANTED for user %s on path %s", userID, path)
		}
		next(w, r.WithContext(r.Context()))
	}
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

	if a.Config.DebugMode {
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

// SpoofMiddleware checks for an impersonation cookie and modifies the user context if valid
func (a *AuthService) SpoofMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Get user session from context
		originalUserSession := getUserSessionFromContext(r)
		if originalUserSession == nil {
			// No session to spoof, proceed normally
			next(w, r)
			return
		}

		// Check for spoof cookie
		spoofCookie, err := r.Cookie("spoof")
		if err != nil || spoofCookie.Value == "" {
			// No spoofing active, ensure flag is cleared if needed
			if originalUserSession.Metadata["is_impersonating"] == true {
				clearImpersonation(w, r, ctx, originalUserSession, next, a)
				return
			}
			// Normal admin session
			next(w, r)
			return
		}

		// Admin is attempting to spoof another user
		targetEmail := spoofCookie.Value
		if a.Config.DebugMode {
			adminEmail := getEmailSafe(originalUserSession)
			a.logWithContext(r, "[DEBUG] SpoofMiddleware: Admin %s attempting to spoof %s", adminEmail, targetEmail)
		}

		// Find target user in BanACL
		targetBanUser, targetFound := a.getUserByEmail(targetEmail)
		if !targetFound {
			handleTargetNotFound(w, r, ctx, originalUserSession, targetEmail, next, a)
			return
		}

		// Create spoofed session
		ctx = createSpoofedSession(ctx, originalUserSession, targetBanUser, targetEmail, a)
		next(w, r.WithContext(ctx))
	}
}

// isAdmin checks if user has admin privileges
func isAdmin(session *UserSession) bool {
	if session == nil {
		return false
	}
	return session.User.Role == "admin" || session.User.Role == "root"
}

// getEmailSafe safely gets user email for logging
func getEmailSafe(session *UserSession) string {
	if session == nil || session.User == nil {
		return "unknown"
	}
	return session.User.Email
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
			if !isNextAsset && a.Config.DebugMode {
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

	if a.Config.DebugMode && !isNextAsset {
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
			var claims map[string]interface{}
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
		if a.Config.DebugMode {
			a.Logger.Printf("[DEBUG] validateAuthToken: Empty token provided")
		}
		return nil, false
	}

	// Check token format
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		if a.Config.DebugMode {
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
			if a.Config.DebugMode {
				a.Logger.Printf("[DEBUG] validateAuthToken: Token expired")
			}
			return nil, false
		}
		if a.Config.DebugMode {
			a.Logger.Printf("[DEBUG] validateAuthToken: Token validation failed: %v", err)
		}
		return nil, false
	}

	if user == nil {
		if a.Config.DebugMode {
			a.Logger.Printf("[DEBUG] validateAuthToken: Token validated but user object is nil")
		}
		return nil, false
	}

	if a.Config.DebugMode {
		a.Logger.Printf("[DEBUG] validateAuthToken: Valid user found via token: %s (ID: %s)",
			maskEmail(user.Email), maskID(user.ID))
	}

	return user, true
}

// ==============================================================================
// session cache
// ==============================================================================

// getUserSessionFromCache retrieves a valid session from cache or returns nil if not found/expired
func getUserSessionFromCache(userID string) (*UserSession, bool) {
	userSessionCacheMutex.RLock()
	session, found := userSessionCache[userID]
	userSessionCacheMutex.RUnlock()

	if !found {
		return nil, false
	}

	// Check if session is expired
	if time.Since(session.CreatedAt) > sessionCacheTTL {
		// Remove expired session
		userSessionCacheMutex.Lock()
		delete(userSessionCache, userID)
		userSessionCacheMutex.Unlock()
		return nil, false
	}

	// Return a deep copy to prevent race conditions
	return deepCopySession(session), true
}

// deepCopySession creates a deep copy of a UserSessio
func deepCopySession(src *UserSession) *UserSession {
	if src == nil {
		return nil
	}

	// Copy tokens
	var tokensCopy *AuthTokens
	if src.Tokens != nil {
		tokensCopy = &AuthTokens{
			CSRFToken: src.Tokens.CSRFToken,
		}
		if src.Tokens.AccessToken != nil {
			tokensCopy.AccessToken = &AuthToken{
				Token:     src.Tokens.AccessToken.Token,
				ExpiresAt: src.Tokens.AccessToken.ExpiresAt,
			}
		}
		if src.Tokens.RefreshToken != nil {
			tokensCopy.RefreshToken = &RefreshToken{
				Token:     src.Tokens.RefreshToken.Token,
				ExpiresAt: src.Tokens.RefreshToken.ExpiresAt,
			}
		}
	}

	// Copy user data
	var userCopy *UserData
	if src.User != nil {
		userCopy = &UserData{
			UserId: src.User.UserId,
			Email:  src.User.Email,
			Role:   src.User.Role,
			Tier:   src.User.Tier,
		}
	}

	// Copy permissions
	permsCopy := make(map[string]interface{}, len(src.Permissions))
	for k, v := range src.Permissions {
		permsCopy[k] = v
	}

	// Copy metadata
	metaCopy := make(map[string]interface{}, len(src.Metadata))
	for k, v := range src.Metadata {
		metaCopy[k] = v
	}

	return &UserSession{
		UserId:      src.UserId,
		Tokens:      tokensCopy,
		User:        userCopy,
		Permissions: permsCopy,
		Metadata:    metaCopy,
		CreatedAt:   src.CreatedAt,
	}
}

// cacheUserSession adds or updates a session in the cache
func cacheUserSession(session *UserSession) {
	if session == nil || session.UserId == "" {
		return
	}

	userSessionCacheMutex.Lock()
	defer userSessionCacheMutex.Unlock()

	// Store a deep copy to prevent race conditions
	userSessionCache[session.UserId] = deepCopySession(session)

	// Start the background cache cleaner if not already running
	cacheCleanerStarted.Do(startCacheCleaner)
}

// startCacheCleaner starts a background goroutine to periodically clean the session cache
func startCacheCleaner() {
	go func() {
		ticker := time.NewTicker(cacheCleanInterval)
		defer ticker.Stop()

		for range ticker.C {
			cleanSessionCache()
		}
	}()
}

// cleanSessionCache removes expired sessions and enforces cache size limits
func cleanSessionCache() {
	userSessionCacheMutex.Lock()
	defer userSessionCacheMutex.Unlock()

	// Track expired sessions and creation times for age-based cleanup
	var expiredKeys []string
	sessionAges := make(map[string]time.Time, len(userSessionCache))

	// Find expired sessions
	now := time.Now()
	for key, session := range userSessionCache {
		sessionAges[key] = session.CreatedAt
		if now.Sub(session.CreatedAt) > sessionCacheTTL {
			expiredKeys = append(expiredKeys, key)
		}
	}

	// Remove expired sessions
	for _, key := range expiredKeys {
		delete(userSessionCache, key)
		delete(sessionAges, key)
	}

	// If still over size limit, remove oldest sessions
	if len(userSessionCache) > sessionCacheMaxSize {
		// Convert to slice for sorting
		type sessionAge struct {
			key string
			age time.Time
		}
		ages := make([]sessionAge, 0, len(sessionAges))
		for k, v := range sessionAges {
			ages = append(ages, sessionAge{k, v})
		}

		// Sort by age (oldest first)
		sort.Slice(ages, func(i, j int) bool {
			return ages[i].age.Before(ages[j].age)
		})

		// Remove oldest entries until we're under the limit
		for i := 0; i < len(ages) && len(userSessionCache) > sessionCacheMaxSize; i++ {
			delete(userSessionCache, ages[i].key)
		}
	}
}

// Helper to remove a session from cache
func removeSessionFromCache(userID string) {
	userSessionCacheMutex.Lock()
	defer userSessionCacheMutex.Unlock()

	delete(userSessionCache, userID)
}

// CustomRoleClient creates a new supabase client with a custom role
func CustomRoleClient(url, key, roleName string) (*supabase.Client, error) {
	client := supabase.CreateClient(url, key)
	client.DB.AddHeader("x-postgres-role", roleName)
	return client, nil
}
