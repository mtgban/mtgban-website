package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/uuid"
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
)

// ============================================================================================
// Authentication Types
// ============================================================================================

// AuthService handles all authentication-related functionality
type AuthService struct {
	Logger     *log.Logger
	Supabase   *supabase.Client
	Config     AuthConfig
	CSRFSecret string
	BanACL     *BanACL
	Navs       map[string]*NavElem
	IPLimiters sync.Map
}

// UserSession represents cached user data and permissions for authentication
type UserSession struct {
	User            *supabase.User
	Role            string
	Tier            string
	Permissions     map[string]interface{}
	IsImpersonating bool
	CreatedAt       time.Time
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

// AuthConfig holds the configuration settings for the authentication service
type AuthConfig struct {
	SupabaseURL     string   `json:"supabase_url"`
	SupabaseAnonKey string   `json:"supabase_anon_key"`
	SupabaseSecret  string   `json:"supabase_jwt_secret"`
	DebugMode       bool     `json:"debug_mode"`
	LogPrefix       string   `json:"log_prefix"`
	ExemptRoutes    []string `json:"exempt_routes"`
	ExemptPrefixes  []string `json:"exempt_prefixes"`
	ExemptSuffixes  []string `json:"exempt_suffixes"`
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
	mux   sync.RWMutex
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

// Context keys for storing data in request context
type ctxKey string

const (
	userContextKey  ctxKey = "user"
	aclContextKey   ctxKey = "acl"
	spoofContextKey ctxKey = "spoof"
)

// Cookie name for impersonation
const spoofCookieName = "spoof_target"

// userSessionContextKey is the key for storing the UserSession in the request context
type userSessionContextKeyType struct{}

var userSessionContextKey = userSessionContextKeyType{}

// Session cache to reduce backend lookups
var (
	userSessionCache      = make(map[string]*UserSession)
	userSessionCacheMutex sync.RWMutex
)

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
	} else {
		logger = log.New(logFile, config.LogPrefix, log.LstdFlags|log.Lshortfile)
		logger.Printf("Logging to file: %s", logFilePath)
	}

	// Initialize Supabase client
	supabaseClient := supabase.CreateClient(config.SupabaseURL, config.SupabaseAnonKey)
	if supabaseClient == nil {
		return nil, errors.New("failed to create Supabase client")
	}
	logger.Printf("Supabase client initialized for URL: %s", config.SupabaseURL)

	csrfSecret, _ := generateCSRFSecret(32, "csrf_secret.txt")

	// Create the service instance
	service := &AuthService{
		Logger:     logger,
		Supabase:   supabaseClient,
		Config:     config,
		CSRFSecret: csrfSecret,
		BanACL:     &BanACL{Users: make(map[string]*BanUser)},
		Navs:       extraNavs,
		IPLimiters: sync.Map{},
	}

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
		Permissions map[string]interface{} `json:"permissions"`
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err := a.Supabase.DB.From("ban_acl").Select("user_id,email,tier,permissions").ExecuteWithContext(ctx, &banUsersData)
	if err != nil {
		a.Logger.Printf("Error fetching BAN ACL data: %v", err)
		return fmt.Errorf("failed to fetch ban_acl data from Supabase: %w", err)
	}

	a.BanACL.mux.Lock()
	defer a.BanACL.mux.Unlock()

	a.BanACL.Users = make(map[string]*BanUser)

	for _, userData := range banUsersData {
		permsCopy := make(map[string]interface{})
		for k, v := range userData.Permissions {
			permsCopy[k] = v
		}

		a.BanACL.Users[userData.Email] = &BanUser{
			UserData: &UserData{
				UserId: userData.UserId,
				Email:  userData.Email,
				Tier:   userData.Tier,
			},
			Permissions: permsCopy,
		}
	}

	a.Logger.Printf("Successfully loaded ACL for %d users.", len(a.BanACL.Users))
	return nil
}

// getUserByEmail retrieves the BanUser struct for a given email.
func (a *AuthService) getUserByEmail(email string) (*BanUser, bool) {
	if a.BanACL == nil {
		a.Logger.Println("Warning: getUserByEmail called before BanACL is initialized.")
		return nil, false
	}

	a.BanACL.mux.RLock()
	defer a.BanACL.mux.RUnlock()

	user, exists := a.BanACL.Users[email]
	if !exists {
		return nil, false
	}

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

	// Name not found as a tier or role
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
	method := r.Method
	path := r.URL.Path

	// Get user ID
	userID := a.getUserIDFromRequest(r)

	// Format log message
	contextMsg := fmt.Sprintf("[%s][%s %s][User:%s] %s",
		clientIP, method, path, userID, format)

	a.Logger.Printf(contextMsg, v...)
}

// getUserIDFromRequest extracts user ID from request context or cookie
func (a *AuthService) getUserIDFromRequest(r *http.Request) string {
	// First try to get UserID from context
	if user, ok := r.Context().Value(userSessionContextKey).(*supabase.User); ok && user != nil {
		return user.ID
	}

	// Then try to get from UserSession if available
	if sessionData := r.Context().Value(userSessionContextKey); sessionData != nil {
		if userSession, ok := sessionData.(*UserSession); ok && userSession != nil && userSession.User != nil {
			return userSession.User.ID
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

// generateCSRFToken generates a CSRF token for a user session
func (a *AuthService) generateCSRFToken(sessionID string) string {
	h := hmac.New(sha256.New, a.getCSRFSecretKey())
	h.Write([]byte(sessionID))
	h.Write([]byte(time.Now().Format("2006-01-02")))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// validateCSRFToken validates a submitted CSRF token against the expected value for the session
func (a *AuthService) validateCSRFToken(submittedToken, sessionID string) bool {
	if submittedToken == "" || sessionID == "" {
		return false
	}

	// Extract the secret
	secretParts := strings.Split(a.CSRFSecret, "|")
	if len(secretParts) != 2 {
		a.Logger.Printf("[ERROR] Invalid CSRF secret format")
		return false
	}

	// Generate expected token
	h := hmac.New(sha256.New, a.getCSRFSecretKey())
	h.Write([]byte(sessionID))
	h.Write([]byte(time.Now().Format("2006-01-02")))
	expectedToken := base64.StdEncoding.EncodeToString(h.Sum(nil))

	return hmac.Equal([]byte(submittedToken), []byte(expectedToken))
}

// setCSRFCookie sets the CSRF token cookie for the frontend to use
func (a *AuthService) setCSRFCookie(w http.ResponseWriter, r *http.Request, csrfToken string) {
	isSecure := r.TLS != nil || !a.Config.DebugMode
	a.setCookie(w, "csrf_token", csrfToken, 24*60*60, false, isSecure, http.SameSiteStrictMode)
}

// validatePassword checks password strength
func (a *AuthService) validatePassword(password string) (bool, string) {
	if len(password) < 8 {
		return false, "Password must be at least 8 characters long"
	}
	hasLetter := false
	hasDigit := false
	for _, c := range password {
		if unicode.IsLetter(c) {
			hasLetter = true
		} else if unicode.IsDigit(c) {
			hasDigit = true
		}
		if hasLetter && hasDigit {
			break
		}
	}
	if !hasLetter || !hasDigit {
		return false, "Password must contain both letters and numbers"
	}

	return true, ""
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

// performSupabaseAuth executes Supabase authentication
func (a *AuthService) performSupabaseAuth(ctx context.Context, email, password string) (*supabase.AuthenticatedDetails, *supabase.User, *AuthError) {
	var authResponse *supabase.AuthenticatedDetails
	var userInfo *supabase.User

	// Authenticate with Supabase
	err := withTimeoutContext(ctx, 10*time.Second, func(timeoutCtx context.Context) error {
		resp, err := a.Supabase.Auth.SignIn(timeoutCtx, supabase.UserCredentials{
			Email:    email,
			Password: password,
		})
		if err != nil {
			return err
		}
		authResponse = resp
		return nil
	})

	if err != nil {
		a.Logger.Printf("Supabase SignIn failed for %s: %v", maskEmail(email), err)
		return nil, nil, &ErrInvalidCredentials
	}

	// Get user information
	err = withTimeoutContext(ctx, 10*time.Second, func(timeoutCtx context.Context) error {
		user, err := a.Supabase.Auth.User(timeoutCtx, authResponse.AccessToken)
		if err != nil {
			return err
		}
		userInfo = user
		return nil
	})

	if err != nil {
		a.Logger.Printf("Failed to get user info after sign-in for %s: %v", maskEmail(email), err)
		return nil, nil, &AuthError{
			Code:       "USER_FETCH_FAILED",
			Message:    "Could not retrieve user data after login",
			StatusCode: http.StatusInternalServerError,
			Internal:   err,
		}
	}

	return authResponse, userInfo, nil
}

// authenticateUser performs authentication with Supabase
func (a *AuthService) authenticateUser(ctx context.Context, req LoginRequest) (*supabase.AuthenticatedDetails, *supabase.User, *AuthError) {
	return a.performSupabaseAuth(ctx, req.Email, req.Password)
}

// createUserResponse builds a standardized user response
func (a *AuthService) createUserResponse(userInfo *supabase.User, expiresAt int64, csrfToken string) map[string]interface{} {
	tier := getTierFromUser(userInfo)

	return map[string]interface{}{
		"user": map[string]interface{}{
			"id":    userInfo.ID,
			"tier":  tier,
			"email": userInfo.Email,
			"sub":   userInfo.UserMetadata["sub"],
		},
		"session": map[string]interface{}{
			"expires_at": expiresAt,
			"csrf_token": csrfToken,
		},
	}
}

// LoginAPI handles POST requests to the API login endpoint
func (a *AuthService) LoginAPI(w http.ResponseWriter, r *http.Request) {
	a.logWithContext(r, "LoginAPI attempt")

	var req LoginRequest
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

	authResponse, userInfo, authErr := a.authenticateUser(r.Context(), req)
	if authErr != nil {
		a.handleAPIError(w, r, *authErr)
		return
	}

	csrfToken := a.setupUserSession(w, r, authResponse, userInfo, req.Remember)
	expiresAt := time.Now().Add(time.Duration(authResponse.ExpiresIn) * time.Second).Unix()
	responseData := a.createUserResponse(userInfo, expiresAt, csrfToken)

	a.sendAPISuccess(w, "Login successful", responseData)
	a.logWithContext(r, "LoginAPI successful for %s (Tier: %s)", maskEmail(req.Email), getTierFromUser(userInfo))
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

		if valid, msg := a.validatePassword(req.Password); !valid {
			return &AuthError{
				Code:       "WEAK_PASSWORD",
				Message:    msg,
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

	// Prepare base response
	responseData := map[string]interface{}{
		"user": map[string]interface{}{
			"id":    user.ID,
			"email": user.Email,
			"tier":  user.UserMetadata["tier"],
			"sub":   user.UserMetadata["sub"],
		},
	}

	// attempt Auto-Login after successful signup
	ctx = r.Context()
	authResponse, userInfo, _ := a.performSupabaseAuth(ctx, req.Email, req.Password)

	if authResponse != nil && userInfo != nil {
		// Auto-login succeeded
		csrfToken := a.setupUserSession(w, r, authResponse, userInfo, false)
		expiresAt := time.Now().Add(time.Duration(authResponse.ExpiresIn) * time.Second).Unix()
		responseData = a.createUserResponse(userInfo, expiresAt, csrfToken)

		a.logWithContext(r, "SignupAPI successful for %s, auto-login succeeded.", maskEmail(req.Email))
		a.sendAPISuccess(w, "Account created and logged in successfully.", responseData)
	} else {
		a.logWithContext(r, "Auto-login after signup failed for %s", maskEmail(req.Email))
		a.sendAPISuccess(w, "Account created successfully. Please log in.", responseData)
	}
}

// LogoutAPI handles POST requests to the API logout endpoint
func (a *AuthService) LogoutAPI(w http.ResponseWriter, r *http.Request) {
	a.logWithContext(r, "LogoutAPI attempt")

	// Add proper null checks
	var userEmail string
	userSession := getUserSessionFromContext(r)
	if userSession != nil && userSession.User != nil {
		userEmail = userSession.User.Email
	}

	// Get auth token from cookie
	if authCookie, err := r.Cookie("auth_token"); err == nil && authCookie.Value != "" {
		withTimeoutContext(r.Context(), 5*time.Second, func(ctx context.Context) error {
			if err := a.Supabase.Auth.SignOut(ctx, authCookie.Value); err != nil {
				a.logWithContext(r, "Supabase SignOut error: %v", err)
			}

			if userEmail != "" {
				a.logWithContext(r, "Supabase SignOut successful for %s", maskEmail(userEmail))
			} else {
				a.logWithContext(r, "Supabase SignOut successful")
			}

			return nil
		})
	} else {
		a.logWithContext(r, "Logout attempted without auth_token cookie")
	}

	// Clear Auth Cookies
	a.clearAuthCookies(w, r)

	// Send Response
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

	newSession, authErr := a.refreshAuthTokens(r, w, refreshToken, "")
	if authErr != nil {
		a.handleAPIError(w, r, *authErr)
		return
	}

	// Generate and Set CSRF Token
	csrfToken := a.generateCSRFToken(newSession.User.ID)
	a.setCSRFCookie(w, r, csrfToken)

	// Calculate expiry time
	expiresAt := time.Now().Add(time.Duration(newSession.ExpiresIn) * time.Second).Unix()
	responseData := a.createUserResponse(&newSession.User, expiresAt, csrfToken)

	a.sendAPISuccess(w, "Token refreshed successfully", responseData)
}

// GetUserAPI handles GET requests to fetch the current authenticated user's info
func (a *AuthService) GetUserAPI(w http.ResponseWriter, r *http.Request) {
	a.logWithContext(r, "GetUserAPI attempt")

	// Get Tokens from Cookies
	authCookie, authErr := r.Cookie("auth_token")
	refreshCookie, refreshErr := r.Cookie("refresh_token")

	var userInfo *supabase.User
	var accessToken string

	// Validate Auth Token
	if authErr == nil && authCookie.Value != "" {
		accessToken = authCookie.Value
		validUser, valid := validateAuthToken(a, r.Context(), accessToken)
		if valid {
			userInfo = validUser
		} else {
			a.logWithContext(r, "Auth token invalid, attempting refresh (%v)", authErr)
			accessToken = "" // Invalidate the current token
		}
	}

	// Attempt Refresh if needed and possible
	if userInfo == nil && refreshErr == nil && refreshCookie.Value != "" {
		a.logWithContext(r, "No valid auth token, attempting refresh with refresh_token")
		refreshToken := refreshCookie.Value

		newSession, authErr := a.refreshAuthTokens(r, w, refreshToken, accessToken) // Pass both tokens
		if authErr != nil {
			a.handleAPIError(w, r, *authErr)
			return
		}
		userInfo = &newSession.User // Update userInfo from refreshed session
	}

	// Check if user is authenticated after all attempts
	if userInfo == nil {
		a.logWithContext(r, "GetUserAPI failed: No valid session found.")
		a.handleAPIError(w, r, ErrMissingToken)
		return
	}

	// Generate and Set CSRF Token
	csrfToken := a.generateCSRFToken(userInfo.ID)
	a.setCSRFCookie(w, r, csrfToken)

	// Estimate session expiry
	sessionExpiresAt := time.Now().Add(24 * time.Hour).Unix()
	responseData := a.createUserResponse(userInfo, sessionExpiresAt, csrfToken)

	a.sendAPISuccess(w, "User data retrieved successfully", responseData)
}

// refreshAuthTokens performs token refresh and handles cookies
func (a *AuthService) refreshAuthTokens(r *http.Request, w http.ResponseWriter, refreshToken, accessToken string) (*supabase.AuthenticatedDetails, *AuthError) {
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
		a.clearAuthCookies(w, r)
		return nil, &ErrSessionExpired
	}

	// Set New Cookies
	a.setAuthCookies(w, r, newSession.AccessToken, newSession.RefreshToken, true)
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

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{w, http.StatusOK}
}

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
		if !strings.HasPrefix(r.URL.Path, "/_next/") {
			a.logWithContext(r, "Request started")
		}

		// Capture status code and process the request
		rw := newResponseWriter(w)
		next(rw, r)

		duration := time.Since(start)
		// Use the captured status code or 200
		status := rw.status
		if status == 0 {
			status = http.StatusOK
		}
		a.logWithContext(r, "Request completed: status=%d duration=%v", status, duration)
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

// AuthContext middleware attempts to validate user tokens, utilizes a session cache,
// and adds a unified UserSession object to the request context.
func (a *AuthService) AuthContext(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user *supabase.User
		var token string
		ctx := r.Context()

		// Extract auth token from request
		token = extractAuthToken(r)
		if token == "" {
			if a.Config.DebugMode {
				a.logWithContext(r, "[DEBUG] AuthContext: No valid auth token found in cookie or header.")
			}
			next(w, r.WithContext(ctx)) // Proceed without user context
			return
		}

		session, found := getUserSessionFromCache(a, extractUserIDFromToken(token))
		if found {
			ctx = context.WithValue(ctx, userSessionContextKey, session)
			next(w, r.WithContext(ctx))
			return
		}

		// Validate Token with Supabase
		user, valid := validateAuthToken(a, ctx, token)
		if !valid || user == nil {
			a.Logger.Printf("[DEBUG] validateAuthToken failed for token: %s...", token[:10])
			next(w, r.WithContext(ctx))
			return
		}

		// Build and Cache New Session
		session = buildUserSession(a, user)
		ctx = context.WithValue(ctx, userSessionContextKey, session)
		next(w, r.WithContext(ctx))
	}
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
		hasPermission := a.userHasPermission(userSession, requiredPermission)
		if !hasPermission {
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

// userHasPermission checks if a user session has a specific permission
func (a *AuthService) userHasPermission(session *UserSession, permissionKey string) bool {
	if session == nil || session.Permissions == nil {
		return false
	}

	// Check permission in permissions map
	_, hasPermission := session.Permissions[permissionKey]

	// Log permission check details if in debug mode
	if a.Config.DebugMode {
		email := "<unknown>"
		if session.User != nil {
			email = session.User.Email
		}
		a.Logger.Printf("[DEBUG] Permission check: user %s, key %s = %t",
			maskEmail(email), permissionKey, hasPermission)
	}

	return hasPermission
}

// getUserID extracts a user ID for logging
func getUserID(session *UserSession) string {
	if session == nil || session.User == nil {
		return "unknown"
	}
	return maskID(session.User.ID)
}

// CSRFProtection middleware checks for valid CSRF tokens on non-exempt, non-GET/HEAD/OPTIONS requests
func (a *AuthService) CSRFProtection(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Fast path: skip check for exempt methods or paths
		if isExemptMethod(r.Method) || a.isExemptPath(r.URL.Path) {
			next(w, r)
			return
		}

		// Get user session from context
		userSession := getUserSessionFromContext(r)
		if userSession == nil || userSession.User == nil {
			a.logWithContext(r, "CSRFProtection: No valid user session found, cannot validate CSRF")
			a.handleAPIError(w, r, ErrInvalidToken)
			return
		}

		// Get CSRF token from request
		submittedToken := getCSRFToken(r)

		// Validate the token
		if !a.validateCSRFToken(submittedToken, userSession.User.ID) {
			if a.Config.DebugMode {
				a.logWithContext(r, "CSRF Token Validation Failed. Submitted: '%s', Expected for UserID: %s",
					submittedToken, maskID(userSession.User.ID))
			}
			a.handleAPIError(w, r, ErrCSRFValidation)
			return
		}

		// Token is valid, continue
		next(w, r)
	}
}

// isExemptMethod returns true if the HTTP method doesn't need CSRF protection
func isExemptMethod(method string) bool {
	return method == "GET" || method == "HEAD" || method == "OPTIONS"
}

// getUserSessionFromContext extracts the UserSession from a request's context
func getUserSessionFromContext(r *http.Request) *UserSession {
	sessionData := r.Context().Value(userSessionContextKey)
	if sessionData == nil {
		return nil
	}

	userSession, ok := sessionData.(*UserSession)
	if !ok || userSession == nil {
		return nil
	}

	return userSession
}

// getCSRFToken extracts the CSRF token from a request
func getCSRFToken(r *http.Request) string {
	// Try header first
	token := r.Header.Get("X-CSRF-Token")
	if token != "" {
		return token
	}

	// Then try form field
	return r.PostFormValue("csrf_token")
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

		// Only admins/root can spoof
		if !isAdmin(originalUserSession) {
			handleNonAdminImpersonation(w, r, ctx, originalUserSession, next, a)
			return
		}

		// Check for spoof cookie
		spoofCookie, err := r.Cookie(spoofCookieName)
		if err != nil || spoofCookie.Value == "" {
			// No spoofing active, ensure flag is cleared if needed
			if originalUserSession.IsImpersonating {
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
	return session.Role == "admin" || session.Role == "root"
}

// handleNonAdminImpersonation handles the case when a non-admin has IsImpersonating flag
func handleNonAdminImpersonation(w http.ResponseWriter, r *http.Request, ctx context.Context, session *UserSession, next http.HandlerFunc, a *AuthService) {

	if session.IsImpersonating {
		a.logWithContext(r, "[WARNING] SpoofMiddleware: Non-admin user has IsImpersonating=true in session.")

		// Clear the flag by creating a clean copy
		modifiedSession := *session
		modifiedSession.IsImpersonating = false
		ctx = context.WithValue(ctx, userSessionContextKey, &modifiedSession)
		next(w, r.WithContext(ctx))
		return
	}

	// Not impersonating, proceed normally
	next(w, r)
}

// clearImpersonation handles clearing the impersonation flag
func clearImpersonation(w http.ResponseWriter, r *http.Request, ctx context.Context, session *UserSession, next http.HandlerFunc, a *AuthService) {

	// Create a clean copy without impersonation
	modifiedSession := *session
	modifiedSession.IsImpersonating = false
	ctx = context.WithValue(ctx, userSessionContextKey, &modifiedSession)

	if a.Config.DebugMode {
		email := getEmailSafe(session)
		a.logWithContext(r, "[DEBUG] SpoofMiddleware: Clearing IsImpersonating flag for admin %s", email)
	}

	next(w, r.WithContext(ctx))
}

// handleTargetNotFound handles the case when a target user for spoofing is not found
func handleTargetNotFound(w http.ResponseWriter, r *http.Request, ctx context.Context, session *UserSession, targetEmail string, next http.HandlerFunc, a *AuthService) {

	a.logWithContext(r, "SpoofMiddleware: Target user %s not found in BanACL. Clearing spoof cookie.", targetEmail)

	// Clear the invalid cookie
	http.SetCookie(w, &http.Cookie{Name: spoofCookieName, Value: "", Path: "/", MaxAge: -1})

	// Clear impersonation flag if needed
	if session.IsImpersonating {
		clearImpersonation(w, r, ctx, session, next, a)
		return
	}

	next(w, r.WithContext(ctx))
}

// createSpoofedSession creates and adds a spoofed session to the context
func createSpoofedSession(ctx context.Context, originalSession *UserSession, targetUser *BanUser, targetEmail string, a *AuthService) context.Context {

	// Create the spoofed session object
	spoofedSession := &UserSession{
		User:            originalSession.User,
		Role:            targetUser.UserData.Role,
		Tier:            targetUser.UserData.Tier,
		Permissions:     targetUser.Permissions,
		IsImpersonating: true,
		CreatedAt:       time.Now(),
	}

	if a.Config.DebugMode {
		email := getEmailSafe(originalSession)
		a.Logger.Printf("[DEBUG] SpoofMiddleware: Created spoofed session for %s as %s (Role: %s, Tier: %s)",
			email, targetEmail, spoofedSession.Role, spoofedSession.Tier)
	}

	// Add the spoofed session to context
	return context.WithValue(ctx, userSessionContextKey, spoofedSession)
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

// handleAuthAsset serves static files for the Next.js frontend under /auth/
func (a *AuthService) handleAuthAsset(w http.ResponseWriter, r *http.Request) {
	// Get path relative to /auth/
	path := strings.TrimPrefix(r.URL.Path, "/auth")

	// Default to index.html if path is empty
	if path == "" || path == "/" {
		a.logWithContext(r, "handleAuthAsset: Empty path, serving default index.html")
		path = "/index.html"
	}

	fsPath := filepath.Join("nextAuth", "out", path)
	fsPath = filepath.ToSlash(fsPath)

	// Log the requested path, *unless* it's a Next.js internal asset
	if !strings.Contains("/_next/", path) {
		a.logWithContext(r, "Serving auth asset: %s", path)
	}

	if strings.HasPrefix(path, "/_next/") {
		// Set content type based on file extension
		ext := filepath.Ext(path)
		if contentType, ok := contentTypeMap[ext]; ok {
			w.Header().Set("Content-Type", contentType)
		} else if ext == ".js" {
			w.Header().Set("Content-Type", "application/javascript")
		} else if ext == ".css" {
			w.Header().Set("Content-Type", "text/css")
		} else {
			w.Header().Set("Content-Type", "application/octet-stream")
		}
		// Read and serve the file
		data, err := authAssets.ReadFile(fsPath)
		if err != nil {
			a.logWithContext(r, "handleAuthAsset: Next.js asset not found: %s (Error: %v)", fsPath, err)
			http.NotFound(w, r)
			return
		}
		w.Write(data)
		return
	}
	// Set content type based on file extension
	ext := filepath.Ext(path)
	if contentType, ok := contentTypeMap[ext]; ok {
		w.Header().Set("Content-Type", contentType)
	} else {
		// Default or guess content type if unknown
		w.Header().Set("Content-Type", "application/octet-stream")
	}

	// Read the file from embedded FS
	data, err := authAssets.ReadFile(fsPath)
	if err != nil {
		// Handle cases where a route might be requested without .html
		if ext == "" {
			fsPathHTML := fsPath + ".html"
			dataHTML, errHTML := authAssets.ReadFile(fsPathHTML)
			if errHTML == nil {
				a.logWithContext(r, "handleAuthAsset: Serving auth asset (added .html): %s", fsPathHTML)
				w.Header().Set("Content-Type", "text/html")
				w.Write(dataHTML)
				return
			}
		}
		// File not found
		a.logWithContext(r, "handleAuthAsset: Auth asset not found: %s (Error: %v)", fsPath, err)
		http.NotFound(w, r)
		return
	}

	// Write the file content to the response
	w.Write(data)
}

// signHMACSHA256Base64 generates an HMAC-SHA256 signature and encodes it in Base64.
func (a *AuthService) signHMACSHA256Base64(key, data []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// generateCSRFSecret generates a new CSRF secret and writes it to a file
func generateCSRFSecret(length int, filePath string) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("length must be greater than 0")
	}
	// Generate random bytes for the secret part
	secretBytes := make([]byte, length)
	_, err := rand.Read(secretBytes)
	if err != nil {
		return "", err
	}
	encodedSecret := base64.StdEncoding.EncodeToString(secretBytes)

	timestamp := time.Now().Unix()
	combinedSecret := fmt.Sprintf("%s:%d", encodedSecret, timestamp)

	err = os.WriteFile(filePath, []byte(combinedSecret), 0600)
	if err != nil {
		return "", err
	}

	return combinedSecret, nil
}

// Extract the actual secret for use in HMAC
func (a *AuthService) getCSRFSecretKey() []byte {
	parts := strings.SplitN(a.CSRFSecret, ":", 2)
	if len(parts) == 2 {
		return []byte(parts[1]) // Just use the random part as the HMAC key
	}
	return []byte(a.CSRFSecret) // Fallback to using the whole string
}

// CSRFRotate rotates the CSRF secret periodically
func (a *AuthService) CSRFRotate(interval time.Duration, filePath string) {
	go func() {
		for {
			// First check if current secret needs rotation
			parts := strings.SplitN(a.CSRFSecret, ":", 2)
			if len(parts) == 2 {
				ts, err := strconv.ParseInt(parts[0], 10, 64)
				if err == nil {
					secretTime := time.Unix(ts, 0)
					elapsed := time.Since(secretTime)

					if elapsed < interval {
						// Secret doesn't need rotation yet
						waitTime := interval - elapsed
						a.Logger.Printf("[INFO] CSRF secret age: %v, rotating in %v", elapsed, waitTime)
						time.Sleep(waitTime)
						continue
					}
				}
			} else {
				// No timestamp found, generate new secret
				secret, err := generateCSRFSecret(32, filePath)
				if err != nil {
					a.Logger.Printf("[ERROR] Failed to generate CSRF secret: %v", err)
					time.Sleep(24 * time.Hour)
					continue
				}

				a.CSRFSecret = secret
				a.Logger.Printf("[INFO] CSRF secret rotated")
			}
			time.Sleep(interval)
		}
	}()
}

// LoadCSRFSecret loads the CSRF secret
func (a *AuthService) LoadCSRFSecret(filePath string) error {
	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		secret, err := generateCSRFSecret(32, filePath)
		if err != nil {
			return fmt.Errorf("failed to generate CSRF secret: %w", err)
		}
		a.CSRFSecret = secret
		a.Logger.Printf("[DEBUG] CSRF secret file created and secret generated.")
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to check CSRF secret file: %w", err)
	}

	secretBytes, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read CSRF secret file: %w", err)
	}

	fullSecret := strings.TrimSpace(string(secretBytes))

	// Parse and validate the timestamp
	parts := strings.Split(fullSecret, ":")
	if len(parts) != 2 {
		// Legacy format or invalid - generate new one
		secret, err := generateCSRFSecret(32, filePath)
		if err != nil {
			return fmt.Errorf("failed to generate CSRF secret: %w", err)
		}
		a.CSRFSecret = secret
		return nil
	}

	timestamp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		// Invalid timestamp - generate new one
		secret, err := generateCSRFSecret(32, filePath)
		if err != nil {
			return fmt.Errorf("failed to generate CSRF secret: %w", err)
		}
		a.CSRFSecret = secret
		return nil
	}

	createTime := time.Unix(timestamp, 0)
	age := time.Since(createTime)

	a.CSRFSecret = fullSecret
	a.Logger.Printf("[DEBUG] CSRF Secret loaded successfully from file (age: %v)", age)
	return nil
}

// setupUserSession sets cookies and CSRF token after successful authentication
func (a *AuthService) setupUserSession(w http.ResponseWriter, r *http.Request,
	authResponse *supabase.AuthenticatedDetails, userInfo *supabase.User, remember bool) string {

	// Set authentication cookies
	a.setAuthCookies(w, r, authResponse.AccessToken, authResponse.RefreshToken, remember)

	// Set CSRF token
	csrfToken := a.generateCSRFToken(userInfo.ID)
	a.setCSRFCookie(w, r, csrfToken)

	// calculate expires_at
	expiresAt := time.Now().Add(time.Duration(authResponse.ExpiresIn) * time.Second)

	// set user session in supabase
	var userSession supabase.JSONMap
	a.Supabase.DB.From("user_sessions").Insert([]supabase.JSONMap{
		{
			"auth_token":    authResponse.AccessToken,
			"refresh_token": authResponse.RefreshToken,
			"session_id":    uuid.New().String(),
			"user_id":       userInfo.ID,
			"email":         userInfo.Email,
			"tier":          getTierFromUser(userInfo),
			"sig":           "dummy sig",
			"permissions":   make(map[string]interface{}),
			"login_time":    time.Now(),
			"last_seen":     time.Now(),
			"expires_at":    expiresAt,
			"ip_address":    r.RemoteAddr,
			"user_agent":    r.UserAgent(),
		},
	}).Execute(&userSession)

	return csrfToken
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

// Helper function to extract auth token from request
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

	return ""
}

// Helper function to validate token with Supabase
func validateAuthToken(a *AuthService, ctx context.Context, token string) (*supabase.User, bool) {
	validateCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	user, err := a.Supabase.Auth.User(validateCtx, token)
	if err != nil {
		if a.Config.DebugMode {
			a.Logger.Printf("[DEBUG] AuthContext: Token validation failed: %v", err)
		}
		return nil, false
	}

	if user == nil {
		if a.Config.DebugMode {
			a.Logger.Printf("[DEBUG] AuthContext: Token validated but user object is nil")
		}
		return nil, false
	}

	if a.Config.DebugMode {
		a.Logger.Printf("[DEBUG] AuthContext: Valid user found via token: %s (ID: %s)",
			maskEmail(user.Email), maskID(user.ID))
	}

	return user, true
}

// Helper function to get session from cache
func getUserSessionFromCache(a *AuthService, userID string) (*UserSession, bool) {
	const cacheTTL = 5 * time.Minute

	userSessionCacheMutex.RLock()
	cachedSession, found := userSessionCache[userID]
	userSessionCacheMutex.RUnlock()

	if found && time.Since(cachedSession.CreatedAt) < cacheTTL {
		if a.Config.DebugMode {
			a.Logger.Printf("[DEBUG] AuthContext: User session cache HIT for user %s", userID)
		}
		return cachedSession, true
	}

	if a.Config.DebugMode {
		if found {
			a.Logger.Printf("[DEBUG] AuthContext: User session cache EXPIRED for user %s", userID)
		} else {
			a.Logger.Printf("[DEBUG] AuthContext: User session cache MISS for user %s", userID)
		}
	}

	return nil, false
}

// Helper function to build and cache user session
func buildUserSession(a *AuthService, user *supabase.User) *UserSession {
	userRole := "user"
	userTier := "free"
	permissions := make(map[string]interface{})

	// Try BAN ACL first
	banUser, banFound := a.getUserByEmail(user.Email)
	if banFound {
		userRole = banUser.UserData.Role
		userTier = banUser.UserData.Tier
		permissions = banUser.Permissions

		if a.Config.DebugMode {
			a.Logger.Printf("[DEBUG] AuthContext: Found user %s in BAN ACL (Role: %s, Tier: %s)",
				user.Email, userRole, userTier)
		}
	} else {
		// Get role/tier from metadata
		if user.UserMetadata != nil {
			if metaRole, ok := user.UserMetadata["role"].(string); ok && metaRole != "" {
				userRole = metaRole
			}
			if metaTier, ok := user.UserMetadata["tier"].(string); ok && metaTier != "" {
				userTier = metaTier
			}
		}

		// Get permissions based on role/tier
		setPermissionsFromACL(a, &userRole, &userTier, &permissions)

		if a.Config.DebugMode {
			a.Logger.Printf("[DEBUG] AuthContext: User %s not in BAN ACL, determined Role: %s, Tier: %s from metadata/defaults",
				user.Email, userRole, userTier)
		}
	}

	// Create new session
	newSession := &UserSession{
		User:        user,
		Role:        userRole,
		Tier:        userTier,
		Permissions: permissions,
		CreatedAt:   time.Now(),
	}

	// Cache the session
	userSessionCacheMutex.Lock()
	userSessionCache[user.ID] = newSession
	userSessionCacheMutex.Unlock()

	if a.Config.DebugMode {
		a.Logger.Printf("[DEBUG] AuthContext: Added UserSession to context (Role: %s, Tier: %s, Permissions: %d keys)",
			newSession.Role, newSession.Tier, len(newSession.Permissions))
	}

	return newSession
}

// Helper function to set permissions from ACL
func setPermissionsFromACL(a *AuthService, userRole *string, userTier *string, permissions *map[string]interface{}) {
	// Try tier first
	aclPerms, resolvedName, aclFound := a.getACLDataByTierRole(*userTier)

	if !aclFound {
		// Try role if tier not found
		aclPerms, resolvedName, aclFound = a.getACLDataByTierRole(*userRole)
	}

	if aclFound {
		*permissions = aclPerms

		// Update role/tier based on what was found
		if _, isRole := Config.ACL.Roles[resolvedName]; isRole {
			*userRole = resolvedName
		} else {
			*userTier = resolvedName
		}
	} else {
		// Fallback to default user permissions
		userPerms, _, userRoleFound := a.getACLDataByTierRole("user")
		if userRoleFound {
			*permissions = userPerms
			*userRole = "user"
		}
	}
}
