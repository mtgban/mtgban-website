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
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	supabase "github.com/nedpals/supabase-go"
	"golang.org/x/time/rate"
)

// ============================================================================================
// Constants and Types
// ============================================================================================

const (
	DefaultHost              = "www.mtgban.com"
	DefaultSignatureDuration = 11 * 24 * time.Hour
)

// Error message constants
const (
	ErrMsg        = "Join the BAN Community and gain access to exclusive tools!"
	ErrMsgPlus    = "Increase your pledge to gain access to this feature!"
	ErrMsgDenied  = "Something went wrong while accessing this page"
	ErrMsgExpired = "You've been logged out"
	ErrMsgRestart = "Website is restarting, please try again in a few minutes"
	ErrMsgUseAPI  = "Slow down, you're making too many requests! For heavy data use consider the BAN API"
)

//go:embed all:nextAuth/out
var authAssets embed.FS

// Map content types
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

// Map of auth page routes to their corresponding HTML files
var authPagesMap = map[string]string{
	"/auth/login":           "login.html",
	"/auth/signup":          "signup.html",
	"/auth/account":         "account.html",
	"/auth/pricing":         "pricing.html",
	"/auth/reset-password":  "reset-password.html",
	"/auth/forgot-password": "forgot-password.html",
	"/auth/confirmation":    "confirmation.html",
	"/auth/success":         "success.html",
}

type SessionKey string

// AuthError represents an auth-related error
type AuthError struct {
	Code       string
	Message    string
	StatusCode int
	Internal   error
	Field      string
}

// Error returns the error string
func (e AuthError) Error() string {
	if e.Internal != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Internal)
	}
	return e.Message
}

// APIResponse represents a API response
type APIResponse struct {
	Success    bool        `json:"success"`
	Message    string      `json:"message,omitempty"`
	Error      string      `json:"error,omitempty"`
	Code       string      `json:"code,omitempty"`
	Field      string      `json:"field,omitempty"`
	Data       interface{} `json:"data,omitempty"`
	RedirectTo string      `json:"redirectTo,omitempty"`
}

// AuthConfig holds the configuration for the authentication service
type AuthConfig struct {
	// Server settings
	Domain        string `json:"domain"`
	Port          string `json:"port"`
	SecureCookies bool   `json:"secure_cookies"`
	CookieDomain  string `json:"cookie_domain"`

	// Auth provider settings
	SupabaseURL     string `json:"supabase_url"`
	SupabaseAnonKey string `json:"supabase_anon_key"`
	SupabaseRoleKey string `json:"supabase_role_key"`
	SupabaseSecret  string `json:"supabase_jwt_secret"`

	// Security settings
	CSRFSecret   string        `json:"csrf_secret"`
	SignatureTTL time.Duration `json:"signature_ttl"`

	// Access Control
	ExemptRoutes   []string `json:"exempt_routes"`
	ExemptPrefixes []string `json:"exempt_prefixes"`
	ExemptSuffixes []string `json:"exempt_suffixes"`

	// Rate Limiting
	LoginRateLimit  int `json:"login_rate_limit"`
	SignupRateLimit int `json:"signup_rate_limit"`
	APIRateLimit    int `json:"api_rate_limit"`
	PublicRateLimit int `json:"public_rate_limit"`

	// Assets
	AssetsPath string `json:"assets_path"`

	// Dev mode
	DebugMode bool   `json:"debug_mode"`
	LogPrefix string `json:"log_prefix"`

	ACL ACLConfig `json:"acl"`
}

// Validate validates the auth configuration
func (c AuthConfig) Validate() error {
	if c.SupabaseURL == "" {
		return errors.New("SupabaseURL is required")
	}

	if c.SupabaseAnonKey == "" {
		return errors.New("SupabaseAnonKey is required")
	}

	return nil
}

// ACLConfig represents the access control list configuration
type ACLConfig struct {
	Tiers       map[string]map[string]map[string]string `json:"tier"`
	Roles       map[string]map[string]map[string]string `json:"role"`
	NavSections []string                                `json:"nav_sections"`
}

// StandardErrors defines all error types
type StandardErrors struct {
	Forbidden          AuthError
	InvalidForm        AuthError
	InvalidCredentials AuthError
	SessionExpired     AuthError
	EmailTaken         AuthError
	WeakPassword       AuthError
	CSRFValidation     AuthError
	RateLimitExceeded  AuthError
	MissingToken       AuthError
	InvalidToken       AuthError
	ServerError        AuthError
}

// UserSession represents a user session
type UserSession struct {
	AccessToken  string
	RefreshToken string
	CSRFToken    string
	BanSignature string
	UserID       string
	Email        string
	Tier         string
	Role         string
	Metadata     map[string]interface{}
	ExpiresAt    time.Time
}

// UserData holds user data for MTGBAN users
type UserData struct {
	UserId string `json:"user_id"`
	Email  string `json:"email"`
	Tier   string `json:"tier"`
}

// BanUser represents a user in the ban ACL
type BanUser struct {
	User        *UserData              `json:"user"`
	Permissions map[string]interface{} `json:"permissions"`
}

// BanACL represents the ban access control list
type BanACL struct {
	Users map[string]*BanUser
}

// CookieOptions stores configuration for a cookie
type CookieOptions struct {
	HttpOnly bool
	Path     string
	SameSite http.SameSite
	MaxAge   int // In seconds, -1 for session, 0 for delete
}

// LoginRequest represents a login request payload
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Remember bool   `json:"remember"`
}

// SignupRequest represents a signup request payload
type SignupRequest struct {
	Email    string                 `json:"email"`
	Password string                 `json:"password"`
	UserData map[string]interface{} `json:"userData"`
}

// PasswordResetRequest represents a password reset request payload
type PasswordResetRequest struct {
	Email string `json:"email"`
}

// PasswordUpdateRequest represents a password update request payload
type PasswordUpdateRequest struct {
	Password string `json:"password"`
	Token    string `json:"token"`
}

// AuthRoute represents a route with its handler and middleware
type AuthRoute struct {
	Path        string
	Method      string
	Handler     http.HandlerFunc
	Middleware  string
	Description string
}

// Middleware wraps an HTTP handler
type Middleware func(http.Handler) http.Handler

// NewStandardErrors creates all standard errors
func NewStandardErrors() StandardErrors {
	return StandardErrors{
		Forbidden: AuthError{
			Code:       "FORBIDDEN",
			Message:    "Access denied",
			StatusCode: http.StatusForbidden,
		},
		InvalidForm: AuthError{
			Code:       "INVALID_FORM",
			Message:    "Invalid form submission",
			StatusCode: http.StatusBadRequest,
		},
		InvalidCredentials: AuthError{
			Code:       "INVALID_CREDENTIALS",
			Message:    "Invalid email or password",
			StatusCode: http.StatusUnauthorized,
		},
		SessionExpired: AuthError{
			Code:       "SESSION_EXPIRED",
			Message:    "Your session has expired. Please log in again.",
			StatusCode: http.StatusUnauthorized,
		},
		EmailTaken: AuthError{
			Code:       "EMAIL_TAKEN",
			Message:    "Email address is already in use",
			StatusCode: http.StatusBadRequest,
		},
		WeakPassword: AuthError{
			Code:       "WEAK_PASSWORD",
			Message:    "Password does not meet strength requirements",
			StatusCode: http.StatusBadRequest,
		},
		CSRFValidation: AuthError{
			Code:       "INVALID_CSRF_TOKEN",
			Message:    "Invalid security token",
			StatusCode: http.StatusForbidden,
		},
		RateLimitExceeded: AuthError{
			Code:       "RATE_LIMIT_EXCEEDED",
			Message:    "Too many requests. Please try again later.",
			StatusCode: http.StatusTooManyRequests,
		},
		MissingToken: AuthError{
			Code:       "MISSING_TOKEN",
			Message:    "Authentication required",
			StatusCode: http.StatusUnauthorized,
		},
		InvalidToken: AuthError{
			Code:       "INVALID_TOKEN",
			Message:    "Invalid authentication token",
			StatusCode: http.StatusUnauthorized,
		},
		ServerError: AuthError{
			Code:       "SERVER_ERROR",
			Message:    "An unexpected error occurred",
			StatusCode: http.StatusInternalServerError,
		},
	}
}

// ==============================================================================================
// DefaultAuthConfig
// ==============================================================================================

// DefaultAuthConfig returns the default authentication configuration
func DefaultAuthConfig() AuthConfig {
	return AuthConfig{
		LogPrefix: "[Auth] ",
		ExemptRoutes: []string{
			"/",
			"/home",
			"/auth",
		},
		ExemptPrefixes: []string{
			"/public/",
			"/css/",
			"/js/",
			"/img/",
		},
		ExemptSuffixes: []string{
			".css",
			".js",
			".ico",
			".png",
			".jpg",
			".jpeg",
			".gif",
			".svg",
		},
		SignatureTTL: DefaultSignatureDuration,
		ACL: ACLConfig{
			NavSections: []string{
				"Search", "Newspaper", "Sleepers", "Upload",
				"Global", "Arbit", "Reverse", "Admin", "API",
			},
			Tiers: make(map[string]map[string]map[string]string),
		},
	}
}

// LoadAuthConfig loads auth configuration from a file
func LoadAuthConfig(filePath string) (AuthConfig, error) {
	// Start with default configuration
	config := DefaultAuthConfig()

	if filePath == "" {
		return config, nil
	}

	// Try to load from file
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return config, nil // Use defaults if file doesn't exist
		}
		return config, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	// Parse config file
	if err := json.NewDecoder(file).Decode(&config); err != nil {
		return config, fmt.Errorf("failed to parse config file: %w", err)
	}

	return config, nil
}

// ==============================================================================================
// ErrorHandler Implementation
// ==============================================================================================

// ErrorHandler provides error handling
type ErrorHandler struct {
	logger   *log.Logger
	debug    bool
	renderer *AssetLoader
	errors   StandardErrors
}

// NewErrorHandler creates a new error handler
func NewErrorHandler(logger *log.Logger, debug bool) *ErrorHandler {
	return &ErrorHandler{
		logger: logger,
		debug:  debug,
		errors: NewStandardErrors(),
	}
}

// SetRenderer sets the renderer for HTML error pages
func (eh *ErrorHandler) SetRenderer(renderer *AssetLoader) {
	eh.renderer = renderer
}

// RespondWithError handles all error responses
func (eh *ErrorHandler) RespondWithError(w http.ResponseWriter, r *http.Request, err AuthError, internal error) {
	// Update internal error if provided
	if internal != nil {
		err.Internal = internal
	}

	// Log the error
	if err.Internal != nil {
		eh.logger.Printf("Error (%s): %v", err.Code, err.Internal)
	} else {
		eh.logger.Printf("Error (%s): %s", err.Code, err.Message)
	}

	// Determine response based on request type
	if isAPIRequest(r) {
		eh.sendAPIError(w, err)
	} else if isFormSubmission(r) {
		eh.redirectWithError(w, r, err)
	} else {
		eh.renderErrorPage(w, err)
	}
}

// sendAPIError sends a JSON error response
func (eh *ErrorHandler) sendAPIError(w http.ResponseWriter, err AuthError) {
	response := APIResponse{
		Success: false,
		Error:   err.Message,
		Code:    err.Code,
		Field:   err.Field,
	}

	// Include debug info if enabled
	if eh.debug && err.Internal != nil {
		response.Error = fmt.Sprintf("%s: %v", err.Message, err.Internal)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.StatusCode)
	json.NewEncoder(w).Encode(response)
}

// redirectWithError redirects with error parameters
func (eh *ErrorHandler) redirectWithError(w http.ResponseWriter, r *http.Request, err AuthError) {
	// Determine return path based on the error and request
	returnPath := determineReturnPath(r, err)

	// Build redirect URL with error parameters
	redirectURL := fmt.Sprintf("%s?error=%s&message=%s",
		returnPath,
		url.QueryEscape(err.Code),
		url.QueryEscape(err.Message))

	// Add field for form errors if specified
	if err.Field != "" {
		redirectURL += "&field=" + url.QueryEscape(err.Field)
	}

	// Preserve return_to parameter if present
	if returnTo := r.FormValue("return_to"); returnTo != "" {
		redirectURL += "&return_to=" + url.QueryEscape(returnTo)
	}

	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// renderErrorPage renders an HTML error page
func (eh *ErrorHandler) renderErrorPage(w http.ResponseWriter, err AuthError) {
	w.WriteHeader(err.StatusCode)

	// Prepare template data
	data := map[string]interface{}{
		"Title":   fmt.Sprintf("Error: %s", err.Code),
		"Message": err.Message,
		"Code":    err.Code,
		"Status":  err.StatusCode,
	}

	// Include debug info if enabled
	if eh.debug && err.Internal != nil {
		data["Debug"] = err.Internal.Error()
	}

	// Render template if available, otherwise use fallback
	if eh.renderer != nil {
		if err := eh.renderer.RenderTemplate(w, "error.html", data); err != nil {
			eh.renderFallbackErrorPage(w, data)
		}
	} else {
		eh.renderFallbackErrorPage(w, data)
	}
}

// renderFallbackErrorPage renders a basic HTML error page
func (eh *ErrorHandler) renderFallbackErrorPage(w http.ResponseWriter, data map[string]interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// HTML template with error information
	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>{{.Title}}</title>
		<style>
			body { font-family: sans-serif; margin: 40px; line-height: 1.6; }
			.error-container { max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
			.error-title { color: #d32f2f; margin-top: 0; }
			.error-message { background-color: #ffebee; padding: 15px; border-radius: 4px; }
			.error-code { color: #555; font-size: 0.9em; margin-top: 15px; }
			.error-debug { background-color: #f5f5f5; padding: 10px; font-family: monospace; margin-top: 15px; overflow-x: auto; }
		</style>
	</head>
	<body>
		<div class="error-container">
			<h1 class="error-title">{{.Title}}</h1>
			<div class="error-message">{{.Message}}</div>
			<div class="error-code">Error code: {{.Code}} (Status: {{.Status}})</div>
			{{if .Debug}}<div class="error-debug">Debug: {{.Debug}}</div>{{end}}
			<p><a href="/">Return to home page</a></p>
		</div>
	</body>
	</html>
	`

	// Replace template variables
	for key, value := range data {
		placeholder := "{{." + key + "}}"
		strValue := fmt.Sprintf("%v", value)
		html = strings.Replace(html, placeholder, strValue, -1)
	}

	// Handle conditional debug info
	if debug, ok := data["Debug"]; ok {
		debugHTML := fmt.Sprintf(`<div class="error-debug">Debug: %v</div>`, debug)
		html = strings.Replace(html, `{{if .Debug}}<div class="error-debug">Debug: {{.Debug}}</div>{{end}}`, debugHTML, 1)
	} else {
		html = strings.Replace(html, `{{if .Debug}}<div class="error-debug">Debug: {{.Debug}}</div>{{end}}`, "", 1)
	}

	w.Write([]byte(html))
}

// ==============================================================================================
// SessionManager
// ==============================================================================================

// SessionManager handles all session operations
type SessionManager struct {
	domain        string
	secureCookies bool
	sameSite      http.SameSite
	csrfSecret    []byte
	logger        *log.Logger
	banACL        *BanACL
	authService   *AuthService
	cookieOptions map[string]CookieOptions
}

// NewSessionManager creates a new session manager
func NewSessionManager(domain string, secureCookies bool, csrfSecret []byte, logger *log.Logger) *SessionManager {
	// Determine SameSite mode based on security settings
	sameSite := http.SameSiteStrictMode
	if !secureCookies {
		sameSite = http.SameSiteLaxMode
	}

	// Define standard cookie configurations
	cookieOptions := map[string]CookieOptions{
		"auth_token": {
			HttpOnly: true,
			Path:     "/",
			SameSite: sameSite,
			MaxAge:   24 * 60 * 60, // 24 hours default
		},
		"refresh_token": {
			HttpOnly: true,
			Path:     "/",
			SameSite: sameSite,
			MaxAge:   60 * 24 * 60 * 60, // 60 days
		},
		"csrf_token": {
			HttpOnly: false, // Accessible to JS
			Path:     "/",
			SameSite: sameSite,
			MaxAge:   24 * 60 * 60,
		},
		"MTGBAN": {
			HttpOnly: true,
			Path:     "/",
			SameSite: sameSite,
			MaxAge:   30 * 24 * 60 * 60, // 30 days
		},
	}

	return &SessionManager{
		domain:        domain,
		secureCookies: secureCookies,
		sameSite:      sameSite,
		csrfSecret:    csrfSecret,
		logger:        logger,
		cookieOptions: cookieOptions,
	}
}

// setCookie sets a cookie with the standard options
func (sm *SessionManager) setCookie(w http.ResponseWriter, name, value string, maxAgeOverride int) {
	options, exists := sm.cookieOptions[name]
	if !exists {
		// Use default options
		options = CookieOptions{
			HttpOnly: true,
			Path:     "/",
			SameSite: sm.sameSite,
			MaxAge:   24 * 60 * 60, // 24 hours default
		}
	}

	// Override MaxAge if specified
	maxAge := options.MaxAge
	if maxAgeOverride != 0 {
		maxAge = maxAgeOverride
	}

	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     options.Path,
		Domain:   sm.domain,
		HttpOnly: options.HttpOnly,
		Secure:   sm.secureCookies,
		SameSite: options.SameSite,
		MaxAge:   maxAge,
	})
}

// SetSession establishes a user session with all required cookies
func (sm *SessionManager) SetSession(w http.ResponseWriter, r *http.Request, session *UserSession) {
	// Set auth_token cookie
	sm.setCookie(w, "auth_token", session.AccessToken, int(time.Until(session.ExpiresAt).Seconds()))

	// Set refresh_token cookie
	sm.setCookie(w, "refresh_token", session.RefreshToken, 0) // Use default

	// Set CSRF token cookie
	sm.setCookie(w, "csrf_token", session.CSRFToken, int(time.Until(session.ExpiresAt).Seconds()))

	// Set MTGBAN signature cookie
	sm.setCookie(w, "MTGBAN", session.BanSignature, 0) // Use default

	sm.logger.Printf("Session established for user: %s (tier: %s)", session.Email, session.Tier)
}

// ClearSession clears all session cookies
func (sm *SessionManager) ClearSession(w http.ResponseWriter, r *http.Request) {
	// List of cookies to clear
	cookieNames := []string{"auth_token", "refresh_token", "csrf_token", "MTGBAN"}

	for _, name := range cookieNames {
		// Clear with domain
		sm.setCookie(w, name, "", -1)

		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			MaxAge:   -1,
			Expires:  time.Unix(0, 0),
		})
	}

	sm.logger.Printf("Session cleared for request from: %s", getClientIP(r))
}

// GetSession retrieves and validates the current session
func (sm *SessionManager) GetSession(r *http.Request) (*UserSession, error) {
	// Get auth token from cookie
	authCookie, err := r.Cookie("auth_token")
	if err != nil || authCookie.Value == "" {
		return nil, errors.New("no auth token found")
	}

	// Get refresh token
	refreshCookie, _ := r.Cookie("refresh_token")
	refreshToken := ""
	if refreshCookie != nil {
		refreshToken = refreshCookie.Value
	}

	// Get CSRF token
	csrfCookie, _ := r.Cookie("csrf_token")
	csrfToken := ""
	if csrfCookie != nil {
		csrfToken = csrfCookie.Value
	}

	// Get MTGBAN signature
	mtgbanCookie, _ := r.Cookie("MTGBAN")
	banSignature := ""
	if mtgbanCookie != nil {
		banSignature = mtgbanCookie.Value
	}

	// Validate token with Supabase
	ctx := r.Context()
	userInfo, err := sm.validateSupabaseToken(ctx, authCookie.Value)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	// Extract tier from metadata
	tier := extractTier(userInfo)

	// Return session
	return &UserSession{
		AccessToken:  authCookie.Value,
		RefreshToken: refreshToken,
		CSRFToken:    csrfToken,
		BanSignature: banSignature,
		UserID:       userInfo.ID,
		Email:        userInfo.Email,
		Tier:         tier,
		Role:         getUserRole(userInfo),
		Metadata:     userInfo.UserMetadata,
		ExpiresAt:    time.Now().Add(24 * time.Hour), // Approximate JWT expiration
	}, nil
}

// RefreshSession attempts to refresh an expired session
func (sm *SessionManager) RefreshSession(w http.ResponseWriter, r *http.Request) (*UserSession, error) {
	// Get refresh token from cookie
	refreshCookie, err := r.Cookie("refresh_token")
	if err != nil || refreshCookie.Value == "" {
		return nil, errors.New("no refresh token found")
	}

	// Get current auth token if available
	var currentToken string
	authCookie, authErr := r.Cookie("auth_token")
	if authErr == nil && authCookie.Value != "" {
		currentToken = authCookie.Value
	}

	// Call Supabase to refresh token
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	authResponse, err := sm.authService.Supabase.Auth.RefreshUser(ctx, currentToken, refreshCookie.Value)
	if err != nil {
		sm.logger.Printf("Token refresh failed: %v", err)
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	// Extract new tokens
	newAccessToken := authResponse.AccessToken
	newRefreshToken := authResponse.RefreshToken

	// Get user data with new token
	userInfo, err := sm.authService.Supabase.Auth.User(ctx, newAccessToken)
	if err != nil {
		sm.logger.Printf("Error retrieving user data after refresh: %v", err)
		return nil, fmt.Errorf("failed to get user data: %w", err)
	}

	// Extract tier from metadata
	tier := extractTier(userInfo)

	// Extract role
	role := getUserRole(userInfo)

	// Generate new CSRF token
	csrfToken := sm.generateCSRFToken(userInfo.ID)

	// Generate new BAN signature
	userData := &UserData{
		UserId: userInfo.ID,
		Email:  userInfo.Email,
		Tier:   tier,
	}

	baseURL := getBaseURL(r)
	banSignature := sm.authService.sign(baseURL, tier, userData)

	// Create new session
	session := &UserSession{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		CSRFToken:    csrfToken,
		BanSignature: banSignature,
		UserID:       userInfo.ID,
		Email:        userInfo.Email,
		Tier:         tier,
		Role:         role,
		Metadata:     userInfo.UserMetadata,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}

	// Set new session cookies
	sm.SetSession(w, r, session)

	sm.logger.Printf("Session refreshed for user: %s (tier: %s)", session.Email, session.Tier)
	return session, nil
}

// validateSupabaseToken validates a token with Supabase
func (sm *SessionManager) validateSupabaseToken(ctx context.Context, token string) (*supabase.User, error) {
	return sm.authService.Supabase.Auth.User(ctx, token)
}

// generateCSRFToken generates a CSRF token for a user
func (sm *SessionManager) generateCSRFToken(userID string) string {
	h := hmac.New(sha256.New, sm.csrfSecret)
	h.Write([]byte(userID))
	h.Write([]byte(time.Now().Format("2006-01-02")))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// ==============================================================================================
// PermissionManager
// ==============================================================================================

// PermissionManager handles all permission checks
type PermissionManager struct {
	config      *AuthConfig
	logger      *log.Logger
	banACL      *BanACL
	pathCache   map[string]bool // Cache for exempt path checks
	accessCache map[string]bool // Cache for access check results
	cacheMutex  sync.RWMutex    // Mutex for thread-safe cache access
}

// NewPermissionManager creates a new permission manager
func NewPermissionManager(config *AuthConfig, logger *log.Logger, banACL *BanACL) *PermissionManager {
	// Pre-compute common exempt paths
	pathCache := make(map[string]bool)
	for _, route := range config.ExemptRoutes {
		pathCache[route] = true
	}

	return &PermissionManager{
		config:      config,
		logger:      logger,
		banACL:      banACL,
		pathCache:   pathCache,
		accessCache: make(map[string]bool),
	}
}

// IsExemptPath checks if a path is exempt from auth
func (pm *PermissionManager) IsExemptPath(path string) bool {
	// Check cache first
	if exempt, found := pm.pathCache[path]; found {
		return exempt
	}

	// Always exempt the root and common paths
	if path == "/" || path == "/home" {
		pm.pathCache[path] = true
		return true
	}

	// Check exact routes
	if pm.pathCache[path] {
		return true
	}

	// Check prefixes
	for _, prefix := range pm.config.ExemptPrefixes {
		if strings.HasPrefix(path, prefix) {
			pm.pathCache[path] = true
			return true
		}
	}

	// Check suffixes
	for _, suffix := range pm.config.ExemptSuffixes {
		if strings.HasSuffix(path, suffix) {
			pm.pathCache[path] = true
			return true
		}
	}

	pm.pathCache[path] = false
	return false
}

// HasPermission is the main entry point for permission checks
func (pm *PermissionManager) HasPermission(session *UserSession, path string) bool {
	// Check if path is exempt from authentication
	if pm.IsExemptPath(path) {
		return true
	}

	// Generate cache key
	cacheKey := fmt.Sprintf("%s:%s:%s:%s", session.UserID, session.Role, session.Tier, path)

	// Check cache first
	pm.cacheMutex.RLock()
	if hasAccess, found := pm.accessCache[cacheKey]; found {
		pm.cacheMutex.RUnlock()
		return hasAccess
	}
	pm.cacheMutex.RUnlock()

	// Determine access
	hasAccess := pm.hasAccess(session, path)

	// Cache the result
	pm.cacheMutex.Lock()
	pm.accessCache[cacheKey] = hasAccess
	pm.cacheMutex.Unlock()

	return hasAccess
}

// hasAccess is the core permission check
func (pm *PermissionManager) hasAccess(session *UserSession, path string) bool {
	// Default paths accessible to all authenticated users
	defaultPaths := map[string]bool{
		"/account": true,
		"/pricing": true,
	}

	if defaultPaths[path] {
		return true
	}

	// Admin/root roles have access to everything
	if session.Role == "admin" || session.Role == "root" {
		return true
	}

	// Check role-based permissions
	if session.Role != "" && pm.hasRoleAccess(session.Role, path) {
		return true
	}

	// Check tier-based permissions
	if session.Tier != "" && pm.hasTierAccess(session.Tier, path) {
		return true
	}

	// Check BanACL for specific permissions
	if pm.banACL != nil {
		user, exists := pm.banACL.Users[session.Email]
		if exists {
			for section, permissions := range user.Permissions {
				// Check if this is a nav section
				if pm.isNavSection(section) {
					// Check specific path permission
					if permMap, ok := permissions.(map[string]interface{}); ok {
						if _, ok := permMap[path]; ok {
							return true
						}
					}

					// If section matches path section, grant access
					pathSection := determinePathSection(path, pm.getNavSections())
					if pathSection == section {
						return true
					}
				}
			}
		}
	}

	return false
}

// hasRoleAccess checks role-based access to a path
func (pm *PermissionManager) hasRoleAccess(role, path string) bool {
	section := determinePathSection(path, pm.getNavSections())
	if section == "" {
		pm.logger.Printf("No section found for path: %s", path)
		return false
	}

	roleConfig, exists := pm.config.ACL.Roles[role]
	if !exists {
		pm.logger.Printf("Role '%s' not found in ACL", role)
		return false
	}

	// Check if role has access to this section
	sectionConfig, exists := roleConfig[section]
	if !exists {
		pm.logger.Printf("Section '%s' not found for role '%s'", section, role)
		return false
	}

	// Check for any feature-specific permissions
	subPath := getSubPathPermission(path)
	if subPath != "" {
		// Check for explicit denials first
		for key, value := range sectionConfig {
			if strings.HasSuffix(key, "Disabled") &&
				strings.Contains(key, subPath) &&
				value != "NONE" {
				return false
			}
		}

		// Check for explicit permissions
		permKey := section + subPath + "Enabled"
		if value, exists := sectionConfig[permKey]; exists && value == "true" {
			return true
		}

		// Check for specific permissions
		if subPath == "buylist" {
			if value, exists := sectionConfig["UploadBuylistEnabled"]; exists && value == "true" {
				return true
			}
		} else if subPath == "changestore" {
			if value, exists := sectionConfig["UploadChangeStoresEnabled"]; exists && value == "true" {
				return true
			}
		} else if subPath == "optimizer" {
			if value, exists := sectionConfig["UploadOptimizer"]; exists && value == "true" {
				return true
			}
		} else if subPath == "download" || subPath == "csv" {
			if value, exists := sectionConfig["SearchDownloadCSV"]; exists && value == "true" {
				return true
			}
		}
	}

	// If there's section access and no specific denials, grant access
	return true
}

// hasTierAccess checks tier-based access to a path
func (pm *PermissionManager) hasTierAccess(tier, path string) bool {
	section := determinePathSection(path, pm.getNavSections())
	if section == "" {
		pm.logger.Printf("No section found for path: %s", path)
		return false
	}

	tierConfig, exists := pm.config.ACL.Tiers[tier]
	if !exists {
		pm.logger.Printf("Tier '%s' not found in ACL", tier)
		return false
	}

	sectionConfig, exists := tierConfig[section]
	if !exists {
		pm.logger.Printf("Section '%s' not found for tier '%s'", section, tier)
		return false
	}

	// Check for any feature-specific permissions
	subPath := getSubPathPermission(path)
	if subPath != "" {
		// Check for explicit denials first
		for key, value := range sectionConfig {
			if strings.HasSuffix(key, "Disabled") &&
				strings.Contains(key, subPath) &&
				value != "NONE" {
				return false
			}
		}

		// Check for explicit permissions based on the ACL format
		if subPath == "buylist" {
			if value, exists := sectionConfig["UploadBuylistEnabled"]; exists && value == "true" {
				return true
			}
		} else if subPath == "changestore" {
			if value, exists := sectionConfig["UploadChangeStoresEnabled"]; exists && value == "true" {
				return true
			}
		} else if subPath == "optimizer" {
			if value, exists := sectionConfig["UploadOptimizer"]; exists && value == "true" {
				return true
			}
		} else if subPath == "download" || subPath == "csv" {
			if value, exists := sectionConfig["SearchDownloadCSV"]; exists && value == "true" {
				return true
			}
		}
	}

	// If there's section access and no specific denials, grant access
	return true
}

// isNavSection checks if a section name is in the navigation sections
func (pm *PermissionManager) isNavSection(section string) bool {
	navSections := pm.getNavSections()

	for _, s := range navSections {
		if s == section {
			return true
		}
	}

	return false
}

// getNavSections gets the list of navigation sections
func (pm *PermissionManager) getNavSections() []string {
	// Use configured nav sections if available
	if len(pm.config.ACL.NavSections) > 0 {
		return pm.config.ACL.NavSections
	}

	// Otherwise, infer from the ACL structure
	sectionSet := make(map[string]bool)

	// Extract from roles
	for _, roleConfig := range pm.config.ACL.Roles {
		for section := range roleConfig {
			sectionSet[section] = true
		}
	}

	// Extract from tiers
	for _, tierConfig := range pm.config.ACL.Tiers {
		for section := range tierConfig {
			sectionSet[section] = true
		}
	}

	// Convert map to slice
	var sections []string
	for section := range sectionSet {
		sections = append(sections, section)
	}

	return sections
}

// ClearCache clears the permission caches
func (pm *PermissionManager) ClearCache() {
	pm.cacheMutex.Lock()
	pm.pathCache = make(map[string]bool)
	pm.accessCache = make(map[string]bool)
	pm.cacheMutex.Unlock()
}

// ==============================================================================================
// AssetLoader
// ==============================================================================================

// AssetLoader handles embedded asset loading
type AssetLoader struct {
	fs           embed.FS
	rootDir      string
	contentTypes map[string]string
	logger       *log.Logger
	pathHandlers map[string]func(http.ResponseWriter, *http.Request)
}

// NewAssetLoader creates a new asset loader
func NewAssetLoader(embedFS embed.FS, rootDir string, logger *log.Logger) (*AssetLoader, error) {
	// If rootDir is empty or ".", use the default path based on the go:embed directive
	if rootDir == "" || rootDir == "." {
		rootDir = "nextAuth/out"
	}

	// Use fs.Sub correctly to get a sub-filesystem just to verify the path is valid
	logger.Printf("Creating sub-filesystem with path: %s", rootDir)
	_, err := fs.Sub(embedFS, rootDir)
	if err != nil {
		logger.Printf("Failed to create sub-filesystem: %v", err)
		return nil, fmt.Errorf("failed to create sub FS: %w", err)
	}

	loader := &AssetLoader{
		fs:           embedFS, // Keep the original FS for access to the whole hierarchy
		rootDir:      rootDir,
		contentTypes: contentTypeMap,
		logger:       logger,
		pathHandlers: make(map[string]func(http.ResponseWriter, *http.Request)),
	}

	// Register special page handlers
	loader.RegisterPathHandler("confirmation", loader.serveConfirmationPage)
	loader.RegisterPathHandler("reset-password-sent", loader.serveResetPasswordSentPage)
	loader.RegisterPathHandler("success", loader.serveSuccessPage)

	return loader, nil
}

// RegisterPathHandler registers a custom handler for a specific path
func (al *AssetLoader) RegisterPathHandler(path string, handler func(http.ResponseWriter, *http.Request)) {
	al.pathHandlers[path] = handler
}

// ServeAsset serves an embedded asset
func (al *AssetLoader) ServeAsset(w http.ResponseWriter, r *http.Request) {
	// Extract path from request URL
	var path string
	if strings.HasPrefix(r.URL.Path, "/_next/") {
		// Handle Next.js static assets
		path = strings.TrimPrefix(r.URL.Path, "/")
		al.logger.Printf("Serving Next.js asset: %s", path)
	} else {
		// Handle auth/* routes
		path = strings.TrimPrefix(r.URL.Path, "/auth/")

		// Default to index.html for empty path
		if path == "" || path == "/" {
			path = "index.html"
		}

		// Trim trailing slashes before normalization to handle paths like "login/"
		path = strings.TrimSuffix(path, "/")

		// Normalize HTML page paths
		if filepath.Ext(path) == "" {
			htmlPaths := map[string]bool{
				"login": true, "signup": true, "account": true,
				"pricing": true, "reset-password": true,
				"forgot-password": true, "confirmation": true,
			}

			if htmlPaths[path] {
				path += ".html"
			}
		}
	}

	// Check for special page handlers
	pathBase := strings.TrimSuffix(path, filepath.Ext(path))
	if !strings.HasPrefix(r.URL.Path, "/_next/") && pathBase != "" {
		if handler, ok := al.pathHandlers[pathBase]; ok {
			handler(w, r)
			return
		}
	}

	// Set content type based on file extension
	al.setContentType(w, path)

	// Get sub-filesystem
	al.logger.Printf("Creating sub-filesystem for path: %s", al.rootDir)
	authFS, err := fs.Sub(al.fs, al.rootDir)
	if err != nil {
		al.logger.Printf("Failed to access embedded files: %v", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	// Check if file exists
	al.logger.Printf("Checking if file exists: %s", path)
	_, err = fs.Stat(authFS, path)
	if err != nil {
		// Fallback to index.html for HTML routes
		if filepath.Ext(path) == ".html" {
			al.logger.Printf("Trying index.html fallback")
			_, err = fs.Stat(authFS, "index.html")
			if err == nil {
				path = "index.html"
			} else {
				al.logger.Printf("File not found: %s, error: %v", path, err)
				http.NotFound(w, r)
				return
			}
		} else {
			al.logger.Printf("File not found: %s, error: %v", path, err)
			http.NotFound(w, r)
			return
		}
	}

	// Open the file
	al.logger.Printf("Opening file: %s", path)
	file, err := authFS.Open(path)
	if err != nil {
		al.logger.Printf("Error opening file: %s, error: %v", path, err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Read file content
	content, err := io.ReadAll(file)
	if err != nil {
		al.logger.Printf("Error reading file: %s, error: %v", path, err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	// Write content to response
	w.Write(content)
}

// ServeIndexWithData serves index.html with injected data
func (al *AssetLoader) ServeIndexWithData(w http.ResponseWriter, data map[string]interface{}) {
	// Read the index file
	indexPath := filepath.Join(al.rootDir, "index.html")
	indexContent, err := al.fs.ReadFile(indexPath)
	if err != nil {
		al.logger.Printf("Failed to read index.html: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Convert data to JSON for injection
	jsonData, err := json.Marshal(data)
	if err != nil {
		al.logger.Printf("Failed to marshal data: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Inject data script before closing head tag
	htmlContent := string(indexContent)
	if strings.Contains(htmlContent, "</head>") {
		injectScript := fmt.Sprintf(`<script id="__INITIAL_DATA__" type="application/json">%s</script>
	<script>
	window.__INITIAL_DATA__ = JSON.parse(document.getElementById('__INITIAL_DATA__').textContent);
	</script>
	</head>`, jsonData)

		htmlContent = strings.Replace(htmlContent, "</head>", injectScript, 1)
	}

	// Set content type and serve
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(htmlContent))
}

// RenderTemplate renders a template with data
func (al *AssetLoader) RenderTemplate(w http.ResponseWriter, templateName string, data interface{}) error {
	templatePath := filepath.Join(al.rootDir, "templates", templateName)
	templateData, err := al.fs.ReadFile(templatePath)
	if err != nil {
		al.logger.Printf("Template not found: %s", templatePath)
		return err
	}

	htmlContent := string(templateData)
	if dataMap, ok := data.(map[string]interface{}); ok {
		for key, value := range dataMap {
			placeholder := "{{." + key + "}}"
			strValue := fmt.Sprintf("%v", value)
			htmlContent = strings.Replace(htmlContent, placeholder, strValue, -1)
		}
	}

	// Set content type and serve
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(htmlContent))
	return nil
}

// setContentType sets the content type based on file extension
func (al *AssetLoader) setContentType(w http.ResponseWriter, path string) {
	ext := filepath.Ext(path)

	// Ensure that Next.js JS files are served with the correct MIME type
	if strings.HasPrefix(path, "_next/") && ext == ".js" {
		w.Header().Set("Content-Type", "application/javascript")
		return
	}

	// Special case for certain Next.js files
	if strings.Contains(path, "_buildManifest.js") ||
		strings.Contains(path, "_ssgManifest.js") ||
		strings.HasSuffix(path, ".js.map") {
		w.Header().Set("Content-Type", "application/javascript")
		return
	}

	// Use the content type map for other extensions
	if contentType, ok := al.contentTypes[ext]; ok {
		w.Header().Set("Content-Type", contentType)
		return
	}

	// Fallback for common types not in the map
	switch ext {
	case ".js":
		w.Header().Set("Content-Type", "application/javascript")
	case ".css":
		w.Header().Set("Content-Type", "text/css")
	case ".json":
		w.Header().Set("Content-Type", "application/json")
	case ".png":
		w.Header().Set("Content-Type", "image/png")
	case ".jpg", ".jpeg":
		w.Header().Set("Content-Type", "image/jpeg")
	case ".svg":
		w.Header().Set("Content-Type", "image/svg+xml")
	case ".woff":
		w.Header().Set("Content-Type", "font/woff")
	case ".woff2":
		w.Header().Set("Content-Type", "font/woff2")
	case ".ttf":
		w.Header().Set("Content-Type", "font/ttf")
	case ".html", ".htm":
		w.Header().Set("Content-Type", "text/html")
	default:
		// Default to octet-stream for unknown types
		w.Header().Set("Content-Type", "application/octet-stream")
	}
}

// serveConfirmationPage serves the email confirmation page
func (al *AssetLoader) serveConfirmationPage(w http.ResponseWriter, r *http.Request) {
	// Extract query parameters
	email := r.URL.Query().Get("email")
	message := r.URL.Query().Get("message")

	if message == "" {
		message = "Please check your email to verify your account."
	}

	// Create email message paragraph if email is present
	var emailHTML string
	if email != "" {
		emailHTML = "<p>We've sent a verification email to <strong>" + email + "</strong></p>"
	}

	// Serve a simple static HTML confirmation page
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`
	<!DOCTYPE html>
	<html>
	<head>
		<title>Confirm Your Email | MTGBAN</title>
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<style>
			.auth-container {
				max-width: 450px;
				margin: 2rem auto;
				padding: 2rem;
				background-color: #fff;
				border-radius: 8px;
				box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
			}
			.auth-title {
				font-size: 1.75rem;
				margin-bottom: 1rem;
				text-align: center;
			}
			.auth-message {
				padding: 1rem;
				margin-bottom: 1.5rem;
				border-radius: 4px;
			}
			.success-message {
				background-color: rgba(52, 211, 153, 0.2);
				color: #065f46;
				border-left: 4px solid #10b981;
			}
			.auth-links {
				margin-top: 1.5rem;
				text-align: center;
			}
			.auth-links a {
				color: #2563eb;
				text-decoration: none;
			}
			.auth-links a:hover {
				text-decoration: underline;
			}
		</style>
	</head>
	<body>
		<div class="auth-container">
			<h1 class="auth-title">Check Your Email</h1>
			<div class="auth-message success-message">
				` + message + `
			</div>
			` + emailHTML + `
			<div class="auth-links">
				<p>Return to <a href="/auth/login">Login</a></p>
			</div>
		</div>
	</body>
	</html>
	`))
}

// serveResetPasswordSentPage serves the reset password sent page
func (al *AssetLoader) serveResetPasswordSentPage(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")

	var emailHTML string
	if email != "" {
		emailHTML = "<p>We've sent password reset instructions to <strong>" + email + "</strong></p>"
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`
	<!DOCTYPE html>
	<html>
	<head>
		<title>Reset Password | MTGBAN</title>
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<style>
			.auth-container {
				max-width: 450px;
				margin: 2rem auto;
				padding: 2rem;
				background-color: #fff;
				border-radius: 8px;
				box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
			}
			.auth-title {
				font-size: 1.75rem;
				margin-bottom: 1rem;
				text-align: center;
			}
			.auth-message {
				padding: 1rem;
				margin-bottom: 1.5rem;
				border-radius: 4px;
			}
			.info-message {
				background-color: rgba(59, 130, 246, 0.2);
				color: #1e40af;
				border-left: 4px solid #3b82f6;
			}
			.auth-info {
				margin: 1.5rem 0;
			}
			.auth-links {
				margin-top: 1.5rem;
				text-align: center;
			}
			.auth-links a {
				color: #2563eb;
				text-decoration: none;
			}
			.auth-links a:hover {
				text-decoration: underline;
			}
		</style>
	</head>
	<body>
		<div class="auth-container">
			<h1 class="auth-title">Check Your Email</h1>
			<div class="auth-message info-message">
				If an account exists with that email, we've sent password reset instructions.
			</div>
			` + emailHTML + `
			<div class="auth-info">
				<p>Please check your inbox and follow the instructions in the email to reset your password.</p>
				<p>If you don't see the email, check your spam folder.</p>
			</div>
			<div class="auth-links">
				<p>Return to <a href="/auth/login">Login</a></p>
			</div>
		</div>
	</body>
	</html>
	`))
}

// serveSuccessPage serves a success page with optional redirect
func (al *AssetLoader) serveSuccessPage(w http.ResponseWriter, r *http.Request) {
	redirectTo := r.URL.Query().Get("redirectTo")
	message := r.URL.Query().Get("message")

	if message == "" {
		message = "Your action was completed successfully."
	}

	if redirectTo == "" {
		redirectTo = "/auth/login"
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`
	<!DOCTYPE html>
	<html>
	<head>
		<title>Success | MTGBAN</title>
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<style>
			.auth-container {
				max-width: 450px;
				margin: 2rem auto;
				padding: 2rem;
				background-color: #fff;
				border-radius: 8px;
				box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
			}
			.auth-title {
				font-size: 1.75rem;
				margin-bottom: 1rem;
				text-align: center;
			}
			.auth-message {
				padding: 1rem;
				margin-bottom: 1.5rem;
				border-radius: 4px;
			}
			.success-message {
				background-color: rgba(52, 211, 153, 0.2);
				color: #065f46;
				border-left: 4px solid #10b981;
			}
			.auth-subtitle {
				text-align: center;
				margin-bottom: 1rem;
			}
			.btn {
				display: inline-block;
				padding: 0.75rem 1.5rem;
				border-radius: 0.375rem;
				font-weight: 500;
				text-align: center;
				text-decoration: none;
				cursor: pointer;
				background-color: #2563eb;
				color: white;
				border: none;
				width: 100%;
				text-align: center;
				margin-top: 1rem;
			}
			.auth-links {
				margin-top: 1.5rem;
				text-align: center;
			}
		</style>
		<!-- Auto redirect after 3 seconds -->
		<meta http-equiv="refresh" content="3;url=` + redirectTo + `">
	</head>
	<body>
		<div class="auth-container">
			<h1 class="auth-title">Success</h1>
			<div class="auth-message success-message">
				` + message + `
			</div>
			<p class="auth-subtitle">
				Redirecting you automatically in 3 seconds...
			</p>
			<a href="` + redirectTo + `" class="btn">
				Continue Now
			</a>
		</div>
	</body>
	</html>
	`))
}

// ==============================================================================================
// ResponseWriter
// ==============================================================================================

// ResponseWriter wraps http.ResponseWriter to capture the status code
type responseWriter struct {
	http.ResponseWriter
	Status int
}

// NewResponseWriter creates a new response writer
func NewResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{w, http.StatusOK}
}

// WriteHeader overrides the original WriteHeader to capture the status code
func (rw *responseWriter) WriteHeader(code int) {
	rw.Status = code
	if rw.ResponseWriter != nil {
		rw.ResponseWriter.WriteHeader(code)
	}
}

// Write overrides the original Write to handle non-200 responses
func (rw *responseWriter) Write(b []byte) (int, error) {
	if rw.ResponseWriter == nil {
		return len(b), nil
	}
	if rw.Status == http.StatusOK {
		return rw.ResponseWriter.Write(b)
	}
	return len(b), nil
}

// responseWriter returns the underlying http.ResponseWriter
func (rw *responseWriter) responseWriter(w http.ResponseWriter) http.ResponseWriter {
	if rw.ResponseWriter == nil {
		rw.ResponseWriter = w
	}
	return rw.ResponseWriter
}

// ==============================================================================================
// ResponseHelper
// ==============================================================================================

// ResponseHelper provides API responses
type ResponseHelper struct {
	writer *responseWriter
}

// NewResponseHelper creates a new response helper
func NewResponseHelper() *ResponseHelper {
	return &ResponseHelper{
		writer: NewResponseWriter(nil),
	}
}

// SendSuccess sends a success response
func (rh *ResponseHelper) SendSuccess(w http.ResponseWriter, msg string, data interface{}) {
	rh.writer.responseWriter(w).WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: msg,
		Data:    data,
	})
}

// SendRedirect sends a success response with redirect
func (rh *ResponseHelper) SendRedirect(w http.ResponseWriter, msg string, redirectTo string, data interface{}) {
	rh.writer.responseWriter(w).WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(APIResponse{
		Success:    true,
		Message:    msg,
		RedirectTo: redirectTo,
		Data:       data,
	})
}

// SendValidationError sends a validation error response
func (rh *ResponseHelper) SendValidationError(w http.ResponseWriter, field, message string) {
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(APIResponse{
		Success: false,
		Error:   message,
		Code:    "VALIDATION_ERROR",
		Field:   field,
	})
}

// ==============================================================================================
// Middlewares
// ==============================================================================================

// MiddlewareChain manages middleware chains
type MiddlewareChain struct {
	service           *AuthService
	chains            map[string][]Middleware
	permissionManager *PermissionManager
}

// NewMiddlewareChain creates a new middleware chain manager
func NewMiddlewareChain(service *AuthService, permManager *PermissionManager) *MiddlewareChain {
	mc := &MiddlewareChain{
		service:           service,
		chains:            make(map[string][]Middleware),
		permissionManager: permManager,
	}

	// Register middleware chains
	mc.RegisterChain("public",
		mc.Recovery(),
		mc.RequestLogger(),
		mc.RateLimiter(service.Config.PublicRateLimit))

	mc.RegisterChain("base",
		mc.Recovery(),
		mc.RequestLogger())

	mc.RegisterChain("api",
		mc.Recovery(),
		mc.RequestLogger(),
		mc.RateLimiter(service.Config.APIRateLimit))

	mc.RegisterChain("auth",
		mc.Recovery(),
		mc.RequestLogger(),
		mc.Authentication())

	mc.RegisterChain("form",
		mc.Recovery(),
		mc.RequestLogger(),
		mc.MethodValidator("POST"),
		mc.RateLimiter(service.Config.LoginRateLimit))

	mc.RegisterChain("protected",
		mc.Recovery(),
		mc.RequestLogger(),
		mc.Authentication(),
		mc.CSRFProtection())

	return mc
}

// RegisterChain registers a named middleware chain
func (mc *MiddlewareChain) RegisterChain(name string, middlewares ...Middleware) {
	mc.chains[name] = middlewares
}

// GetChain returns a named middleware chain
func (mc *MiddlewareChain) GetChain(name string) []Middleware {
	return mc.chains[name]
}

// Apply applies a middleware chain to a handler
func (mc *MiddlewareChain) Apply(chainName string, handler http.Handler) http.Handler {
	chain, ok := mc.chains[chainName]
	if !ok {
		mc.service.Logger.Printf("Warning: Middleware chain '%s' not found", chainName)
		return handler
	}

	return mc.ApplyMiddlewares(handler, chain...)
}

// ApplyMiddlewares applies multiple middlewares to a handler
func (mc *MiddlewareChain) ApplyMiddlewares(handler http.Handler, middlewares ...Middleware) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}

// Recovery middleware recovers from panics
func (mc *MiddlewareChain) Recovery() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					// Log stack trace
					buf := make([]byte, 1<<16)
					n := runtime.Stack(buf, false)
					mc.service.Logger.Printf("PANIC: %v\n%s", err, buf[:n])

					// Handle the error
					mc.service.ErrorHandler.RespondWithError(w, r, mc.service.ErrorHandler.errors.ServerError, fmt.Errorf("%v", err))
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// RequestLogger logs request information
func (mc *MiddlewareChain) RequestLogger() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Create response writer that captures status code
			rw := &responseWriter{ResponseWriter: w, Status: http.StatusOK}

			// Process request
			next.ServeHTTP(rw, r)

			// Log request completion
			duration := time.Since(start)
			clientIP := getClientIP(r)
			mc.service.Logger.Printf("[%s] %s %s - %d %s - %v",
				clientIP, r.Method, r.URL.Path, rw.Status,
				http.StatusText(rw.Status), duration)
		})
	}
}

// Authentication middleware ensures the request is authenticated
func (mc *MiddlewareChain) Authentication() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip authentication for exempt paths
			if mc.permissionManager.IsExemptPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// Get session from request
			session, err := mc.service.SessionManager.GetSession(r)
			if err != nil {
				// Try session refresh first
				refreshedSession, refreshErr := mc.tryRefreshSession(w, r)
				if refreshErr == nil {
					// Store user info in context and continue
					ctx := context.WithValue(r.Context(), SessionKey("session"), refreshedSession)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}

				// Handle authentication failure
				mc.handleAuthFailure(w, r, err)
				return
			}

			// Store session in context
			ctx := context.WithValue(r.Context(), SessionKey("session"), session)

			// Check permissions if applicable
			if !mc.permissionManager.IsExemptPath(r.URL.Path) &&
				!mc.permissionManager.HasPermission(session, r.URL.Path) {
				mc.service.ErrorHandler.RespondWithError(w, r, mc.service.ErrorHandler.errors.Forbidden, nil)
				return
			}

			// Continue with the authenticated request
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// tryRefreshSession attempts to refresh an expired session
func (mc *MiddlewareChain) tryRefreshSession(w http.ResponseWriter, r *http.Request) (*UserSession, error) {
	refreshCookie, refreshErr := r.Cookie("refresh_token")
	if refreshErr != nil || refreshCookie.Value == "" {
		return nil, errors.New("no refresh token")
	}

	return mc.service.SessionManager.RefreshSession(w, r)
}

// handleAuthFailure handles authentication failures
func (mc *MiddlewareChain) handleAuthFailure(w http.ResponseWriter, r *http.Request, err error) {
	// Handle API requests
	if isAPIRequest(r) {
		mc.service.ErrorHandler.RespondWithError(w, r, mc.service.ErrorHandler.errors.MissingToken, err)
	} else {
		// Redirect to login for browser requests
		redirectURL := "/auth/login"
		if r.URL.Path != "/" {
			redirectURL = fmt.Sprintf("/auth/login?return_to=%s",
				url.QueryEscape(r.URL.Path))
		}
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
	}
}

// CSRFProtection middleware provides CSRF protection
func (mc *MiddlewareChain) CSRFProtection() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip for GET, HEAD, OPTIONS, TRACE requests
			if r.Method == "GET" || r.Method == "HEAD" ||
				r.Method == "OPTIONS" || r.Method == "TRACE" {
				next.ServeHTTP(w, r)
				return
			}

			// Get session from context (added by Authentication middleware)
			session, ok := r.Context().Value("session").(*UserSession)
			if !ok {
				mc.service.ErrorHandler.RespondWithError(w, r, mc.service.ErrorHandler.errors.MissingToken, nil)
				return
			}

			// Extract CSRF token
			csrfToken := r.Header.Get("X-CSRF-Token")
			if csrfToken == "" {
				csrfToken = r.FormValue("csrf_token")
				if csrfToken == "" {
					csrfCookie, err := r.Cookie("csrf_token")
					if err == nil {
						csrfToken = csrfCookie.Value
					}
				}
			}

			// Validate CSRF token
			if !mc.service.validateCSRFToken(csrfToken, session.UserID) {
				mc.service.Logger.Printf("CSRF validation failed for user %s", session.UserID)
				mc.service.ErrorHandler.RespondWithError(w, r, mc.service.ErrorHandler.errors.CSRFValidation, nil)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimiter provides rate limiting for requests
func (mc *MiddlewareChain) RateLimiter(requestsPerMinute int) Middleware {
	// Create limiter store with concurrent access
	limiters := &sync.Map{}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get client IP
			ip := getClientIP(r)

			// Get or create limiter for this IP
			limiterI, _ := limiters.LoadOrStore(ip,
				rate.NewLimiter(rate.Limit(float64(requestsPerMinute)/60.0), requestsPerMinute))
			limiter := limiterI.(*rate.Limiter)

			// Check rate limit
			if !limiter.Allow() {
				mc.service.Logger.Printf("Rate limit exceeded for IP: %s", ip)
				mc.service.ErrorHandler.RespondWithError(w, r, mc.service.ErrorHandler.errors.RateLimitExceeded, nil)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// MethodValidator validates HTTP methods
func (mc *MiddlewareChain) MethodValidator(method string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != method {
				http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ==============================================================================================
// AuthService
// ==============================================================================================

// AuthService handles all authentication related functionality
type AuthService struct {
	Config         *AuthConfig
	Logger         *log.Logger
	Supabase       *supabase.Client
	CSRFSecret     []byte
	BanACL         *BanACL
	StandardErrors StandardErrors

	SessionManager    *SessionManager
	ErrorHandler      *ErrorHandler
	AssetLoader       *AssetLoader
	MiddlewareChain   *MiddlewareChain
	PermissionManager *PermissionManager
	ResponseHelper    *ResponseHelper
	Writer            *responseWriter

	userCache      map[string]*UserData
	userCacheMutex sync.RWMutex
	tierCache      map[string]map[string]bool
	tierCacheMutex sync.RWMutex
}

// NewAuthService creates a new authentication service
func NewAuthService(config AuthConfig) (*AuthService, error) {
	var err error
	// Validate config
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	logger := log.New(os.Stdout, config.LogPrefix, log.LstdFlags)

	supabaseClient := supabase.CreateClient(config.SupabaseURL, config.SupabaseAnonKey)
	if supabaseClient == nil {
		return nil, errors.New("failed to create Supabase client")
	}

	var csrfSecret []byte
	if config.CSRFSecret != "" {
		var err error
		csrfSecret, err = base64.StdEncoding.DecodeString(config.CSRFSecret)
		if err != nil {
			// If CSRF secret is not valid base64, generate a new one
			logger.Printf("Warning: Invalid CSRF secret - generating a new random one")
			csrfSecret = make([]byte, 32)
			if _, err := rand.Read(csrfSecret); err != nil {
				return nil, fmt.Errorf("failed to generate CSRF secret: %w", err)
			}
			// Encode and log the new secret so it can be saved to the config if desired
			newEncodedSecret := base64.StdEncoding.EncodeToString(csrfSecret)
			logger.Printf("New CSRF secret generated. Add this to your config file: %s", newEncodedSecret)
		}
	} else {
		csrfSecret = make([]byte, 32)
		if _, err := rand.Read(csrfSecret); err != nil {
			return nil, fmt.Errorf("failed to generate CSRF secret: %w", err)
		}
	}

	// Create the service
	service := &AuthService{
		Config:         &config,
		Logger:         logger,
		Supabase:       supabaseClient,
		CSRFSecret:     csrfSecret,
		StandardErrors: NewStandardErrors(),
		BanACL: &BanACL{
			Users: make(map[string]*BanUser),
		},
		userCache: make(map[string]*UserData),
		tierCache: make(map[string]map[string]bool),
	}

	// Initialize error handler
	service.ErrorHandler = NewErrorHandler(logger, config.DebugMode)

	// Initialize asset loader
	var assetLoader *AssetLoader
	assetLoader, err = NewAssetLoader(authAssets, config.AssetsPath, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create asset loader: %w", err)
	}
	service.AssetLoader = assetLoader

	// Initialize permission manager
	service.PermissionManager = NewPermissionManager(service.Config, logger, service.BanACL)

	// Initialize middleware chain manager
	service.MiddlewareChain = NewMiddlewareChain(service, service.PermissionManager)

	// Initialize session manager
	sameSite := http.SameSiteStrictMode
	service.SessionManager = &SessionManager{
		domain:        config.CookieDomain,
		secureCookies: config.SecureCookies,
		sameSite:      sameSite,
		csrfSecret:    csrfSecret,
		logger:        logger,
		banACL:        service.BanACL,
		authService:   service,
	}

	// Initialize response helper
	service.ResponseHelper = NewResponseHelper()

	// Initialize response writer
	service.Writer = NewResponseWriter(http.ResponseWriter(nil))

	// Set the renderer in error handler
	service.ErrorHandler.SetRenderer(service.AssetLoader)

	return service, nil
}

// Initialize sets up the auth service and registers routes
func (a *AuthService) Initialize() error {
	a.Logger.Printf("Initializing authentication service")

	if err := a.GetBanACL(a.BanACL); err != nil {
		a.Logger.Printf("Warning: Failed to load BanACL: %v", err)
	}

	a.RegisterAuthRoutes(http.DefaultServeMux)

	a.Logger.Printf("Authentication service initialized successfully")
	return nil
}

// RegisterAuthRoutes registers all authentication routes
func (a *AuthService) RegisterAuthRoutes(mux *http.ServeMux) {
	a.Logger.Printf("Registering authentication routes")

	// Next.js static assets handler - this must be registered first
	mux.Handle("/_next/", http.HandlerFunc(a.AssetLoader.ServeAsset))
	a.Logger.Printf("Registered Next.js assets route: /_next/")

	// Register auth pages
	for route, page := range authPagesMap {
		var handler http.Handler

		if route == "/auth/account" {
			handler = a.MiddlewareChain.Apply("protected",
				http.HandlerFunc(a.handleAuthPageWithSession(page)))
		} else {
			handler = a.MiddlewareChain.Apply("base",
				http.HandlerFunc(a.handleAuthPage(page)))
		}

		mux.Handle(route, handler)
		a.Logger.Printf("Registered route: %s", route)
	}

	// Register API routes
	apiRoutes := []AuthRoute{
		{Path: "/next-api/auth/login", Method: "POST", Handler: a.handleLoginAPI, Middleware: "form"},
		{Path: "/next-api/auth/signup", Method: "POST", Handler: a.handleSignupAPI, Middleware: "form"},
		{Path: "/next-api/auth/logout", Method: "POST", Handler: a.handleLogoutAPI, Middleware: "api"},
		{Path: "/next-api/auth/me", Method: "GET", Handler: a.handleGetUserAPI, Middleware: "api"},
		{Path: "/next-api/auth/refresh-token", Method: "POST", Handler: a.handleRefreshTokenAPI, Middleware: "api"},
		{Path: "/next-api/auth/forgot-password", Method: "POST", Handler: a.handleForgotPasswordAPI, Middleware: "form"},
		{Path: "/next-api/auth/reset-password", Method: "POST", Handler: a.handleResetPasswordAPI, Middleware: "form"},
	}

	for _, route := range apiRoutes {
		mux.Handle(route.Path, a.MiddlewareChain.Apply(route.Middleware,
			http.HandlerFunc(route.Handler)))
		a.Logger.Printf("Registered API route: %s %s", route.Method, route.Path)
	}

	// Form submission routes
	formRoutes := []AuthRoute{
		{Path: "/auth/login-submit", Method: "POST", Handler: a.handleLoginFormSubmit, Middleware: "form"},
		{Path: "/auth/signup-submit", Method: "POST", Handler: a.handleSignupFormSubmit, Middleware: "form"},
		{Path: "/auth/forgot-password-submit", Method: "POST", Handler: a.handleForgotPasswordFormSubmit, Middleware: "form"},
		{Path: "/auth/reset-password-submit", Method: "POST", Handler: a.handleResetPasswordFormSubmit, Middleware: "form"},
		{Path: "/auth/logout", Method: "GET", Handler: a.handleLogoutForm, Middleware: "base"},
	}

	for _, route := range formRoutes {
		mux.Handle(route.Path, a.MiddlewareChain.Apply(route.Middleware,
			http.HandlerFunc(route.Handler)))
		a.Logger.Printf("Registered form route: %s %s", route.Method, route.Path)
	}

	// Catch-all handler for auth assets
	mux.Handle("/auth/", a.MiddlewareChain.Apply("base",
		http.HandlerFunc(a.AssetLoader.ServeAsset)))

	a.Logger.Printf("Registered authentication routes successfully")
}

// handleAuthPage creates a handler for auth pages
func (a *AuthService) handleAuthPage(pageName string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		a.Logger.Printf("Auth page request: %s", pageName)
		a.AssetLoader.setContentType(w, pageName)
		a.AssetLoader.ServeAsset(w, r)
	}
}

// handleAuthPageWithSession creates a handler for auth pages with session
func (a *AuthService) handleAuthPageWithSession(pageName string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// get session from context (should be set by middleware)
		session, ok := r.Context().Value("session").(*UserSession)
		if !ok {
			// this shouldn't happen since Authentication MW would redirect
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		// get additional page data
		pageData := map[string]interface{}{
			"user": map[string]interface{}{
				"id":       session.UserID,
				"email":    session.Email,
				"tier":     session.Tier,
				"metadata": session.Metadata,
			},
			"csrf_token": session.CSRFToken,
		}

		// Add specific page data based on page name
		switch pageName {
		case "account.html":
			userDetails, _ := a.getUserDetails(session.UserID)
			subscription, _ := a.getUserSubscription(session.UserID)
			pageData["userDetails"] = userDetails
			pageData["subscription"] = subscription

		case "pricing.html":
			userDetails, _ := a.getUserDetails(session.UserID)
			subscription, _ := a.getUserSubscription(session.UserID)
			productsWithPrices, _ := a.getProductsWithPrices()
			pageData["userDetails"] = userDetails
			pageData["subscription"] = subscription
			pageData["products"] = productsWithPrices
		}

		// serve page with injected data
		a.AssetLoader.ServeIndexWithData(w, pageData)
	}
}

// authenticateUser handles the core authentication logic
func (a *AuthService) authenticateUser(email, password string, rememberMe bool) (*UserSession, error) {
	// Authenticate with Supabase
	ctx := context.Background()
	authResponse, err := a.Supabase.Auth.SignIn(ctx, supabase.UserCredentials{
		Email:    email,
		Password: password,
	})

	if err != nil {
		a.Logger.Printf("Authentication failed for email %s: %v", maskEmail(email), err)
		return nil, err
	}

	// Get user info
	userInfo, err := a.Supabase.Auth.User(ctx, authResponse.AccessToken)
	if err != nil {
		a.Logger.Printf("Error retrieving user data after authentication: %v", err)
		return nil, fmt.Errorf("error retrieving user data: %w", err)
	}

	// Extract tier from metadata
	tier := extractTier(userInfo)

	// Extract role
	role := getUserRole(userInfo)

	// Generate CSRF token
	csrfToken := a.SessionManager.generateCSRFToken(userInfo.ID)

	// Generate BAN signature
	userData := &UserData{
		UserId: userInfo.ID,
		Email:  userInfo.Email,
		Tier:   tier,
	}

	// Calculate expiry duration
	expiryDuration := 24 * time.Hour // Default expiry
	if rememberMe {
		expiryDuration = 30 * 24 * time.Hour // 30 days if remember me is checked
	}

	// Create and return session
	session := &UserSession{
		AccessToken:  authResponse.AccessToken,
		RefreshToken: authResponse.RefreshToken,
		CSRFToken:    csrfToken,
		BanSignature: a.sign("", tier, userData), // Base URL will be added when cookies are set
		UserID:       userInfo.ID,
		Email:        userInfo.Email,
		Tier:         tier,
		Role:         role,
		Metadata:     userInfo.UserMetadata,
		ExpiresAt:    time.Now().Add(expiryDuration),
	}

	a.Logger.Printf("Authentication successful for user: %s (tier: %s)", maskEmail(email), tier)
	return session, nil
}

func (a *AuthService) GetSignature(r *http.Request) string {
	session, ok := r.Context().Value("session").(*UserSession)
	if !ok || session == nil {
		return ""
	}
	return session.BanSignature
}

// GetBanACL retrieves the ban access control list from Supabase
func (a *AuthService) GetBanACL(result *BanACL) error {
	var banUsers []struct {
		UserId      string                 `json:"user_id"`
		Email       string                 `json:"email"`
		Tier        string                 `json:"tier"`
		Permissions map[string]interface{} `json:"permissions"`
	}

	err := a.Supabase.DB.From("ban_acl").
		Select("user_id", "email", "tier", "permissions").
		Execute(&banUsers)
	if err != nil {
		return fmt.Errorf("failed to get ban users: %w", err)
	}

	result.Users = make(map[string]*BanUser)
	for _, user := range banUsers {
		result.Users[user.Email] = &BanUser{
			User: &UserData{
				UserId: user.UserId,
				Email:  user.Email,
				Tier:   user.Tier,
			},
			Permissions: user.Permissions,
		}
	}
	return nil
}

// getUserDetails retrieves user details from the database
func (a *AuthService) getUserDetails(userID string) (map[string]interface{}, error) {
	var userDetails map[string]interface{}

	err := a.Supabase.DB.From("users").
		Select("*").
		Eq("id", userID).
		Execute(&userDetails)

	if err != nil {
		a.Logger.Printf("Failed to get user details for %s: %v", userID, err)
		return nil, fmt.Errorf("failed to retrieve user details: %w", err)
	}

	return userDetails, nil
}

// getUserSubscription retrieves subscription information for a user
func (a *AuthService) getUserSubscription(userID string) (map[string]interface{}, error) {
	var subscriptions []map[string]interface{}

	err := a.Supabase.DB.From("subscriptions").
		Select("*, prices(*, products(*))").
		Eq("user_id", userID).
		In("status", []string{"trialing", "active"}).
		Execute(&subscriptions)

	if err != nil {
		a.Logger.Printf("Failed to get subscription info for %s: %v", userID, err)
		return nil, fmt.Errorf("failed to retrieve subscription: %w", err)
	}

	// Return the first active subscription if any exists
	if len(subscriptions) > 0 {
		return subscriptions[0], nil
	}

	return nil, nil
}

// getProductsWithPrices retrieves products with pricing information
func (a *AuthService) getProductsWithPrices() ([]map[string]interface{}, error) {
	var products []map[string]interface{}

	err := a.Supabase.DB.From("products").
		Select("*, prices(*)").
		Eq("active", "true").
		Execute(&products)

	if err != nil {
		a.Logger.Printf("Failed to get products: %v", err)
		return nil, fmt.Errorf("failed to retrieve products: %w", err)
	}

	return products, nil
}

// GetUserData gets user data
func (a *AuthService) GetUserData(userID string) (*UserData, error) {
	// Check cache first
	a.userCacheMutex.RLock()
	cachedData, found := a.userCache[userID]
	a.userCacheMutex.RUnlock()

	if found {
		return cachedData, nil
	}

	// Get from database
	var userData UserData

	userInfo, err := a.getUserDetails(userID)
	if err != nil {
		return nil, err
	}

	userData.UserId = userID
	userData.Email = userInfo["email"].(string)

	if tierVal, ok := userInfo["tier"].(string); ok {
		userData.Tier = tierVal
	} else {
		userData.Tier = "free"
	}

	// Cache the result
	a.userCacheMutex.Lock()
	a.userCache[userID] = &userData
	a.userCacheMutex.Unlock()

	return &userData, nil
}

// ClearUserCache clears the user data cache for a specific user
func (a *AuthService) ClearUserCache(userID string) {
	a.userCacheMutex.Lock()
	delete(a.userCache, userID)
	a.userCacheMutex.Unlock()
}

// ClearAllCaches clears all caches
func (a *AuthService) ClearAllCaches() {
	a.userCacheMutex.Lock()
	a.userCache = make(map[string]*UserData)
	a.userCacheMutex.Unlock()

	a.tierCacheMutex.Lock()
	a.tierCache = make(map[string]map[string]bool)
	a.tierCacheMutex.Unlock()
}

// sign signs data for permission granting
func (a *AuthService) sign(baseURL, tierTitle string, userData *UserData) string {
	// Create values for the signature
	v := url.Values{}

	// Add user data
	if userData != nil {
		v.Set("UserEmail", userData.Email)
		v.Set("UserTier", tierTitle)

		// Add permissions based on tier
		a.addTierPermissions(v, tierTitle)

		// Add BanACL permissions if available
		if a.BanACL != nil {
			a.addBanACLPermissions(v, userData.Email)
		}
	}

	// Set expiration
	expires := time.Now().Add(a.Config.SignatureTTL)
	expiresUnix := fmt.Sprintf("%d", expires.Unix())

	// Create signature data
	data := fmt.Sprintf("GET%s%s%s", expiresUnix, baseURL, v.Encode())

	// Get secret key
	key := os.Getenv("BAN_SECRET")
	if key == "" {
		key = a.Config.SupabaseSecret
	}

	// Generate signature
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(data))
	sig := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// Add signature and expiration to values
	v.Set("Expires", expiresUnix)
	v.Set("Signature", sig)

	// Encode final result
	return base64.StdEncoding.EncodeToString([]byte(v.Encode()))
}

// addTierPermissions adds permissions for a specific tier
func (a *AuthService) addTierPermissions(v url.Values, tierTitle string) {
	tierConfig, found := a.Config.ACL.Tiers[tierTitle]
	if !found {
		return
	}

	// Add permissions for each section
	for section, permissions := range tierConfig {
		v.Set(section, "true")

		// Add detailed permissions
		for key, val := range permissions {
			v.Set(key, val)
		}
	}
}

// addBanACLPermissions adds permissions from BanACL to the values
func (a *AuthService) addBanACLPermissions(v url.Values, email string) {
	if a.BanACL == nil {
		return
	}

	// Get user from BanACL
	user, exists := a.BanACL.Users[email]
	if !exists {
		return
	}

	// Add permissions from BanACL to values
	for section, permissions := range user.Permissions {
		// Each section key corresponds to a navigation section
		if a.PermissionManager.isNavSection(section) {
			// Set the section to true to enable this navigation item
			v.Set(section, "true")

			// Add detailed permissions
			if permMap, ok := permissions.(map[string]interface{}); ok {
				for key, val := range permMap {
					// Convert each permission value to string
					var strVal string
					switch v := val.(type) {
					case string:
						strVal = v
					case bool:
						strVal = strconv.FormatBool(v)
					case float64:
						strVal = strconv.FormatFloat(v, 'f', -1, 64)
					case int:
						strVal = strconv.Itoa(v)
					default:
						strVal = "true" // Default for complex objects
					}

					v.Set(key, strVal)
				}
			}
		}
	}
}

// validateCSRFToken validates a CSRF token
func (a *AuthService) validateCSRFToken(token, userID string) bool {
	// If no token provided, validation fails
	if token == "" {
		return false
	}

	expected := a.SessionManager.generateCSRFToken(userID)
	return token == expected
}

// ==============================================================================================
// API Handlers
// ==============================================================================================

// handleLoginAPI handles API login requests
func (a *AuthService) handleLoginAPI(w http.ResponseWriter, r *http.Request) {
	// Only accept POST requests
	if r.Method != http.MethodPost {
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "METHOD_NOT_ALLOWED",
			Message:    "Method not allowed",
			StatusCode: http.StatusMethodNotAllowed,
		}, nil)
		return
	}

	// Parse request
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "INVALID_REQUEST",
			Message:    "Invalid request format",
			StatusCode: http.StatusBadRequest,
		}, err)
		return
	}

	// Validate required fields
	if req.Email == "" || req.Password == "" {
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "MISSING_CREDENTIALS",
			Message:    "Email and password are required",
			StatusCode: http.StatusBadRequest,
		}, nil)
		return
	}

	// Authenticate with Supabase
	session, err := a.authenticateUser(req.Email, req.Password, req.Remember)
	if err != nil {
		a.ErrorHandler.RespondWithError(w, r, a.ErrorHandler.errors.InvalidCredentials, nil)
		return
	}

	a.SessionManager.SetSession(w, r, session)

	a.ResponseHelper.SendSuccess(w, "Login successful", map[string]interface{}{
		"user": map[string]interface{}{
			"id":             session.UserID,
			"email":          session.Email,
			"tier":           session.Tier,
			"role":           session.Role,
			"emailConfirmed": true,
			"user_metadata":  session.Metadata,
		},
		"session": map[string]interface{}{
			"expires_at": session.ExpiresAt.Unix(),
			"csrf_token": session.CSRFToken,
		},
	})
}

// handleSignupAPI handles API signup requests
func (a *AuthService) handleSignupAPI(w http.ResponseWriter, r *http.Request) {
	// Only accept POST requests
	if r.Method != http.MethodPost {
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "METHOD_NOT_ALLOWED",
			Message:    "Method not allowed",
			StatusCode: http.StatusMethodNotAllowed,
		}, nil)
		return
	}

	// Parse request
	var req SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "INVALID_REQUEST",
			Message:    "Invalid request format",
			StatusCode: http.StatusBadRequest,
		}, err)
		return
	}

	// Validate required fields
	if req.Email == "" || req.Password == "" {
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "MISSING_CREDENTIALS",
			Message:    "Email and password are required",
			StatusCode: http.StatusBadRequest,
		}, nil)
		return
	}

	// Validate password strength
	isValid, errorMsg := validatePassword(req.Password)
	if !isValid {
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "WEAK_PASSWORD",
			Message:    errorMsg,
			StatusCode: http.StatusBadRequest,
		}, nil)
		return
	}

	// Ensure user data has tier set
	if req.UserData == nil {
		req.UserData = make(map[string]interface{})
	}
	if _, ok := req.UserData["tier"]; !ok {
		req.UserData["tier"] = "free"
	}

	// Sign up with Supabase
	ctx := context.Background()
	user, err := a.Supabase.Auth.SignUp(ctx, supabase.UserCredentials{
		Email:    req.Email,
		Password: req.Password,
		Data:     req.UserData,
	})

	if err != nil {
		// Check for common errors
		errMsg := err.Error()
		if strings.Contains(strings.ToLower(errMsg), "already") ||
			strings.Contains(strings.ToLower(errMsg), "taken") {
			a.ErrorHandler.RespondWithError(w, r, a.ErrorHandler.errors.EmailTaken, err)
		} else {
			a.ErrorHandler.RespondWithError(w, r, AuthError{
				Code:       "SIGNUP_FAILED",
				Message:    "Failed to create account",
				StatusCode: http.StatusBadRequest,
				Internal:   err,
			}, err)
		}
		return
	}

	// Check if email confirmation is required
	if user.ConfirmedAt.IsZero() {
		// Email confirmation required
		a.Logger.Printf("Signup successful, email confirmation required: %s", maskEmail(req.Email))
		a.ResponseHelper.SendSuccess(w, "Account created successfully. Please check your email to verify your account.", map[string]interface{}{
			"user": map[string]interface{}{
				"id":             user.ID,
				"email":          user.Email,
				"emailConfirmed": false,
			},
			"emailConfirmationRequired": true,
		})
		return
	}

	// If email already confirmed, log in the user automatically
	a.Logger.Printf("Signup successful with pre-confirmed email: %s", maskEmail(req.Email))
	authResponse, err := a.Supabase.Auth.SignIn(ctx, supabase.UserCredentials{
		Email:    req.Email,
		Password: req.Password,
	})

	if err != nil {
		// Return partial success without session
		a.ResponseHelper.SendSuccess(w, "Account created successfully. Please check your email to verify your account.", map[string]interface{}{
			"user": map[string]interface{}{
				"id":             user.ID,
				"email":          user.Email,
				"emailConfirmed": true,
			},
		})

		return
	}

	// Extract tier from metadata
	tier := extractTier(user)

	// Get role
	role := getUserRole(user)

	// Generate CSRF token
	csrfToken := a.SessionManager.generateCSRFToken(user.ID)

	// Generate BAN signature
	userData := &UserData{
		UserId: user.ID,
		Email:  user.Email,
		Tier:   tier,
	}

	baseURL := getBaseURL(r)
	banSignature := a.sign(baseURL, tier, userData)

	// Create session
	session := &UserSession{
		AccessToken:  authResponse.AccessToken,
		RefreshToken: authResponse.RefreshToken,
		CSRFToken:    csrfToken,
		BanSignature: banSignature,
		UserID:       user.ID,
		Email:        user.Email,
		Tier:         tier,
		Role:         role,
		Metadata:     user.UserMetadata,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}

	// Set session cookies
	a.SessionManager.SetSession(w, r, session)

	// Return full success response with session
	a.ResponseHelper.SendSuccess(w, "Signup successful", map[string]interface{}{
		"user": map[string]interface{}{
			"id":             user.ID,
			"email":          user.Email,
			"emailConfirmed": true,
			"tier":           tier,
			"role":           role,
			"user_metadata":  user.UserMetadata,
		},
		"session": map[string]interface{}{
			"expires_at": session.ExpiresAt.Unix(),
			"csrf_token": csrfToken,
		},
	})
}

// handleLogoutAPI handles API logout requests
func (a *AuthService) handleLogoutAPI(w http.ResponseWriter, r *http.Request) {
	// Get token from cookie
	authCookie, err := r.Cookie("auth_token")
	if err == nil && authCookie.Value != "" {
		// Sign out from Supabase
		ctx := context.Background()
		err := a.Supabase.Auth.SignOut(ctx, authCookie.Value)
		if err != nil {
			a.Logger.Printf("Supabase logout error: %v", err)
		}
	}

	// Clear all session cookies
	a.SessionManager.ClearSession(w, r)

	// Return success response
	a.ResponseHelper.SendSuccess(w, "Logout successful", nil)
}

// handleGetUserAPI handles API requests to get current user information
func (a *AuthService) handleGetUserAPI(w http.ResponseWriter, r *http.Request) {
	// Get session from context (added by Authentication middleware)
	session, ok := r.Context().Value("session").(*UserSession)
	if !ok {
		a.ErrorHandler.RespondWithError(w, r, a.ErrorHandler.errors.MissingToken, nil)
		return
	}

	// Try to get user details
	userDetails, _ := a.getUserDetails(session.UserID)

	// Try to get subscription info
	subscription, _ := a.getUserSubscription(session.UserID)

	// Return user data
	a.ResponseHelper.SendSuccess(w, "User data retrieved", map[string]interface{}{
		"user": map[string]interface{}{
			"id":            session.UserID,
			"email":         session.Email,
			"tier":          session.Tier,
			"role":          session.Role,
			"user_metadata": session.Metadata,
		},
		"userDetails":  userDetails,
		"subscription": subscription,
		"csrf_token":   session.CSRFToken,
	})
}

// handleRefreshTokenAPI handles API requests to refresh authentication tokens
func (a *AuthService) handleRefreshTokenAPI(w http.ResponseWriter, r *http.Request) {
	// Attempt to refresh the session
	session, err := a.SessionManager.RefreshSession(w, r)
	if err != nil {
		a.ErrorHandler.RespondWithError(w, r, a.ErrorHandler.errors.SessionExpired, err)
		return
	}

	// Return success with updated session info
	a.ResponseHelper.SendSuccess(w, "Token refreshed successfully", map[string]interface{}{
		"user": map[string]interface{}{
			"id":    session.UserID,
			"email": session.Email,
			"tier":  session.Tier,
			"role":  session.Role,
		},
		"session": map[string]interface{}{
			"expires_at": session.ExpiresAt.Unix(),
			"csrf_token": session.CSRFToken,
		},
	})
}

// handleForgotPasswordAPI handles API password reset requests
func (a *AuthService) handleForgotPasswordAPI(w http.ResponseWriter, r *http.Request) {
	// Only accept POST requests
	if r.Method != http.MethodPost {
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "METHOD_NOT_ALLOWED",
			Message:    "Method not allowed",
			StatusCode: http.StatusMethodNotAllowed,
		}, nil)
		return
	}

	// Parse request
	var req PasswordResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "INVALID_REQUEST",
			Message:    "Invalid request format",
			StatusCode: http.StatusBadRequest,
		}, err)
		return
	}

	// Validate email
	if req.Email == "" {
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "MISSING_EMAIL",
			Message:    "Email is required",
			StatusCode: http.StatusBadRequest,
		}, nil)
		return
	}

	// Request password reset from Supabase
	ctx := context.Background()
	err := a.Supabase.Auth.ResetPasswordForEmail(ctx, req.Email, "/auth/reset-password")

	// For security reasons, don't reveal if the email exists
	if err != nil {
		a.Logger.Printf("Password reset request failed: %v", err)
	} else {
		a.Logger.Printf("Password reset request sent to: %s", maskEmail(req.Email))
	}

	// Return success response regardless to prevent email enumeration
	a.ResponseHelper.SendSuccess(w, "If an account exists with that email, we've sent password reset instructions.", nil)
}

// handleResetPasswordAPI handles API password reset completions
func (a *AuthService) handleResetPasswordAPI(w http.ResponseWriter, r *http.Request) {
	// Only accept POST requests
	if r.Method != http.MethodPost {
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "METHOD_NOT_ALLOWED",
			Message:    "Method not allowed",
			StatusCode: http.StatusMethodNotAllowed,
		}, nil)
		return
	}

	// Parse request
	var req PasswordUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "INVALID_REQUEST",
			Message:    "Invalid request format",
			StatusCode: http.StatusBadRequest,
		}, err)
		return
	}

	// Validate required fields
	if req.Password == "" || req.Token == "" {
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "MISSING_FIELDS",
			Message:    "Password and token are required",
			StatusCode: http.StatusBadRequest,
		}, nil)
		return
	}

	// Validate password strength
	isValid, errorMsg := validatePassword(req.Password)
	if !isValid {
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "WEAK_PASSWORD",
			Message:    errorMsg,
			StatusCode: http.StatusBadRequest,
		}, nil)
		return
	}

	// Update user's password with token
	ctx := context.Background()
	updateData := map[string]interface{}{
		"password": req.Password,
	}

	user, err := a.Supabase.Auth.UpdateUser(ctx, req.Token, updateData)
	if err != nil {
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "RESET_FAILED",
			Message:    "Failed to reset password",
			StatusCode: http.StatusInternalServerError,
		}, err)
		return
	}

	// Log the successful password reset
	a.Logger.Printf("Password reset successful for user ID: %s", maskID(user.ID))

	// Return success response with redirect to login page
	a.ResponseHelper.SendRedirect(w, "Your password has been reset successfully. You can now log in with your new password.", "/auth/login", nil)
}

// ==============================================================================================
// Form Handlers
// ==============================================================================================

// handleLoginFormSubmit handles form-based login requests
func (a *AuthService) handleLoginFormSubmit(w http.ResponseWriter, r *http.Request) {
	// Parse form
	if err := r.ParseForm(); err != nil {
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "INVALID_FORM",
			Message:    "Error parsing form data",
			StatusCode: http.StatusBadRequest,
			Internal:   err,
		}, NewStandardErrors().InvalidForm)
		return
	}

	// Extract email and password
	email := r.FormValue("email")
	password := r.FormValue("password")
	rememberMe := r.FormValue("remember") == "on"
	returnTo := r.FormValue("return_to")

	if email == "" || password == "" {
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "MISSING_CREDENTIALS",
			Message:    "Email and password are required",
			StatusCode: http.StatusBadRequest,
		}, NewStandardErrors().InvalidCredentials)
		return
	}

	// Authenticate with Supabase
	session, err := a.authenticateUser(email, password, rememberMe)
	if err != nil {
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "INVALID_CREDENTIALS",
			Message:    "Invalid email or password",
			StatusCode: http.StatusUnauthorized,
		}, NewStandardErrors().InvalidCredentials)
		return
	}

	// Set session cookies
	a.SessionManager.SetSession(w, r, session)

	// Redirect to return path or default
	if returnTo == "" {
		returnTo = "/"
	}

	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}

// handleSignupFormSubmit handles form-based signup requests
func (a *AuthService) handleSignupFormSubmit(w http.ResponseWriter, r *http.Request) {
	// Parse form
	if err := r.ParseForm(); err != nil {
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "INVALID_FORM",
			Message:    "Error parsing form data",
			StatusCode: http.StatusBadRequest,
		}, NewStandardErrors().InvalidForm)
		return
	}

	// Extract form values
	email := r.FormValue("email")
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm-password")

	// Basic validation
	if email == "" || password == "" {
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "MISSING_CREDENTIALS",
			Message:    "Email and password are required",
			StatusCode: http.StatusBadRequest,
		}, NewStandardErrors().InvalidCredentials)
		return
	}

	if password != confirmPassword {
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "PASSWORD_MISMATCH",
			Message:    "Passwords do not match",
			StatusCode: http.StatusBadRequest,
		}, NewStandardErrors().InvalidCredentials)
		return
	}

	// Validate password strength
	isValid, errorMsg := validatePassword(password)
	if !isValid {
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "WEAK_PASSWORD",
			Message:    errorMsg,
			StatusCode: http.StatusBadRequest,
		}, NewStandardErrors().WeakPassword)
		return
	}

	// Setup user metadata
	userData := map[string]interface{}{
		"tier": "free", // Default tier
	}

	// Create user in Supabase
	ctx := context.Background()
	user, err := a.Supabase.Auth.SignUp(ctx, supabase.UserCredentials{
		Email:    email,
		Password: password,
		Data:     userData,
	})

	if err != nil {
		// Check for email already taken
		if strings.Contains(strings.ToLower(err.Error()), "already") {
			a.ErrorHandler.RespondWithError(w, r, AuthError{
				Code:       "EMAIL_TAKEN",
				Message:    "Email is already taken",
				StatusCode: http.StatusBadRequest,
			}, NewStandardErrors().EmailTaken)
		} else {
			a.ErrorHandler.RespondWithError(w, r, AuthError{
				Code:       "SIGNUP_FAILED",
				Message:    "Failed to create account",
				StatusCode: http.StatusInternalServerError,
				Internal:   err,
			}, NewStandardErrors().ServerError)
		}
		return
	}

	// Check if email confirmation is required
	if user.ConfirmedAt.IsZero() {
		// Redirect to confirmation page
		confirmURL := fmt.Sprintf("/auth/confirmation?email=%s", url.QueryEscape(email))
		http.Redirect(w, r, confirmURL, http.StatusSeeOther)
		return
	}

	// If email already confirmed, redirect to success page
	successURL := "/auth/success?redirectTo=/auth/login&message=Account created successfully. You can now log in."
	http.Redirect(w, r, successURL, http.StatusSeeOther)
}

// handleLogoutForm handles form-based logout requests
func (a *AuthService) handleLogoutForm(w http.ResponseWriter, r *http.Request) {
	// Get token from cookie and sign out from Supabase
	authCookie, err := r.Cookie("auth_token")
	if err == nil && authCookie.Value != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := a.Supabase.Auth.SignOut(ctx, authCookie.Value)
		if err != nil {
			a.Logger.Printf("Supabase logout error: %v", err)
		}
	}

	// Clear all session cookies
	a.SessionManager.ClearSession(w, r)

	// Serve a cleanup page with JavaScript to clear client-side state
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")

	// Construct home URL
	baseURL := getBaseURL(r)
	homeURL := baseURL
	if !strings.HasSuffix(homeURL, "/") {
		homeURL += "/"
	}

	logoutHTML := `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Logging Out</title>
        <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
        <script>
            // Clear all client-side state
            function cleanupAndRedirect() {
                // Clear localStorage and sessionStorage
                try {
                    localStorage.clear();
                    sessionStorage.clear();
                } catch (e) {
                    console.error("Storage clear error:", e);
                }

                // Clear all cookies by setting expired date
                document.cookie.split(";").forEach(function(c) {
                    document.cookie = c.trim().split("=")[0] + "=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/";
                    document.cookie = c.trim().split("=")[0] + "=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/;domain=" + window.location.hostname;
                });

                // Redirect to home with cache buster
                window.location.href = "` + homeURL + `?nocache=" + new Date().getTime();
            }

            // Run immediately
            cleanupAndRedirect();
        </script>
    </head>
    <body>
        <h1>Logging you out...</h1>
        <p>Please wait while we complete the logout process.</p>
        <p>If you're not redirected, <a href="` + homeURL + `">click here</a>.</p>
    </body>
    </html>
    `
	w.Write([]byte(logoutHTML))
}

// handleForgotPasswordFormSubmit handles form-based password reset requests
func (a *AuthService) handleForgotPasswordFormSubmit(w http.ResponseWriter, r *http.Request) {
	// Parse form
	if err := r.ParseForm(); err != nil {
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "INVALID_FORM",
			Message:    "Error parsing form data",
			StatusCode: http.StatusBadRequest,
		}, NewStandardErrors().InvalidForm)
		return
	}

	// Extract email
	email := r.FormValue("email")
	if email == "" {
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "MISSING_EMAIL",
			Message:    "Email is required",
			StatusCode: http.StatusBadRequest,
		}, NewStandardErrors().InvalidCredentials)
		return
	}

	// Request password reset from Supabase
	ctx := context.Background()
	err := a.Supabase.Auth.ResetPasswordForEmail(ctx, email, "/auth/reset-password")

	// For security reasons, don't reveal if the email exists
	if err != nil {
		a.Logger.Printf("Password reset request failed: %v", err)
	} else {
		a.Logger.Printf("Password reset request sent to: %s", maskEmail(email))
	}

	// Redirect to reset password sent page
	resetSentURL := fmt.Sprintf("/auth/reset-password-sent?email=%s", url.QueryEscape(email))
	http.Redirect(w, r, resetSentURL, http.StatusSeeOther)
}

// handleResetPasswordFormSubmit handles form-based password reset completions
func (a *AuthService) handleResetPasswordFormSubmit(w http.ResponseWriter, r *http.Request) {
	// Parse form data
	if err := r.ParseForm(); err != nil {
		a.Logger.Printf("Error parsing form data: %v", err)
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "INVALID_FORM",
			Message:    "Error parsing form data",
			StatusCode: http.StatusBadRequest,
			Internal:   err,
		}, NewStandardErrors().InvalidForm)
		return
	}

	// Get form values
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm-password")
	token := r.FormValue("token") // This is the reset token from the URL

	// Validate inputs
	if password == "" || token == "" {
		a.Logger.Printf("Password reset with empty fields")
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "MISSING_FIELDS",
			Message:    "Password and token are required",
			StatusCode: http.StatusBadRequest,
		}, NewStandardErrors().InvalidForm)
		return
	}

	if password != confirmPassword {
		a.Logger.Printf("Password reset passwords don't match")
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "PASSWORD_MISMATCH",
			Message:    "Passwords do not match",
			StatusCode: http.StatusBadRequest,
		}, NewStandardErrors().InvalidForm)
		return
	}

	// Validate password strength
	isValid, errorMsg := validatePassword(password)
	if !isValid {
		a.Logger.Printf("Password validation failed: %s", errorMsg)
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "WEAK_PASSWORD",
			Message:    errorMsg,
			StatusCode: http.StatusBadRequest,
		}, NewStandardErrors().InvalidForm)
		return
	}

	// Update user's password with token
	ctx := context.Background()
	updateData := map[string]interface{}{
		"password": password,
	}

	user, err := a.Supabase.Auth.UpdateUser(ctx, token, updateData)
	if err != nil {
		a.Logger.Printf("Password reset failed: %v", err)
		a.ErrorHandler.RespondWithError(w, r, AuthError{
			Code:       "RESET_FAILED",
			Message:    "Failed to reset password",
			StatusCode: http.StatusInternalServerError,
			Internal:   err,
		}, NewStandardErrors().InvalidForm)
		return
	}

	// Log the successful password reset
	a.Logger.Printf("Password reset successful for user ID: %s", maskID(user.ID))

	// Redirect to success page
	successURL := fmt.Sprintf("/auth/success?redirectTo=%s&message=%s",
		url.QueryEscape("/auth/login"),
		url.QueryEscape("Your password has been reset successfully. You can now log in with your new password."))

	http.Redirect(w, r, successURL, http.StatusSeeOther)
}

// ==============================================================================================
// Utility Functions
// ==============================================================================================

// extractTier extracts the tier from user metadata
func extractTier(userInfo *supabase.User) string {
	if userInfo == nil || userInfo.UserMetadata == nil {
		return "free"
	}

	tierVal, ok := userInfo.UserMetadata["tier"].(string)
	if !ok || tierVal == "" {
		return "free"
	}

	return tierVal
}

// getUserRole extracts the role from user metadata or defaults to "user"
func getUserRole(userInfo *supabase.User) string {
	if userInfo == nil || userInfo.UserMetadata == nil {
		return "user"
	}

	roleVal, ok := userInfo.UserMetadata["role"].(string)
	if !ok || roleVal == "" {
		return "user"
	}

	return roleVal
}

// determineReturnPath determines the appropriate return path for a redirect
func determineReturnPath(r *http.Request, err AuthError) string {
	// Check for return_to parameter
	returnTo := r.FormValue("return_to")
	if returnTo != "" {
		return returnTo
	}

	// Default paths based on error context
	if strings.Contains(r.URL.Path, "login") || err.Code == "INVALID_CREDENTIALS" {
		return "/auth/login"
	} else if strings.Contains(r.URL.Path, "signup") || err.Code == "EMAIL_TAKEN" {
		return "/auth/signup"
	} else if strings.Contains(r.URL.Path, "reset-password") || err.Code == "RESET_FAILED" {
		return "/auth/reset-password"
	} else if strings.Contains(r.URL.Path, "forgot-password") {
		return "/auth/forgot-password"
	}

	// Default fallback
	return "/auth/login"
}

// isFormSubmission determines if a request is a form submission
func isFormSubmission(r *http.Request) bool {
	// Check method
	if r.Method != "POST" {
		return false
	}

	// Check content type
	contentType := r.Header.Get("Content-Type")
	return strings.Contains(contentType, "application/x-www-form-urlencoded") ||
		strings.Contains(contentType, "multipart/form-data")
}

// isAPIRequest determines if a request is an API request
func isAPIRequest(r *http.Request) bool {
	// Check path first (faster check)
	if strings.Contains(r.URL.Path, "/api/") || strings.Contains(r.URL.Path, "/next-api/") {
		return true
	}

	// Check Accept header
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "application/json")
}

// getBaseURL gets the base URL for the request
func getBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}

	host := r.Host
	if host == "" {
		host = DefaultHost
	}

	return fmt.Sprintf("%s://%s", scheme, host)
}

// determinePathSection maps a path to a section
func determinePathSection(path string, navSections []string) string {
	// Map common path prefixes to sections
	pathSectionMap := map[string]string{
		"/search":           "Search",
		"/sets":             "Search",
		"/sealed":           "Search",
		"/newspaper":        "Newspaper",
		"/sleepers":         "Sleepers",
		"/upload":           "Upload",
		"/global":           "Global",
		"/arbit":            "Arbit",
		"/reverse":          "Reverse",
		"/admin":            "Admin",
		"/api/mtgban/":      "API",
		"/api/mtgjson/":     "API",
		"/api/tcgplayer/":   "API",
		"/api/search/":      "Search",
		"/api/cardkingdom/": "API",
		"/api/suggest":      "API",
	}

	// Check exact matches
	if section, exists := pathSectionMap[path]; exists {
		return section
	}

	// Check prefixes
	for prefix, section := range pathSectionMap {
		if strings.HasPrefix(path, prefix) {
			return section
		}
	}

	// If no mapping found, try to match with nav sections
	for _, section := range navSections {
		if strings.Contains(path, strings.ToLower(section)) {
			return section
		}
	}

	return ""
}

// getSubPathPermission extracts the specific permission needed for a path
func getSubPathPermission(path string) string {
	// Extract sub-features from path
	if strings.Contains(path, "buylist") {
		return "buylist"
	} else if strings.Contains(path, "optimizer") {
		return "optimizer"
	} else if strings.Contains(path, "download") || strings.Contains(path, "csv") {
		return "download"
	} else if strings.Contains(path, "changestore") {
		return "changestore"
	} else if strings.Contains(path, "sealed") {
		return "sealed"
	}
	return ""
}

// GetParamFromSig extracts a parameter from the BAN signature
func GetParamFromSig(sig, paramName string) string {
	if sig == "" {
		return ""
	}

	// Decode base64 signature
	decodedBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return ""
	}

	// Parse as URL query parameters
	values, err := url.ParseQuery(string(decodedBytes))
	if err != nil {
		return ""
	}

	// Return the requested parameter
	return values.Get(paramName)
}

// validatePassword checks password strength
func validatePassword(password string) (bool, string) {
	if len(password) < 8 {
		return false, "Password must be at least 8 characters long"
	}

	var (
		hasLetter bool
		hasDigit  bool
	)

	for _, c := range password {
		switch {
		case unicode.IsLetter(c):
			hasLetter = true
		case unicode.IsDigit(c):
			hasDigit = true
		}
	}

	if !hasLetter {
		return false, "Password must contain at least one letter"
	}

	if !hasDigit {
		return false, "Password must contain at least one number"
	}

	return true, ""
}

func SignHMACSHA256Base64(key, data []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	signature := mac.Sum(nil)
	return base64.StdEncoding.EncodeToString(signature)
}
