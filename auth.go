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

// Error messages used throughout the application
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
)

// APIResponse represents a standardized API response
type APIResponse struct {
	Success    bool        `json:"success"`
	Message    string      `json:"message,omitempty"`
	Error      string      `json:"error,omitempty"`
	Code       string      `json:"code,omitempty"`
	Data       interface{} `json:"data,omitempty"`
	RedirectTo string      `json:"redirectTo,omitempty"`
}

// AuthService handles all authentication related functionality
type AuthService struct {
	Logger         *log.Logger
	Supabase       *supabase.Client
	SupabaseAdmin  *supabase.Client
	SupabaseURL    string
	SupabaseKey    string
	SupabaseSecret string
	DebugMode      bool
	BaseAuthURL    string
	CSRFSecret     []byte
	BanACL         *BanACL
	AuthConfig     AuthConfig

	// Rate limiters
	LoginLimiter    *rate.Limiter
	SignupLimiter   *rate.Limiter
	ResetPwdLimiter *rate.Limiter
	IPLimiters      sync.Map // map[string]*rate.Limiter
}

// AuthConfig holds the configuration for the authentication service
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
}

// UserData holds user data for MTGBAN users
type UserData struct {
	UserId string `json:"user_id"`
	Email  string `json:"email"`
	Tier   string `json:"tier"`
}

type BanUser struct {
	User        *UserData              `json:"user"`
	Permissions map[string]interface{} `json:"permissions"`
}

type BanACL struct {
	Users map[string]*BanUser
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
	Middlewares MiddlewareChain
	Description string
}

// MiddlewareChain is a chain of middleware functions
type MiddlewareChain []func(http.HandlerFunc) http.HandlerFunc

// Then applies the middleware chain to a handler
func (c MiddlewareChain) Then(h http.HandlerFunc) http.HandlerFunc {
	for i := len(c) - 1; i >= 0; i-- {
		h = c[i](h)
	}
	return h
}

// Append adds more middleware to the chain
func (c MiddlewareChain) Append(m ...func(http.HandlerFunc) http.HandlerFunc) MiddlewareChain {
	return append(c, m...)
}

// ============================================================================================
// AuthService Initialization
// ============================================================================================

// DefaultAuthConfig returns the default authentication configuration
func DefaultAuthConfig() AuthConfig {
	return AuthConfig{
		LogPrefix: " ",
		ExemptRoutes: []string{
			"/",
			"/home",
			"/auth",
		},
		ExemptPrefixes: []string{
			"/auth/",
			"/next-api/auth/",
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

// ValidateConfig validates the auth configuration
func (c AuthConfig) Validate() error {
	if c.SupabaseURL == "" {
		return errors.New("SupabaseURL is required")
	}

	if c.SupabaseAnonKey == "" {
		return errors.New("SupabaseAnonKey is required")
	}

	return nil
}

// NewAuthService creates a new authentication service
func NewAuthService(config AuthConfig) (*AuthService, error) {
	// Validate config
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	logger := log.New(os.Stdout, config.LogPrefix, log.LstdFlags)

	supabaseClient := supabase.CreateClient(config.SupabaseURL, config.SupabaseAnonKey)
	if supabaseClient == nil {
		return nil, errors.New("failed to create Supabase client")
	}

	supabaseAdminClient := supabase.CreateClient(config.SupabaseURL, config.SupabaseRoleKey)
	if supabaseAdminClient == nil {
		return nil, errors.New("failed to create Supabase admin client")
	}

	// Generate CSRF secret
	csrfSecret := make([]byte, 32)
	if _, err := rand.Read(csrfSecret); err != nil {
		return nil, fmt.Errorf("failed to generate CSRF secret: %w", err)
	}

	// Create the service
	service := &AuthService{
		Logger:          logger,
		Supabase:        supabaseClient,
		SupabaseAdmin:   supabaseAdminClient,
		SupabaseURL:     config.SupabaseURL,
		SupabaseKey:     config.SupabaseAnonKey,
		SupabaseSecret:  config.SupabaseSecret,
		DebugMode:       config.DebugMode,
		BaseAuthURL:     config.SupabaseURL + "/auth/v1",
		CSRFSecret:      csrfSecret,
		AuthConfig:      config,
		BanACL:          nil,        // load ACL after initialization
		IPLimiters:      sync.Map{}, // Initialize the map
		LoginLimiter:    rate.NewLimiter(rate.Every(1*time.Second), 5),
		SignupLimiter:   rate.NewLimiter(rate.Every(5*time.Second), 3),
		ResetPwdLimiter: rate.NewLimiter(rate.Every(30*time.Second), 3),
	}

	return service, nil
}

// Initialize sets up the auth service and registers routes
func (a *AuthService) Initialize() error {
	a.Logger.Printf("Initializing authentication service")
	a.Logger.Printf("Supabase URL: %s", a.SupabaseURL)

	a.registerRoutes()

	a.Logger.Printf("Authentication service initialized successfully")
	return nil
}

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

func (a *AuthService) getAccessByEmail(email string) (map[string]interface{}, error) {
	if a.BanACL == nil {
		return nil, errors.New("BanACL is not initialized")
	}

	user, exists := a.BanACL.Users[email]
	if !exists {
		return nil, errors.New("user not found")
	}

	return user.Permissions, nil
}

// registerRoutes registers authentication routes
func (a *AuthService) registerRoutes() {
	a.Logger.Printf("Registering authentication routes")

	// Next.js static assets handler - this must be registered first
	http.HandleFunc("/_next/", a.handleNextJsAssets)

	// Create middleware chains
	chains := a.createMiddlewareChains()

	// Define routes with their middlewares
	routes := []AuthRoute{
		// Base routes
		{
			Path:        "/auth/login",
			Method:      "GET",
			Handler:     a.handleAuthLogin,
			Middlewares: chains["base"],
			Description: "Login page",
		},
		{
			Path:        "/auth/signup",
			Method:      "GET",
			Handler:     a.handleAuthSignup,
			Middlewares: chains["base"],
			Description: "Signup page",
		},
		// API Routes
		{
			Path:        "/next-api/auth/login",
			Method:      "POST",
			Handler:     a.handleAuthLogin,
			Middlewares: chains["apiAuth"],
			Description: "API login endpoint",
		},
		{
			Path:        "/next-api/auth/signup",
			Method:      "POST",
			Handler:     a.handleAuthSignup,
			Middlewares: chains["apiAuth"],
			Description: "API signup endpoint",
		},
		{
			Path:        "/next-api/auth/logout",
			Method:      "POST",
			Handler:     a.handleAuthLogout,
			Middlewares: chains["api"],
			Description: "API logout endpoint",
		},
		{
			Path:        "/next-api/auth/me",
			Method:      "GET",
			Handler:     a.handleAuthGetUser,
			Middlewares: chains["api"],
			Description: "API get current user endpoint",
		},
		{
			Path:        "/next-api/auth/refresh-token",
			Method:      "POST",
			Handler:     a.handleAuthRefreshToken,
			Middlewares: chains["api"],
			Description: "API refresh token endpoint",
		},
		{
			Path:        "/next-api/auth/forgot-password",
			Method:      "POST",
			Handler:     a.handleAuthForgotPassword,
			Middlewares: chains["apiAuth"],
			Description: "API forgot password endpoint",
		},
		{
			Path:        "/next-api/auth/reset-password",
			Method:      "POST",
			Handler:     a.handleAuthResetPassword,
			Middlewares: chains["apiAuth"],
			Description: "API reset password endpoint",
		},

		// Form submission routes
		{
			Path:        "/auth/login-submit",
			Method:      "POST",
			Handler:     a.handleLoginFormSubmit,
			Middlewares: chains["form"],
			Description: "Login form submission",
		},
		{
			Path:        "/auth/signup-submit",
			Method:      "POST",
			Handler:     a.handleSignupFormSubmit,
			Middlewares: chains["form"],
			Description: "Signup form submission",
		},
		{
			Path:        "/auth/forgot-password-submit",
			Method:      "POST",
			Handler:     a.handleForgotPasswordFormSubmit,
			Middlewares: chains["form"],
			Description: "Forgot password form submission",
		},
		{
			Path:        "/auth/reset-password-submit",
			Method:      "POST",
			Handler:     a.handleResetPasswordFormSubmit,
			Middlewares: chains["form"],
			Description: "Reset password form submission",
		},
		{
			Path:        "/auth/logout",
			Method:      "GET",
			Handler:     a.handleLogoutForm,
			Middlewares: chains["base"],
			Description: "Logout form submission",
		},
	}

	// Register routes
	for _, route := range routes {
		handler := route.Handler

		// Apply middlewares
		handler = route.Middlewares.Then(handler)

		// Register with method checking
		http.HandleFunc(route.Path, func(w http.ResponseWriter, r *http.Request) {
			if route.Method != "" && r.Method != route.Method {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			handler(w, r)
		})

		a.Logger.Printf("Registered route: %s %s", route.Method, route.Path)
	}

	// Set up path normalizer for /auth/auth/ redirects
	pathNormalizerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasPrefix(path, "/auth/auth/") {
			newPath := "/auth/" + strings.TrimPrefix(path, "/auth/auth/")
			query := r.URL.RawQuery
			if query != "" {
				newPath += "?" + query
			}
			a.Logger.Printf("Redirecting from duplicate auth path: %s → %s", path, newPath)
			http.Redirect(w, r, newPath, http.StatusMovedPermanently)
			return
		}

		// Continue to next handler
		http.NotFound(w, r)
	})

	// Handle path normalization before serving static files
	http.Handle("/auth/auth/", pathNormalizerHandler)

	// Serve static files and React components from embedded Next.js app
	authFS, err := fs.Sub(authAssets, "nextAuth/out")
	if err != nil {
		a.Logger.Printf("Failed to load embedded auth assets: %v", err)
		return
	}

	http.Handle("/auth/", http.StripPrefix("/auth", a.createStaticFileServer(authFS)))

	a.Logger.Printf("Authentication routes registered successfully")
}

// ============================================================================================
// Middleware Functions
// ============================================================================================

// createMiddlewareChains creates standard middleware chains
func (a *AuthService) createMiddlewareChains() map[string]MiddlewareChain {
	return map[string]MiddlewareChain{
		"base": {
			a.Recover,        // Always first to catch panics
			a.RequestLogger,  // Log all requests
			a.PathNormalizer, // Normalize paths
		},
		"api": {
			a.Recover,       // Always first to catch panics
			a.RequestLogger, // Log all requests
		},
		"apiAuth": {
			a.Recover,
			a.RequestLogger,
			a.RateLimitAuth,
		},
		"form": {
			a.Recover,
			a.RequestLogger,
			a.PathNormalizer,
			a.MethodValidator("POST"),
		},
		"authRequired": {
			a.Recover,
			a.RequestLogger,
			a.PathNormalizer,
			a.AuthRequired,   // Check for authentication
			a.CSRFProtection, // CSRF protection for authenticated requests
		},
	}
}

// Recover middleware to recover from panics
func (a *AuthService) Recover(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// Log stack trace
				buf := make([]byte, 1<<16)
				n := runtime.Stack(buf, false)
				a.logWithContext(r, "PANIC: %v\n%s", err, buf[:n])

				// Create server error
				serverErr := ErrServerError
				serverErr.Internal = fmt.Errorf("%v", err)

				// Handle the error
				a.handleAPIError(w, r, serverErr)
			}
		}()
		next(w, r)
	}
}

// RequestLogger logs request information
func (a *AuthService) RequestLogger(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		a.logWithContext(r, "Request started")

		// Create a response wrapper to capture status code
		rw := newResponseWriter(w)
		next(rw, r)

		duration := time.Since(start)
		a.logWithContext(r, "Request completed: status=%d duration=%v",
			rw.status, duration)
	}
}

// PathNormalizer normalizes request paths
func (a *AuthService) PathNormalizer(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		originalPath := r.URL.Path
		normalizedPath := a.normalizeAuthPath(originalPath)

		if normalizedPath != originalPath {
			query := r.URL.RawQuery
			if query != "" {
				normalizedPath += "?" + query
			}
			a.logWithContext(r, "Redirecting to normalized path: %s → %s", originalPath, normalizedPath)
			http.Redirect(w, r, normalizedPath, http.StatusMovedPermanently)
			return
		}

		next(w, r)
	}
}

// MethodValidator validates the request method
func (a *AuthService) MethodValidator(method string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != method {
				a.logWithContext(r, "Method not allowed: %s", r.Method)
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			next(w, r)
		}
	}
}

// RateLimitAuth provides rate limiting for authentication endpoints
func (a *AuthService) RateLimitAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)

		// Get or create limiter for this IP
		limiterI, _ := a.IPLimiters.LoadOrStore(ip, rate.NewLimiter(rate.Every(1*time.Second), 5))
		limiter := limiterI.(*rate.Limiter)

		if !limiter.Allow() {
			a.logWithContext(r, "Rate limit exceeded for IP: %s", ip)
			a.handleAPIError(w, r, ErrRateLimitExceeded)
			return
		}

		next(w, r)
	}
}

// AuthRequired ensures the request is authenticated
func (a *AuthService) AuthRequired(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if the path is exempt from authentication
		if a.isExemptPath(r.URL.Path) {
			next(w, r)
			return
		}

		// Check if user is authenticated
		authCookie, err := r.Cookie("auth_token")
		if err != nil {
			a.logWithContext(r, "No auth_token cookie found")

			// Try to refresh token if refresh token exists
			_, refreshErr := r.Cookie("refresh_token")
			if refreshErr == nil {
				a.logWithContext(r, "Found refresh_token, attempting refresh")
				a.handleAuthRefreshToken(w, r)
				return
			}

			// Redirect to login
			redirectURL := "/auth/login"
			if r.URL.Path != "/" {
				redirectURL = fmt.Sprintf("/auth/login?return_to=%s", url.QueryEscape(r.URL.Path))
			}

			a.logWithContext(r, "Redirecting to login: %s", redirectURL)
			http.Redirect(w, r, redirectURL, http.StatusSeeOther)
			return
		}

		// Validate the token
		ctx := context.Background()
		userInfo, err := a.Supabase.Auth.User(ctx, authCookie.Value)
		if err != nil {
			a.logWithContext(r, "Invalid auth token: %v", err)

			// Clear cookies and redirect to login
			a.clearAuthCookies(w, r)
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		// Store user info in request context
		ctx = context.WithValue(r.Context(), "user", userInfo)
		next(w, r.WithContext(ctx))
	}
}

// CSRFProtection provides CSRF protection for authenticated requests
func (a *AuthService) CSRFProtection(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip for GET, HEAD, OPTIONS, TRACE
		if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" || r.Method == "TRACE" {
			next(w, r)
			return
		}

		// Get user from context
		userInfo, ok := r.Context().Value("user").(*supabase.User)
		if !ok {
			a.logWithContext(r, "No user in context for CSRF check")
			a.handleAPIError(w, r, ErrMissingToken)
			return
		}

		// Check CSRF token
		csrfToken := r.Header.Get("X-CSRF-Token")
		if csrfToken == "" {
			// Try to get from form or cookie
			csrfToken = r.FormValue("csrf_token")
			if csrfToken == "" {
				csrfCookie, err := r.Cookie("csrf_token")
				if err == nil {
					csrfToken = csrfCookie.Value
				}
			}
		}

		if !a.validateCSRFToken(csrfToken, userInfo.ID) {
			a.logWithContext(r, "CSRF validation failed for user %s", userInfo.ID)
			a.handleAPIError(w, r, ErrCSRFValidation)
			return
		}

		next(w, r)
	}
}

// AuthWrapper is a middleware that handles authentication based on existing middleware
func (a *AuthService) AuthWrapper(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.logWithContext(r, "[Go-Auth] %s %s", r.Method, r.URL.Path)
		path := r.URL.Path

		// First check if path is exempt
		if a.isExemptPath(path) {
			a.logWithContext(r, "Exempt path: %s", path)
			handler.ServeHTTP(w, r)
			return
		}

		// Non-exempt paths must be authenticated
		sig := getSignatureFromCookies(r)
		if sig == "" {
			a.logWithContext(r, "No signature found for protected path: %s", path)
			http.Redirect(w, r, "/auth/login?return_to="+path, http.StatusFound)
			return
		}

		decodedSig, err := base64.StdEncoding.DecodeString(sig)
		if err != nil {
			a.logWithContext(r, "Failed to decode signature: %v", err)
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}

		values, err := url.ParseQuery(string(decodedSig))
		if err != nil {
			a.logWithContext(r, "Failed to parse signature: %v", err)
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}

		userEmail := values.Get("UserEmail")

		userAccess, err := a.getAccessByEmail(userEmail)
		if DevMode {
			a.logWithContext(r, "User access: %v", userAccess)
		}
		if err != nil {
			a.logWithContext(r, "Failed to get user access: %v", err)
			http.Error(w, "Internal System Error", http.StatusSeeOther)
			return
		}

		if _, ok := userAccess[path]; ok {
			handler(w, r)
			return
		}

		if a.isExemptPath(path) {

			noSigning(http.HandlerFunc(handler)).ServeHTTP(w, r)
			return
		}

		if strings.HasPrefix(path, "/api/mtgban/") ||
			strings.HasPrefix(path, "/api/mtgjson/") {
			// Use API-specific middleware for API paths
			enforceAPISigning(http.HandlerFunc(handler)).ServeHTTP(w, r)
			return
		}

		// Otherwise use standard enforceSigning middleware
		enforceSigning(http.HandlerFunc(handler)).ServeHTTP(w, r)
	}
}

// ============================================================================================
// Authentication Handler Functions
// ============================================================================================

// handleNextJsAssets serves static assets for Next.js
func (a *AuthService) handleNextJsAssets(w http.ResponseWriter, r *http.Request) {
	//a.logWithContext(r, "Next.js static asset request: %s", r.URL.Path)

	// Set content type headers based on file extension
	if strings.HasSuffix(r.URL.Path, ".js") {
		w.Header().Set("Content-Type", "application/javascript")
	} else if strings.HasSuffix(r.URL.Path, ".css") {
		w.Header().Set("Content-Type", "text/css")
	} else if strings.HasSuffix(r.URL.Path, ".json") {
		w.Header().Set("Content-Type", "application/json")
	} else if strings.HasSuffix(r.URL.Path, ".map") {
		w.Header().Set("Content-Type", "application/json")
	}

	// Get embedded files
	authFS, err := fs.Sub(authAssets, "nextAuth/out")
	if err != nil {
		a.logWithContext(r, "Failed to access embedded files: %v", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	// Remove leading slash for filesystem access
	fsPath := strings.TrimPrefix(r.URL.Path, "/")

	// Check if file exists
	_, err = fs.Stat(authFS, fsPath)
	if err != nil {
		a.logWithContext(r, "File not found: %s, error: %v", fsPath, err)
		http.NotFound(w, r)
		return
	}

	// Open the file
	file, err := authFS.Open(fsPath)
	if err != nil {
		a.logWithContext(r, "Error opening file: %s", fsPath)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Stream the file directly to the response
	io.Copy(w, file)
}

// handleAuthLogin handles API login requests
func (a *AuthService) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	// Handle GET requests (serve the page)
	if r.Method == http.MethodGet {
		a.logWithContext(r, "Login page request")

		// Set content type to HTML
		w.Header().Set("Content-Type", "text/html")

		// Get embedded files
		authFS, err := fs.Sub(authAssets, "nextAuth/out")
		if err != nil {
			a.logWithContext(r, "Failed to access embedded files: %v", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}

		// Serve the login HTML file
		serveFile(http.FileServer(http.FS(authFS)), w, r, "login.html")
		return
	}

	// Continue with POST handling for API login
	if r.Method != http.MethodPost {
		a.logWithContext(r, "Method not allowed: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	a.logWithContext(r, "API login attempt")

	// Parse request
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.logWithContext(r, "Failed to parse login request: %v", err)
		a.handleAPIError(w, r, AuthError{
			Code:       "INVALID_REQUEST",
			Message:    "Invalid request format",
			StatusCode: http.StatusBadRequest,
			Internal:   err,
		})
		return
	}

	// Basic validation
	if req.Email == "" || req.Password == "" {
		a.logWithContext(r, "Login attempt with empty credentials")
		a.handleAPIError(w, r, AuthError{
			Code:       "MISSING_CREDENTIALS",
			Message:    "Email and password are required",
			StatusCode: http.StatusBadRequest,
		})
		return
	}

	// Authenticate with Supabase
	ctx := context.Background()
	authResponse, err := a.Supabase.Auth.SignIn(ctx, supabase.UserCredentials{
		Email:    req.Email,
		Password: req.Password,
	})

	if err != nil {
		a.logWithContext(r, "Login failed: %v", err)
		a.handleAPIError(w, r, ErrInvalidCredentials)
		return
	}

	// Set cookies
	a.setAuthCookies(w, r, authResponse.AccessToken, authResponse.RefreshToken, req.Remember)

	// Get user data
	userInfo, err := a.Supabase.Auth.User(ctx, authResponse.AccessToken)
	if err != nil {
		a.logWithContext(r, "Error retrieving user data: %v", err)
		a.handleAPIError(w, r, AuthError{
			Code:       "USER_DATA_ERROR",
			Message:    "Error retrieving user data",
			StatusCode: http.StatusInternalServerError,
			Internal:   err,
		})
		return
	}

	// Get user tier from metadata
	tier := "free"
	if userInfo.UserMetadata != nil {
		if tierVal, ok := userInfo.UserMetadata["tier"].(string); ok && tierVal != "" {
			tier = tierVal
		}
	}

	// Generate CSRF token
	csrfToken := a.generateCSRFToken(userInfo.ID)

	// Set CSRF cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Path:     "/",
		HttpOnly: false,        // Accessible to JS
		MaxAge:   24 * 60 * 60, // 24 hours
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})

	// Generate internal signature for app permissions
	userData := &UserData{
		UserId: userInfo.ID,
		Email:  userInfo.Email,
		Tier:   tier,
	}

	// put signature in cookies
	baseURL := getBaseURL(r)
	sig := a.sign(baseURL, tier, userData)
	a.putSignatureInCookies(w, r, sig)

	// Send success response
	a.sendAPISuccess(w, "Login successful", map[string]interface{}{
		"user": map[string]interface{}{
			"id":             userInfo.ID,
			"email":          userInfo.Email,
			"tier":           tier,
			"emailConfirmed": !userInfo.ConfirmedAt.IsZero(),
			"user_metadata":  userInfo.UserMetadata,
		},
		"session": map[string]interface{}{
			"expires_at": time.Now().Add(24 * time.Hour).Unix(),
			"csrf_token": csrfToken,
		},
	})
}

// handleLoginFormSubmit handles form-based login submissions
func (a *AuthService) handleLoginFormSubmit(w http.ResponseWriter, r *http.Request) {
	a.logWithContext(r, "Form login attempt")

	// Parse form data
	if err := r.ParseForm(); err != nil {
		a.logWithContext(r, "Error parsing form data: %v", err)
		a.handleFormError(w, r, AuthError{
			Code:       "INVALID_FORM",
			Message:    "Error parsing form data",
			StatusCode: http.StatusBadRequest,
			Internal:   err,
		}, "/auth/login")
		return
	}

	// Get form values
	email := r.FormValue("email")
	password := r.FormValue("password")
	remember := r.FormValue("remember") == "on"

	// Validate required fields
	if email == "" || password == "" {
		a.logWithContext(r, "Login attempt with empty credentials")
		a.handleFormError(w, r, AuthError{
			Code:       "MISSING_CREDENTIALS",
			Message:    "Email and password are required",
			StatusCode: http.StatusBadRequest,
		}, "/auth/login")
		return
	}

	// Authenticate with Supabase
	ctx := context.Background()
	authResponse, err := a.Supabase.Auth.SignIn(ctx, supabase.UserCredentials{
		Email:    email,
		Password: password,
	})

	if err != nil {
		a.logWithContext(r, "Login failed: %v", err)
		a.handleFormError(w, r, AuthError{
			Code:       "INVALID_CREDENTIALS",
			Message:    "Invalid email or password",
			StatusCode: http.StatusUnauthorized,
			Internal:   err,
		}, "/auth/login")
		return
	}

	// Extract tokens
	jwtToken := authResponse.AccessToken
	refreshToken := authResponse.RefreshToken

	// Set cookies
	a.setAuthCookies(w, r, jwtToken, refreshToken, remember)

	// Get user data
	userInfo, err := a.Supabase.Auth.User(ctx, jwtToken)
	if err != nil {
		a.logWithContext(r, "Error getting user data: %v", err)
		a.handleFormError(w, r, AuthError{
			Code:       "USER_DATA_ERROR",
			Message:    "Error retrieving user data",
			StatusCode: http.StatusInternalServerError,
			Internal:   err,
		}, "/auth/login")
		return
	}

	// Set user tier
	tierTitle := "free"
	if userInfo.UserMetadata != nil {
		if tier, ok := userInfo.UserMetadata["tier"].(string); ok && tier != "" {
			tierTitle = tier
		}
	}

	// Generate signature
	userData := &UserData{
		UserId: userInfo.ID,
		Email:  userInfo.Email,
		Tier:   tierTitle,
	}

	baseURL := getBaseURL(r)
	sig := a.sign(baseURL, tierTitle, userData)
	a.putSignatureInCookies(w, r, sig)

	// Generate CSRF token
	csrfToken := a.generateCSRFToken(userInfo.ID)

	// Set CSRF cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Path:     "/",
		HttpOnly: false,        // Accessible to JS
		MaxAge:   24 * 60 * 60, // 24 hours
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})

	// Redirect after successful login
	returnTo := r.FormValue("return_to")
	if returnTo == "" {
		returnTo = "/home"
	}

	// Redirect to success page with proper parameters
	successURL := fmt.Sprintf("/auth/success?redirectTo=%s&message=%s",
		url.QueryEscape(returnTo),
		url.QueryEscape("You have successfully logged in"))

	a.logWithContext(r, "Login successful, redirecting to: %s", successURL)
	http.Redirect(w, r, successURL, http.StatusSeeOther)
}

// handleAuthSignup handles API signup requests
func (a *AuthService) handleAuthSignup(w http.ResponseWriter, r *http.Request) {
	// Handle GET requests (serve the page)
	if r.Method == http.MethodGet {
		a.logWithContext(r, "Signup page request")

		// Set content type to HTML
		w.Header().Set("Content-Type", "text/html")

		// Get embedded files
		authFS, err := fs.Sub(authAssets, "nextAuth/out")
		if err != nil {
			a.logWithContext(r, "Failed to access embedded files: %v", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}

		// Serve the signup HTML file
		serveFile(http.FileServer(http.FS(authFS)), w, r, "signup.html")
		return
	}

	// Continue with POST handling for API signup
	if r.Method != http.MethodPost {
		a.logWithContext(r, "Method not allowed: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	a.logWithContext(r, "API signup attempt")

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		a.logWithContext(r, "Error reading request body: %v", err)
		a.handleAPIError(w, r, AuthError{
			Code:       "INVALID_REQUEST",
			Message:    "Error reading request body",
			StatusCode: http.StatusBadRequest,
			Internal:   err,
		})
		return
	}

	// Parse request
	var req SignupRequest
	if err := json.Unmarshal(body, &req); err != nil {
		a.logWithContext(r, "Error parsing signup request: %v", err)
		a.handleAPIError(w, r, AuthError{
			Code:       "INVALID_REQUEST",
			Message:    "Invalid request format",
			StatusCode: http.StatusBadRequest,
			Internal:   err,
		})
		return
	}

	// Validate required fields
	if req.Email == "" || req.Password == "" {
		a.logWithContext(r, "Signup attempt with empty credentials")
		a.handleAPIError(w, r, AuthError{
			Code:       "MISSING_CREDENTIALS",
			Message:    "Email and password are required",
			StatusCode: http.StatusBadRequest,
		})
		return
	}

	// Validate password strength
	isValid, errorMsg := a.validatePassword(req.Password)
	if !isValid {
		a.logWithContext(r, "Password validation failed: %s", errorMsg)
		a.handleAPIError(w, r, AuthError{
			Code:       "WEAK_PASSWORD",
			Message:    errorMsg,
			StatusCode: http.StatusBadRequest,
		})
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
		a.logWithContext(r, "Signup failed: %v", err)

		// Check for common errors
		errMsg := err.Error()
		if strings.Contains(strings.ToLower(errMsg), "already") ||
			strings.Contains(strings.ToLower(errMsg), "taken") {
			a.handleAPIError(w, r, ErrEmailTaken)
		} else {
			a.handleAPIError(w, r, AuthError{
				Code:       "SIGNUP_FAILED",
				Message:    "Failed to create account",
				StatusCode: http.StatusBadRequest,
				Internal:   err,
			})
		}
		return
	}

	// Check if email confirmation is required
	if user.ConfirmedAt.IsZero() {
		// Email confirmation required
		a.logWithContext(r, "Signup successful, email confirmation required: %s", req.Email)
		a.sendAPISuccess(w, "Account created successfully. Please check your email to verify your account.", map[string]interface{}{
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
	a.logWithContext(r, "Signup successful with pre-confirmed email: %s", req.Email)
	authResponse, err := a.Supabase.Auth.SignIn(ctx, supabase.UserCredentials{
		Email:    req.Email,
		Password: req.Password,
	})

	if err != nil {
		// Return partial success without session
		a.sendAPISuccess(w, "Account created successfully. Please log in.", map[string]interface{}{
			"user": map[string]interface{}{
				"id":             user.ID,
				"email":          user.Email,
				"emailConfirmed": true,
			},
		})
		return
	}

	// Set cookies for the frontend
	a.setAuthCookies(w, r, authResponse.AccessToken, authResponse.RefreshToken, false)

	// Generate MTGBAN signature for internal auth
	userData := &UserData{
		UserId: user.ID,
		Email:  user.Email,
		Tier:   "free", // Default tier, can be updated later
	}

	baseURL := getBaseURL(r)
	sig := a.sign(baseURL, userData.Tier, userData)
	a.putSignatureInCookies(w, r, sig)

	// Generate CSRF token
	csrfToken := a.generateCSRFToken(user.ID)

	// Set CSRF cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Path:     "/",
		HttpOnly: false,        // Accessible to JS
		MaxAge:   24 * 60 * 60, // 24 hours
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})

	// Return full success response with session
	a.sendAPISuccess(w, "Account created successfully", map[string]interface{}{
		"user": map[string]interface{}{
			"id":             user.ID,
			"email":          user.Email,
			"emailConfirmed": true,
			"tier":           "free",
			"user_metadata":  user.UserMetadata,
		},
		"session": map[string]interface{}{
			"expires_at": time.Now().Add(24 * time.Hour).Unix(),
			"csrf_token": csrfToken,
		},
	})
}

// handleSignupFormSubmit handles form-based signup submissions
func (a *AuthService) handleSignupFormSubmit(w http.ResponseWriter, r *http.Request) {
	a.logWithContext(r, "Form signup attempt")

	// Parse form data
	if err := r.ParseForm(); err != nil {
		a.logWithContext(r, "Error parsing form data: %v", err)
		a.handleFormError(w, r, AuthError{
			Code:       "INVALID_FORM",
			Message:    "Error parsing form data",
			StatusCode: http.StatusBadRequest,
			Internal:   err,
		}, "/auth/signup")
		return
	}

	// Get form values
	email := r.FormValue("email")
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm-password")
	fullName := r.FormValue("fullname")
	termsAccepted := r.FormValue("terms") == "on"

	// Mask email for logging
	maskedEmail := maskEmail(email)

	// Validate inputs
	if email == "" || password == "" || fullName == "" {
		a.logWithContext(r, "Signup validation failed for %s: empty fields", maskedEmail)
		a.handleFormError(w, r, AuthError{
			Code:       "MISSING_FIELDS",
			Message:    "All fields are required",
			StatusCode: http.StatusBadRequest,
		}, "/auth/signup")
		return
	}

	if password != confirmPassword {
		a.logWithContext(r, "Signup validation failed for %s: passwords don't match", maskedEmail)
		a.handleFormError(w, r, AuthError{
			Code:       "PASSWORD_MISMATCH",
			Message:    "Passwords do not match",
			StatusCode: http.StatusBadRequest,
		}, "/auth/signup")
		return
	}

	if !termsAccepted {
		a.logWithContext(r, "Signup validation failed for %s: terms not accepted", maskedEmail)
		a.handleFormError(w, r, AuthError{
			Code:       "TERMS_REQUIRED",
			Message:    "You must accept the Terms of Service",
			StatusCode: http.StatusBadRequest,
		}, "/auth/signup")
		return
	}

	// Validate password strength
	isValid, errorMsg := a.validatePassword(password)
	if !isValid {
		a.logWithContext(r, "Password validation failed for %s: %s", maskedEmail, errorMsg)
		a.handleFormError(w, r, AuthError{
			Code:       "WEAK_PASSWORD",
			Message:    errorMsg,
			StatusCode: http.StatusBadRequest,
		}, "/auth/signup")
		return
	}

	// Create user metadata
	userMetadata := map[string]interface{}{
		"full_name": fullName,
		"tier":      "free",
	}

	// Create user in Supabase
	ctx := context.Background()
	user, err := a.Supabase.Auth.SignUp(ctx, supabase.UserCredentials{
		Email:    email,
		Password: password,
		Data:     userMetadata,
	})

	if err != nil {
		// Error handling
		errMsg := err.Error()
		a.logWithContext(r, "Signup failed for %s: %v", maskedEmail, err)

		if strings.Contains(strings.ToLower(errMsg), "already") ||
			strings.Contains(strings.ToLower(errMsg), "taken") {
			a.handleFormError(w, r, ErrEmailTaken, "/auth/signup")
		} else if strings.Contains(strings.ToLower(errMsg), "database") {
			a.handleFormError(w, r, AuthError{
				Code:       "DATABASE_ERROR",
				Message:    "Database error occurred",
				StatusCode: http.StatusInternalServerError,
				Internal:   err,
			}, "/auth/signup")
		} else {
			a.handleFormError(w, r, AuthError{
				Code:       "SIGNUP_FAILED",
				Message:    "Failed to create account",
				StatusCode: http.StatusBadRequest,
				Internal:   err,
			}, "/auth/signup")
		}
		return
	}

	a.logWithContext(r, "Signup successful for %s", maskedEmail)

	// If email confirmation is NOT required (user is already confirmed)
	if !user.ConfirmedAt.IsZero() {
		a.logWithContext(r, "Auto-login for new user %s", maskedEmail)

		// Auto-login the user after signup
		authResponse, err := a.Supabase.Auth.SignIn(ctx, supabase.UserCredentials{
			Email:    email,
			Password: password,
		})

		if err == nil {
			a.logWithContext(r, "Auto-login successful for %s", maskedEmail)

			// Extract tokens
			jwtToken := authResponse.AccessToken
			refreshToken := authResponse.RefreshToken

			// Set cookies
			a.setAuthCookies(w, r, jwtToken, refreshToken, false)

			// Get user data
			userData := &UserData{
				UserId: user.ID,
				Email:  user.Email,
				Tier:   "free", // Default tier for new users
			}

			// Generate internal signature
			baseURL := getBaseURL(r)
			sig := a.sign(baseURL, userData.Tier, userData)
			a.putSignatureInCookies(w, r, sig)

			// Generate CSRF token
			csrfToken := a.generateCSRFToken(user.ID)

			// Set CSRF cookie
			http.SetCookie(w, &http.Cookie{
				Name:     "csrf_token",
				Value:    csrfToken,
				Path:     "/",
				HttpOnly: false,        // Accessible to JS
				MaxAge:   24 * 60 * 60, // 24 hours
				Secure:   r.TLS != nil,
				SameSite: http.SameSiteStrictMode,
			})

			// Redirect to success page instead of directly to home
			successURL := fmt.Sprintf("/auth/success?redirectTo=%s&message=%s",
				url.QueryEscape("/home"),
				url.QueryEscape("Your account has been created successfully!"))

			a.logWithContext(r, "Redirecting new user %s to success page", maskedEmail)
			http.Redirect(w, r, successURL, http.StatusSeeOther)
			return
		} else {
			a.logWithContext(r, "Auto-login failed for new user %s: %v", maskedEmail, err)
		}
	}

	// Redirect to confirmation page if email verification is required
	a.logWithContext(r, "Redirecting %s to confirmation page (email verification pending)", maskedEmail)
	confirmationURL := fmt.Sprintf("/auth/confirmation?email=%s&message=%s",
		url.QueryEscape(email),
		url.QueryEscape("Your account has been created. Please check your email to verify your account."))

	http.Redirect(w, r, confirmationURL, http.StatusSeeOther)
}

// handleAuthForgotPassword handles API password reset requests
func (a *AuthService) handleAuthForgotPassword(w http.ResponseWriter, r *http.Request) {
	a.logWithContext(r, "API password reset request")

	// Parse request
	var req PasswordResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.logWithContext(r, "Error parsing password reset request: %v", err)
		a.handleAPIError(w, r, AuthError{
			Code:       "INVALID_REQUEST",
			Message:    "Invalid request format",
			StatusCode: http.StatusBadRequest,
			Internal:   err,
		})
		return
	}

	if req.Email == "" {
		a.logWithContext(r, "Password reset request with empty email")
		a.handleAPIError(w, r, AuthError{
			Code:       "MISSING_EMAIL",
			Message:    "Email is required",
			StatusCode: http.StatusBadRequest,
		})
		return
	}

	// Request password reset from Supabase
	ctx := context.Background()
	err := a.Supabase.Auth.ResetPasswordForEmail(ctx, req.Email, "/auth/reset-password")

	// For security reasons, don't reveal if the email exists
	if err != nil {
		a.logWithContext(r, "Password reset request failed: %v", err)
	} else {
		a.logWithContext(r, "Password reset request sent to: %s", maskEmail(req.Email))
	}

	// Return success response regardless to prevent email enumeration
	a.sendAPISuccess(w, "If an account exists with that email, we've sent password reset instructions.", nil)
}

// handleForgotPasswordFormSubmit handles form-based password reset requests
func (a *AuthService) handleForgotPasswordFormSubmit(w http.ResponseWriter, r *http.Request) {
	a.logWithContext(r, "Form password reset request")

	// Parse form data
	if err := r.ParseForm(); err != nil {
		a.logWithContext(r, "Error parsing form data: %v", err)
		a.handleFormError(w, r, AuthError{
			Code:       "INVALID_FORM",
			Message:    "Error parsing form data",
			StatusCode: http.StatusBadRequest,
			Internal:   err,
		}, "/auth/forgot-password")
		return
	}

	// Get form values
	email := r.FormValue("email")
	maskedEmail := maskEmail(email)

	if email == "" {
		a.logWithContext(r, "Password reset request with empty email")
		a.handleFormError(w, r, AuthError{
			Code:       "MISSING_EMAIL",
			Message:    "Email is required",
			StatusCode: http.StatusBadRequest,
		}, "/auth/forgot-password")
		return
	}

	// Request password reset from Supabase
	ctx := context.Background()
	err := a.Supabase.Auth.ResetPasswordForEmail(ctx, email, "/auth/reset-password")

	// For security reasons, don't reveal if the email exists
	if err != nil {
		a.logWithContext(r, "Password reset request failed: %v", err)
	} else {
		a.logWithContext(r, "Password reset request sent to: %s", maskedEmail)
	}

	// Redirect to confirmation page
	confirmationURL := fmt.Sprintf("/auth/reset-password-sent?email=%s&message=%s",
		url.QueryEscape(email),
		url.QueryEscape("If an account exists with that email, we've sent password reset instructions."))

	http.Redirect(w, r, confirmationURL, http.StatusSeeOther)
}

// handleAuthResetPassword handles API password reset completions
func (a *AuthService) handleAuthResetPassword(w http.ResponseWriter, r *http.Request) {
	a.logWithContext(r, "API password reset completion")

	// Parse request
	var req PasswordUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.logWithContext(r, "Error parsing password update request: %v", err)
		a.handleAPIError(w, r, AuthError{
			Code:       "INVALID_REQUEST",
			Message:    "Invalid request format",
			StatusCode: http.StatusBadRequest,
			Internal:   err,
		})
		return
	}

	// Validate required fields
	if req.Password == "" || req.Token == "" {
		a.logWithContext(r, "Password update request with missing fields")
		a.handleAPIError(w, r, AuthError{
			Code:       "MISSING_FIELDS",
			Message:    "Password and token are required",
			StatusCode: http.StatusBadRequest,
		})
		return
	}

	// Validate password strength
	isValid, errorMsg := a.validatePassword(req.Password)
	if !isValid {
		a.logWithContext(r, "Password validation failed: %s", errorMsg)
		a.handleAPIError(w, r, AuthError{
			Code:       "WEAK_PASSWORD",
			Message:    errorMsg,
			StatusCode: http.StatusBadRequest,
		})
		return
	}

	// Update user's password with token
	ctx := context.Background()
	updateData := map[string]interface{}{
		"password": req.Password,
	}

	user, err := a.Supabase.Auth.UpdateUser(ctx, req.Token, updateData)
	if err != nil {
		a.logWithContext(r, "Password reset failed: %v", err)
		a.handleAPIError(w, r, AuthError{
			Code:       "RESET_FAILED",
			Message:    "Failed to reset password",
			StatusCode: http.StatusInternalServerError,
			Internal:   err,
		})
		return
	}

	// Log the successful password reset
	a.logWithContext(r, "Password reset successful for user ID: %s", user.ID)

	// Return success response with redirect to login page
	a.sendAPISuccess(w, "Your password has been reset successfully. You can now log in with your new password.", map[string]interface{}{
		"redirectTo": "/auth/login",
	})
}

// handleResetPasswordFormSubmit handles form-based password reset completions
func (a *AuthService) handleResetPasswordFormSubmit(w http.ResponseWriter, r *http.Request) {
	a.logWithContext(r, "Form password reset completion")

	// Parse form data
	if err := r.ParseForm(); err != nil {
		a.logWithContext(r, "Error parsing form data: %v", err)
		a.handleFormError(w, r, AuthError{
			Code:       "INVALID_FORM",
			Message:    "Error parsing form data",
			StatusCode: http.StatusBadRequest,
			Internal:   err,
		}, "/auth/reset-password")
		return
	}

	// Get form values
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm-password")
	token := r.FormValue("token") // This is the reset token from the URL

	// Validate inputs
	if password == "" || token == "" {
		a.logWithContext(r, "Password reset with empty fields")
		a.handleFormError(w, r, AuthError{
			Code:       "MISSING_FIELDS",
			Message:    "Password and token are required",
			StatusCode: http.StatusBadRequest,
		}, "/auth/reset-password")
		return
	}

	if password != confirmPassword {
		a.logWithContext(r, "Password reset passwords don't match")
		a.handleFormError(w, r, AuthError{
			Code:       "PASSWORD_MISMATCH",
			Message:    "Passwords do not match",
			StatusCode: http.StatusBadRequest,
		}, "/auth/reset-password")
		return
	}

	// Validate password strength
	isValid, errorMsg := a.validatePassword(password)
	if !isValid {
		a.logWithContext(r, "Password validation failed: %s", errorMsg)
		a.handleFormError(w, r, AuthError{
			Code:       "WEAK_PASSWORD",
			Message:    errorMsg,
			StatusCode: http.StatusBadRequest,
		}, "/auth/reset-password")
		return
	}

	// Update user's password with token
	ctx := context.Background()
	updateData := map[string]interface{}{
		"password": password,
	}

	user, err := a.Supabase.Auth.UpdateUser(ctx, token, updateData)
	if err != nil {
		a.logWithContext(r, "Password reset failed: %v", err)
		a.handleFormError(w, r, AuthError{
			Code:       "RESET_FAILED",
			Message:    "Failed to reset password",
			StatusCode: http.StatusInternalServerError,
			Internal:   err,
		}, "/auth/reset-password")
		return
	}

	// Log the successful password reset
	a.logWithContext(r, "Password reset successful for user ID: %s", user.ID)

	// Redirect to success page
	successURL := fmt.Sprintf("/auth/success?redirectTo=%s&message=%s",
		url.QueryEscape("/auth/login"),
		url.QueryEscape("Your password has been reset successfully. You can now log in with your new password."))

	http.Redirect(w, r, successURL, http.StatusSeeOther)
}

// handleAuthLogout handles API logout requests
func (a *AuthService) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	a.logWithContext(r, "API logout request")

	// Get token from cookie
	authCookie, err := r.Cookie("auth_token")
	if err == nil && authCookie.Value != "" {
		// Sign out from Supabase
		err := a.Supabase.Auth.SignOut(context.Background(), authCookie.Value)
		if err != nil {
			a.logWithContext(r, "Supabase logout error: %v", err)
		}
	}

	// Clear auth cookies
	a.clearAuthCookies(w, r)

	// Return success response
	a.sendAPISuccess(w, "Logout successful", map[string]interface{}{
		"redirectTo": "/",
	})
}

// handleLogoutForm handles form-based logout requests
func (a *AuthService) handleLogoutForm(w http.ResponseWriter, r *http.Request) {
	a.logWithContext(r, "Form logout request")

	// Get token from cookie and sign out from Supabase
	authCookie, err := r.Cookie("auth_token")
	if err == nil && authCookie.Value != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := a.Supabase.Auth.SignOut(ctx, authCookie.Value)
		if err != nil {
			a.logWithContext(r, "Supabase logout error: %v", err)
		}
	}

	// 2. Clear ALL cookies (using multiple techniques)
	a.clearAllCookies(w, r)

	// 3. Serve a cleanup page with JavaScript to clear client-side state
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

// Clear all cookies using multiple approaches to handle various scenarios
func (a *AuthService) clearAllCookies(w http.ResponseWriter, r *http.Request) {
	// Get domain variations
	baseURL := getBaseURL(r)
	domain := "mtgban.com"
	if strings.Contains(baseURL, "localhost") {
		domain = "localhost"
	}

	// List of cookies to clear
	cookiesToClear := []string{"MTGBAN", "auth_token", "refresh_token", "csrf_token"}

	// Clear each cookie in multiple ways
	for _, name := range cookiesToClear {
		// Clear with domain
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			Domain:   domain,
			MaxAge:   -1,
			Expires:  time.Unix(0, 0),
			HttpOnly: true,
		})

		// Clear without domain (for browser compatibility)
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Expires:  time.Unix(0, 0),
			HttpOnly: true,
		})
	}

	a.logWithContext(r, "Cleared all authentication cookies")
}

// handleAuthGetUser handles API requests to get user information
func (a *AuthService) handleAuthGetUser(w http.ResponseWriter, r *http.Request) {
	a.logWithContext(r, "API get user request")

	// Get auth token and refresh token from cookies
	authCookie, authErr := r.Cookie("auth_token")
	refreshCookie, refreshErr := r.Cookie("refresh_token")

	var userInfo *supabase.User
	var err error

	// Check if we have a valid auth token
	if authErr != nil || authCookie.Value == "" {
		// No auth token, check if we have refresh token
		if refreshErr != nil || refreshCookie.Value == "" {
			a.logWithContext(r, "No auth token and no refresh token found")
			a.handleAPIError(w, r, ErrMissingToken)
			return
		}

		// Try to refresh using refresh token
		a.logWithContext(r, "No auth token but refresh token found, attempting token refresh")

		newAuthToken, newRefreshToken, refreshedUser, refreshErr := a.refreshTokenInternal("", refreshCookie.Value)
		if refreshErr != nil {
			a.logWithContext(r, "Token refresh failed: %v", refreshErr)
			a.clearAuthCookies(w, r)
			a.handleAPIError(w, r, ErrSessionExpired)
			return
		}

		// Set new cookies
		a.setAuthCookies(w, r, newAuthToken, newRefreshToken, true)

		// Use the refreshed user info
		userInfo = refreshedUser
	} else {
		// We have an auth token, try to get user info
		ctx := context.Background()
		userInfo, err = a.Supabase.Auth.User(ctx, authCookie.Value)

		if err != nil {
			// Auth token is invalid, try to refresh if we have a refresh token
			if refreshErr == nil && refreshCookie.Value != "" {
				a.logWithContext(r, "Invalid auth token, attempting refresh")

				newAuthToken, newRefreshToken, refreshedUser, refreshErr := a.refreshTokenInternal(authCookie.Value, refreshCookie.Value)
				if refreshErr != nil {
					a.logWithContext(r, "Token refresh failed: %v", refreshErr)
					a.clearAuthCookies(w, r)
					a.handleAPIError(w, r, ErrSessionExpired)
					return
				}

				// Set new cookies
				a.setAuthCookies(w, r, newAuthToken, newRefreshToken, true)

				// Use the refreshed user info
				userInfo = refreshedUser
			} else {
				a.logWithContext(r, "Invalid auth token and no refresh token found")
				a.clearAuthCookies(w, r)
				a.handleAPIError(w, r, ErrInvalidToken)
				return
			}
		}
	}

	// If we still don't have valid user info after all attempts
	if userInfo == nil {
		a.logWithContext(r, "Failed to get user info after token refresh")
		a.clearAuthCookies(w, r)
		a.handleAPIError(w, r, ErrInvalidToken)
		return
	}

	// Extract user metadata and tier information
	var userMetadata map[string]interface{}
	tier := "free" // Default tier

	if userInfo.UserMetadata != nil {
		userMetadata = userInfo.UserMetadata

		// Extract tier from metadata if available
		if tierVal, ok := userInfo.UserMetadata["tier"].(string); ok && tierVal != "" {
			tier = tierVal
		}
	}

	// Get current user tier from internal cookie if available
	signature, err := r.Cookie("MTGBAN")
	if err == nil && signature.Value != "" {
		sigTier := GetParamFromSig(signature.Value, "UserTier")
		if sigTier != "" {
			tier = sigTier
		}
	}

	// Update internal signature with latest user data
	userData := &UserData{
		UserId: userInfo.ID,
		Email:  userInfo.Email,
		Tier:   tier,
	}

	baseURL := getBaseURL(r)
	sig := a.sign(baseURL, tier, userData)
	a.putSignatureInCookies(w, r, sig)

	// Generate new CSRF token
	csrfToken := a.generateCSRFToken(userInfo.ID)

	// Set CSRF cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Path:     "/",
		HttpOnly: false,        // Accessible to JS
		MaxAge:   24 * 60 * 60, // 24 hours
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})

	// Return comprehensive user data
	a.sendAPISuccess(w, "User data retrieved successfully", map[string]interface{}{
		"user": map[string]interface{}{
			"id":             userInfo.ID,
			"email":          userInfo.Email,
			"tier":           tier,
			"emailConfirmed": !userInfo.ConfirmedAt.IsZero(),
			"user_metadata":  userMetadata,
		},
		"csrf_token": csrfToken,
	})
}

// refreshTokenInternal handles the internal logic for refreshing tokens
func (a *AuthService) refreshTokenInternal(authToken, refreshToken string) (string, string, *supabase.User, error) {
	ctx := context.Background()

	// Refresh token with Supabase
	authResponse, err := a.Supabase.Auth.RefreshUser(ctx, authToken, refreshToken)
	if err != nil {
		return "", "", nil, err
	}

	// Extract new tokens
	newJwtToken := authResponse.AccessToken
	newRefreshToken := authResponse.RefreshToken

	// Get user data if token was refreshed successfully
	var userInfo *supabase.User
	if newJwtToken != "" {
		userInfo, _ = a.Supabase.Auth.User(ctx, newJwtToken)
	}

	return newJwtToken, newRefreshToken, userInfo, nil
}

// handleAuthRefreshToken handles API requests to refresh tokens
func (a *AuthService) handleAuthRefreshToken(w http.ResponseWriter, r *http.Request) {
	a.logWithContext(r, "API token refresh request")

	// Get refresh token from cookie
	refreshCookie, refreshErr := r.Cookie("refresh_token")
	authCookie, authErr := r.Cookie("auth_token")

	if refreshErr != nil || refreshCookie.Value == "" {
		a.logWithContext(r, "No refresh token found")
		a.handleAPIError(w, r, ErrMissingToken)
		return
	}

	// Get tokens from cookies
	var authToken string
	if authErr == nil && authCookie.Value != "" {
		authToken = authCookie.Value
	}
	refreshToken := refreshCookie.Value

	// Refresh the token using our internal function
	newAuthToken, newRefreshToken, userInfo, err := a.refreshTokenInternal(authToken, refreshToken)
	if err != nil {
		a.logWithContext(r, "Token refresh failed: %v", err)
		a.clearAuthCookies(w, r)
		a.handleAPIError(w, r, ErrSessionExpired)
		return
	}

	// Set new cookies
	a.setAuthCookies(w, r, newAuthToken, newRefreshToken, true)

	// Prepare the response
	response := map[string]interface{}{
		"expires_at":      time.Now().Add(24 * time.Hour).Unix(),
		"token_refreshed": true,
	}

	// Only proceed with user data if we have a valid user
	if userInfo != nil {
		// Update signature cookie with latest user data
		tier := "free"
		if userInfo.UserMetadata != nil {
			if tierVal, ok := userInfo.UserMetadata["tier"].(string); ok && tierVal != "" {
				tier = tierVal
			}
		}

		userData := &UserData{
			UserId: userInfo.ID,
			Email:  userInfo.Email,
			Tier:   tier,
		}

		baseURL := getBaseURL(r)
		sig := a.sign(baseURL, tier, userData)
		a.putSignatureInCookies(w, r, sig)

		// Generate new CSRF token
		csrfToken := a.generateCSRFToken(userInfo.ID)

		// Set CSRF cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "csrf_token",
			Value:    csrfToken,
			Path:     "/",
			HttpOnly: false,        // Accessible to JS
			MaxAge:   24 * 60 * 60, // 24 hours
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteStrictMode,
		})

		// Add user info and CSRF token to response
		response["csrf_token"] = csrfToken
		response["user"] = map[string]interface{}{
			"id":    userInfo.ID,
			"email": userInfo.Email,
			"tier":  tier,
		}
	}

	// Send the response
	a.sendAPISuccess(w, "Token refreshed successfully", response)
}

// ============================================================================================
// Helper Functions
// ============================================================================================

// logWithContext logs messages with request context
func (a *AuthService) logWithContext(r *http.Request, format string, v ...interface{}) {
	clientIP := getClientIP(r)
	method := r.Method
	path := r.URL.Path

	// Get user ID if authenticated
	userID := "anonymous"
	authCookie, err := r.Cookie("auth_token")
	if err == nil && authCookie.Value != "" {
		// Extract user ID from JWT without full verification
		parts := strings.Split(authCookie.Value, ".")
		if len(parts) == 3 {
			payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
			var claims map[string]interface{}
			if json.Unmarshal(payload, &claims) == nil {
				if sub, ok := claims["sub"].(string); ok {
					userID = maskID(sub) // Mask for security
				}
			}
		}
	}

	contextMsg := fmt.Sprintf("[%s][%s %s][User:%s] %s",
		clientIP, method, path, userID, format)

	a.Logger.Printf(contextMsg, v...)
}

// normalizeAuthPath normalizes authentication paths
func (a *AuthService) normalizeAuthPath(path string) string {
	// Define base auth paths
	authPaths := map[string]bool{
		"/login":                  true,
		"/signup":                 true,
		"/forgot-password":        true,
		"/reset-password":         true,
		"/confirmation":           true,
		"/success":                true,
		"/signup-success":         true,
		"/reset-password-sent":    true,
		"/login-submit":           true,
		"/signup-submit":          true,
		"/forgot-password-submit": true,
		"/reset-password-submit":  true,
		"/logout":                 true,
	}

	// Remove trailing slash if present
	if len(path) > 1 && path[len(path)-1] == '/' {
		path = path[:len(path)-1]
	}

	// Handle duplicate /auth/auth/ prefix
	if strings.HasPrefix(path, "/auth/auth/") {
		path = "/auth/" + strings.TrimPrefix(path, "/auth/auth/")
		return path
	}

	// Add /auth/ prefix for known auth paths if missing
	if authPaths[path] && !strings.HasPrefix(path, "/auth") {
		return "/auth" + path
	}

	return path
}

// isExemptPath checks if a path is exempt from authentication
func (a *AuthService) isExemptPath(path string) bool {
	// Always exempt the root path
	if path == "/" || path == "/home" {
		return true
	}

	// Check exact routes
	for _, route := range a.AuthConfig.ExemptRoutes {
		if path == route {
			return true
		}
	}

	// Check prefixes
	for _, prefix := range a.AuthConfig.ExemptPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	// Check suffixes
	for _, suffix := range a.AuthConfig.ExemptSuffixes {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}

	return false
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
	}

	if !hasLetter {
		return false, "Password must contain at least one letter"
	}

	if !hasDigit {
		return false, "Password must contain at least one number"
	}

	return true, ""
}

// serveFile serves a file with a modified request path
func serveFile(fileServer http.Handler, w http.ResponseWriter, r *http.Request, path string) {
	// Create a new request with the modified path
	newReq := &http.Request{
		Method:     r.Method,
		URL:        &url.URL{Path: "/" + path},
		Proto:      r.Proto,
		ProtoMajor: r.ProtoMajor,
		ProtoMinor: r.ProtoMinor,
		Header:     r.Header,
		Body:       r.Body,
		Host:       r.Host,
	}

	if DevMode {
		log.Printf("Serving auth asset: %s", path)
	}

	// Set the content type based on the file extension
	if strings.HasSuffix(path, ".html") {
		w.Header().Set("Content-Type", "text/html")
	} else if strings.HasSuffix(path, ".js") {
		w.Header().Set("Content-Type", "application/javascript")
	} else if strings.HasSuffix(path, ".json") {
		w.Header().Set("Content-Type", "application/json")
	} else if strings.HasSuffix(path, ".svg") {
		w.Header().Set("Content-Type", "image/svg+xml")
	} else if strings.HasSuffix(path, ".png") {
		w.Header().Set("Content-Type", "image/png")
	} else if strings.HasSuffix(path, ".jpg") || strings.HasSuffix(path, ".jpeg") {
		w.Header().Set("Content-Type", "image/jpeg")
	} else if strings.HasSuffix(path, ".ico") {
		w.Header().Set("Content-Type", "image/x-icon")
	} else if strings.HasSuffix(path, ".css") {
		w.Header().Set("Content-Type", "text/css")
	} else if strings.HasSuffix(path, ".woff") {
		w.Header().Set("Content-Type", "font/woff")
	} else if strings.HasSuffix(path, ".woff2") {
		w.Header().Set("Content-Type", "font/woff2")
	} else if strings.HasSuffix(path, ".ttf") {
		w.Header().Set("Content-Type", "font/ttf")
	}

	// Serve the file
	fileServer.ServeHTTP(w, newReq)
}

// generateCSRFToken generates a CSRF token for a user
func (a *AuthService) generateCSRFToken(userID string) string {
	h := hmac.New(sha256.New, a.CSRFSecret)
	h.Write([]byte(userID))
	h.Write([]byte(time.Now().Format("2006-01-02"))) // Daily rotation
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// validateCSRFToken validates a CSRF token
func (a *AuthService) validateCSRFToken(token, userID string) bool {
	// If no token provided, validation fails
	if token == "" {
		return false
	}

	expected := a.generateCSRFToken(userID)
	return token == expected
}

// getBaseURL gets the base URL for the request
func getBaseURL(r *http.Request) string {
	host := r.Host
	if host == "localhost:8080" && !DevMode {
		host = DefaultHost
	}
	baseURL := "http://" + host
	if r.TLS != nil {
		baseURL = strings.Replace(baseURL, "http", "https", 1)
	}
	return baseURL
}

// signHMACSHA256Base64 signs data with HMAC-SHA256
func (a *AuthService) signHMACSHA256Base64(key []byte, data []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// sign signs data for permission granting
func (a *AuthService) sign(link string, tierTitle string, userData *UserData) string {
	// Get values for the tier
	v := a.getValuesForTier(tierTitle)

	// add BanACL data if available
	if userData != nil && a.BanACL != nil {
		a.addBanACLPermissions(v, userData.Email)

		v.Set("UserEmail", userData.Email)
		v.Set("UserTier", tierTitle)
	}

	expires := time.Now().Add(DefaultSignatureDuration)
	data := fmt.Sprintf("GET%d%s%s", expires.Unix(), link, v.Encode())
	key := os.Getenv("BAN_SECRET")
	sig := a.signHMACSHA256Base64([]byte(key), []byte(data))

	v.Set("Expires", fmt.Sprintf("%d", expires.Unix()))
	v.Set("Signature", sig)
	str := base64.StdEncoding.EncodeToString([]byte(v.Encode()))

	return str
}

// getValuesForTier gets values for a specific tier
func (a *AuthService) getValuesForTier(tierTitle string) url.Values {
	v := url.Values{}
	tier, found := Config.ACL.Tiers[tierTitle]
	if !found {
		return v
	}
	for _, page := range OrderNav {
		options, found := tier[page]
		if !found {
			continue
		}
		v.Set(page, "true")

		for _, key := range OptionalFields {
			val, found := options[key]
			if !found {
				continue
			}
			v.Set(key, val)
		}
	}
	return v
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
		// Each section key corresponds to a value in OrderNav
		if isNavSection(section) {
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

// isNavSection checks if a section name is in OrderNav
func isNavSection(section string) bool {
	for _, navSection := range OrderNav {
		if navSection == section {
			return true
		}
	}
	return false
}

// GetParamFromSig gets a parameter from a signature
func GetParamFromSig(sig, param string) string {
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return ""
	}
	v, err := url.ParseQuery(string(raw))
	if err != nil {
		return ""
	}
	return v.Get(param)
}

// putSignatureInCookies puts a signature in cookies
func (a *AuthService) putSignatureInCookies(w http.ResponseWriter, r *http.Request, sig string) {
	baseURL := getBaseURL(r)

	year, month, _ := time.Now().Date()
	endOfThisMonth := time.Date(year, month+1, 1, 0, 0, 0, 0, time.Now().Location())
	domain := "mtgban.com"
	if strings.Contains(baseURL, "localhost") {
		domain = "localhost"
	}

	cookie := http.Cookie{
		Name:    "MTGBAN",
		Domain:  domain,
		Path:    "/",
		Expires: endOfThisMonth,
		Value:   sig,
	}

	http.SetCookie(w, &cookie)
}

// setAuthCookies sets authentication cookies
// Ensure the remember option is working correctly
func (a *AuthService) setAuthCookies(w http.ResponseWriter, r *http.Request, token, refreshToken string, rememberMe bool) {
	// Set the token expiration time based on remember option
	maxAge := 24 * 60 * 60 // 24 hours by default
	if rememberMe {
		maxAge = 30 * 24 * 60 * 60 // 30 days if remember is checked
	}

	// Determine security settings
	isSecure := r.TLS != nil || !a.DebugMode
	sameSiteMode := http.SameSiteStrictMode
	if a.DebugMode {
		sameSiteMode = http.SameSiteLaxMode
	}

	// Set auth token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   maxAge,
		Secure:   isSecure,
		SameSite: sameSiteMode,
	})

	// Set refresh token cookie (longer expiry)
	refreshMaxAge := 60 * 24 * 60 * 60 // 60 days by default
	if rememberMe {
		refreshMaxAge = 365 * 24 * 60 * 60 // 1 year if remember is checked
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   refreshMaxAge,
		Secure:   isSecure,
		SameSite: sameSiteMode,
	})
}

// clearAuthCookies clears authentication cookies
func (a *AuthService) clearAuthCookies(w http.ResponseWriter, r *http.Request) {
	// Clear auth token cookie
	baseURL := getBaseURL(r)
	domain := "mtgban.com"
	if strings.Contains(baseURL, "localhost") {
		domain = "localhost"
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "MTGBAN",
		Value:    "",
		Path:     "/",
		Domain:   domain,
		MaxAge:   -1,
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})

	// Clear refresh token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})

	// Clear CSRF token
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Path:     "/",
		HttpOnly: false,
		MaxAge:   -1,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})
}

// sendAPISuccess sends a successful API response
func (a *AuthService) sendAPISuccess(w http.ResponseWriter, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: message,
		Data:    data,
	})
}

// handleAPIError handles API errors
func (a *AuthService) handleAPIError(w http.ResponseWriter, r *http.Request, err AuthError) {
	// Log internal error if present
	if err.Internal != nil {
		a.logWithContext(r, "API error (%s): %v", err.Code, err.Internal)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.StatusCode)
	json.NewEncoder(w).Encode(APIResponse{
		Success: false,
		Error:   err.Message,
		Code:    err.Code,
	})
}

// handleFormError handles form errors with redirects
func (a *AuthService) handleFormError(w http.ResponseWriter, r *http.Request, err AuthError, returnPath string) {
	// Log internal error if present
	if err.Internal != nil {
		a.logWithContext(r, "Form error (%s): %v", err.Code, err.Internal)
	}

	// Redirect with error message
	redirectURL := fmt.Sprintf("%s?error=%s&message=%s",
		returnPath,
		url.QueryEscape(err.Code),
		url.QueryEscape(err.Message))

	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// ============================================================================================
// Route Registration
// ============================================================================================

// createStaticFileServer creates a file server for static auth assets
func (a *AuthService) createStaticFileServer(authFS fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(authFS))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log the requested path for debugging
		if a.DebugMode {
			a.logWithContext(r, "Auth asset request: %s", r.URL.Path)
		}

		// Handle special paths like confirmation, success, etc.
		switch r.URL.Path {
		case "/confirmation":
			a.serveConfirmationPage(w, r)
			return
		case "/signup-success":
			a.serveSignupSuccessPage(w, r)
			return
		case "/success":
			a.serveSuccessPage(w, r)
			return
		case "/reset-password-sent":
			a.serveResetPasswordSentPage(w, r)
			return
		}

		// Get the clean path for route matching
		path := r.URL.Path
		cleanPath := strings.TrimPrefix(strings.Trim(path, "/"), "auth/")

		// Try to serve the file directly
		filePath := cleanPath
		if filepath.Ext(cleanPath) == "" {
			// If no extension and not a directory, try adding .html
			htmlPath := cleanPath + ".html"
			if authFileExists(authFS, htmlPath) {
				w.Header().Set("Content-Type", "text/html")
				serveFile(fileServer, w, r, htmlPath)
				return
			}
		}

		if authFileExists(authFS, filePath) {
			serveFile(fileServer, w, r, filePath)
			return
		}

		// Handle Next.js static files
		if strings.HasPrefix(path, "/_next/") {
			nextPath := strings.TrimPrefix(path, "/")
			if authFileExists(authFS, nextPath) {
				serveFile(fileServer, w, r, nextPath)
				return
			}
		}

		// If all else fails for login-related paths, try to serve login.html
		if strings.Contains(path, "login") {
			if authFileExists(authFS, "login.html") {
				w.Header().Set("Content-Type", "text/html")
				serveFile(fileServer, w, r, "login.html")
				return
			}
		}

		// Last resort - serve index.html for SPA navigation
		if !strings.Contains(path, ".") {
			if authFileExists(authFS, "index.html") {
				w.Header().Set("Content-Type", "text/html")
				serveFile(fileServer, w, r, "index.html")
				return
			}
		}

		a.Logger.Printf("Auth file not found: %s", path)
		http.NotFound(w, r)
	})
}

func (a *AuthService) serveConfirmationPage(w http.ResponseWriter, r *http.Request) {
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
    <link rel="stylesheet" href="auth.css">
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
            <p>Return to <a href="login">Login</a></p>
        </div>
    </div>
</body>
</html>
	`))
}

// serveSignupSuccessPage serves the signup success page
func (a *AuthService) serveSignupSuccessPage(w http.ResponseWriter, r *http.Request) {
	// Serve a simple static HTML success page
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`
<!DOCTYPE html>
<html>
<head>
    <title>Signup Successful | MTGBAN</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="auth.css">
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
        <h1 class="auth-title">Account Created</h1>
        <div class="auth-message success-message">
            Your account has been created. Please check your email to verify your account.
        </div>
        <div class="auth-links">
            <p>Return to <a href="login">Login</a></p>
        </div>
    </div>
</body>
</html>
	`))
}

// serveSuccessPage serves the success page
func (a *AuthService) serveSuccessPage(w http.ResponseWriter, r *http.Request) {
	// Extract query parameters
	redirectTo := r.URL.Query().Get("redirectTo")
	message := r.URL.Query().Get("message")

	if message == "" {
		message = "Your action was completed successfully."
	}

	// Default redirect if none provided
	if redirectTo == "" {
		redirectTo = "login"
	}

	// Serve a simple static HTML success page
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`
<!DOCTYPE html>
<html>
<head>
    <title>Success | MTGBAN</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="auth.css">
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

// serveResetPasswordSentPage serves the reset password sent page
func (a *AuthService) serveResetPasswordSentPage(w http.ResponseWriter, r *http.Request) {
	// Extract query parameters
	email := r.URL.Query().Get("email")

	// Create email message if provided
	var emailHTML string
	if email != "" {
		emailHTML = "<p>We've sent password reset instructions to <strong>" + email + "</strong></p>"
	}

	// Serve a simple static HTML page
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`
<!DOCTYPE html>
<html>
<head>
    <title>Reset Password | MTGBAN</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="auth.css">
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
            <p>Return to <a href="login">Login</a></p>
        </div>
    </div>
</body>
</html>
	`))
}

// ============================================================================================
// Custom Types
// ============================================================================================

// responseWriter wraps http.ResponseWriter to capture the status code
type responseWriter struct {
	http.ResponseWriter
	status int
}

// newResponseWriter creates a new response writer
func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{w, http.StatusOK}
}

// WriteHeader overrides the original WriteHeader to capture the status code
func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// ============================================================================================
// InitAuth - Legacy Compatibility Function
// ============================================================================================

type TierNavCache struct {
	navConfigs map[string][]NavElem
	mutex      sync.RWMutex
}

// NewTierNavCache creates a navigation cache based on the current configuration
func NewTierNavCache() *TierNavCache {
	cache := &TierNavCache{
		navConfigs: make(map[string][]NavElem),
	}

	cache.RefreshCache()

	return cache
}

// RefreshCache rebuilds the navigation configurations for all tiers
func (c *TierNavCache) RefreshCache() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Clear existing configurations
	c.navConfigs = make(map[string][]NavElem)

	// Build navigation for each tier defined in Config
	for tier := range Config.ACL.Tiers {
		// Start with default navigation
		nav := make([]NavElem, len(DefaultNav))
		copy(nav, DefaultNav)

		// Add navigation elements based on tier permissions
		for _, feat := range OrderNav {
			// Check if this tier has access to this feature
			_, allowed := Config.ACL.Tiers[tier][feat]

			// If allowed or feature doesn't require auth, add it
			if allowed || ExtraNavs[feat].NoAuth {
				nav = append(nav, *ExtraNavs[feat])
			}
		}

		c.navConfigs[tier] = nav
	}

	anonymousNav := make([]NavElem, len(DefaultNav))
	copy(anonymousNav, DefaultNav)

	for _, feat := range OrderNav {
		if ExtraNavs[feat].NoAuth {
			anonymousNav = append(anonymousNav, *ExtraNavs[feat])
		}
	}

	c.navConfigs["anonymous"] = anonymousNav
}

// GetNavForTier returns a copy of the navigation for a specific tier
func (c *TierNavCache) GetNavForTier(tier string) []NavElem {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	nav, exists := c.navConfigs[tier]
	if !exists {
		nav = c.navConfigs["free"]
		if nav == nil {
			nav = c.navConfigs["anonymous"]
		}
	}

	// Return a copy to prevent modification of cached data
	result := make([]NavElem, len(nav))
	copy(result, nav)

	return result
}

// BuildPageVars builds the PageVars with the right navigation
func (c *TierNavCache) BuildPageVars(activeTab, sig string) PageVars {
	// Extract basic user info from signature
	exp := GetParamFromSig(sig, "Expires")
	expires, _ := strconv.ParseInt(exp, 10, 64)
	userEmail := GetParamFromSig(sig, "UserEmail")
	userTier := GetParamFromSig(sig, "UserTier")

	msg := ""
	showLogin := false
	if sig != "" {
		if expires < time.Now().Unix() {
			msg = ErrMsgExpired
		}
	} else {
		showLogin = true
	}

	isLoggedIn := userEmail != "" && (expires > time.Now().Unix() || (DevMode && !SigCheck))

	// Initialize base page variables
	pageVars := PageVars{
		Title:        "BAN " + activeTab,
		ErrorMessage: msg,
		LastUpdate:   LastUpdate,
		ShowLogin:    showLogin,
		Hash:         BuildCommit,
		IsLoggedIn:   isLoggedIn,
		UserEmail:    userEmail,
		UserTier:     userTier,
	}

	applyGameSettings(&pageVars)

	var nav []NavElem
	if isLoggedIn {
		nav = c.GetNavForTier(userTier)
	} else {
		nav = c.GetNavForTier("anonymous")
	}

	for i := range nav {
		if nav[i].Name == activeTab {
			nav[i].Active = true
			nav[i].Class = "active"

			if showLogin && nav[i].NoAuth {
				betaNav := NavElem{
					Active: true,
					Class:  "beta",
					Short:  "Beta Public Access",
					Link:   "javascript:void(0)",
				}
				nav = append(nav, betaNav)
			}
			break
		}
	}

	pageVars.Nav = nav
	return pageVars
}

// InitAuth initializes the auth service (legacy compatibility function)
func InitAuth(params ...string) (*AuthService, error) {
	// Set default config
	config := AuthConfig{
		SupabaseURL:     Config.DB.Url,
		SupabaseAnonKey: Config.DB.Key,
		SupabaseSecret:  Config.DB.Secret,
		DebugMode:       DevMode,
		LogPrefix:       "[AUTH] ",
		ExemptRoutes:    []string{"/", "/home, /api/suggest"},
		ExemptPrefixes:  []string{"/auth/", "/next-api/auth/", "/css/", "/js/", "/img/"},
		ExemptSuffixes:  []string{".css", ".js", ".ico", ".png", ".jpg", ".jpeg", ".gif", ".svg"},
	}

	var configFile string
	if len(params) > 0 {
		configFile = params[0]
	}

	// Try to load from config file if provided
	if configFile != "" {
		log.Printf("Loading configuration from file: %s", configFile)
		// Check if the file exists and is not empty
		file, err := os.Open(configFile)
		if err == nil {
			defer file.Close()
			if err := json.NewDecoder(file).Decode(&config); err != nil {
				return nil, fmt.Errorf("failed to parse config file: %w", err)
			}
		} else if !os.IsNotExist(err) && !DevMode {
			return nil, fmt.Errorf("failed to open config file: %w", err)
		}
	}

	service, err := NewAuthService(config)
	if err != nil {
		return nil, err
	}

	if err := service.Initialize(); err != nil {
		return nil, err
	}

	return service, nil
}

// getSignatureFromCookies returns the signature from the cookies
func getSignatureFromCookies(r *http.Request) string {
	_, authErr := r.Cookie("auth_token")
	if authErr != nil {
		return ""
	}

	var sig string
	for _, cookie := range r.Cookies() {
		if cookie.Name == "MTGBAN" {
			sig = cookie.Value
			break
		}
	}

	querySig := r.FormValue("sig")
	if sig == "" && querySig != "" {
		sig = querySig
	}

	exp := GetParamFromSig(sig, "Expires")
	if exp == "" {
		return ""
	}

	expires, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || expires < time.Now().Unix() {
		return ""
	}

	return sig
}

func recoverPanic(r *http.Request, w http.ResponseWriter) {
	errPanic := recover()
	if errPanic != nil {
		log.Println("panic occurred:", errPanic)

		// Restrict stack size to fit into discord message
		buf := make([]byte, 1<<16)
		n := runtime.Stack(buf, true)
		if n > 1024 {
			buf = buf[:1024]
		}

		var msg string
		err, ok := errPanic.(error)
		if ok {
			msg = err.Error()
		} else {
			msg = fmt.Sprintf("%v", errPanic)
		}

		// Notify server administrators
		ServerNotify("panic", msg, true)
		ServerNotify("panic", string(buf[:n]))
		ServerNotify("panic", "source request: "+r.URL.String())

		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
	}
}
