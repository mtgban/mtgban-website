package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mtgban/mtgban-website/auth"
)

// Common errors
var (
	ErrEmptyToken     = errors.New("empty token")
	ErrInvalidToken   = errors.New("invalid token")
	ErrForbidden      = errors.New("insufficient permissions")
	ErrRateLimited    = errors.New("rate limit exceeded")
	ErrMissingUser    = errors.New("user not found in context")
	ErrInvalidContext = errors.New("invalid context data")

	// Default timeout for auth operations
	AuthTimeout = 5 * time.Second
)

// MiddlewareConfig holds configuration for middlewares
type MiddlewareConfig struct {
	AuthService        *auth.AuthService
	DevMode            bool
	SkipSignatureCheck bool
	JWTSecret          string
	RequestsPerSecond  int
	Logger             *log.Logger
}

// NewMiddlewareConfig creates a middleware configuration
func NewMiddlewareConfig(authService *auth.AuthService) *MiddlewareConfig {
	return &MiddlewareConfig{
		AuthService:        authService,
		DevMode:            os.Getenv("DEV_MODE") == "true",
		SkipSignatureCheck: os.Getenv("SKIP_SIG_CHECK") == "true",
		JWTSecret:          os.Getenv("SUPABASE_JWT_SECRET"),
		Logger:             log.New(os.Stdout, "[MIDDLEWARE] ", log.LstdFlags),
	}
}

// recoverMiddleware handles panic recovery
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("Panic recovered in middleware: %v", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// APIAuthMiddleware handles authentication for API endpoints
func (cfg *MiddlewareConfig) APIAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set API headers
		w.Header().Add("RateLimit-Limit", fmt.Sprint(cfg.RequestsPerSecond))
		w.Header().Add("Content-Type", "application/json")

		// Extract token
		token := extractToken(r)
		if token == "" {
			http.Error(w, `{"error":"missing token"}`, http.StatusUnauthorized)
			return
		}

		// Create context with timeout
		ctx, cancel := context.WithTimeout(r.Context(), AuthTimeout)
		defer cancel()

		// Get user from token
		user, err := getUserFromToken(ctx, cfg.AuthService, token, cfg.JWTSecret)
		if err != nil {
			http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
			return
		}

		// Check API access permission
		if !user.HasAccess(auth.RoleAccess, auth.TierAPI) {
			http.Error(w, `{"error":"insufficient permissions"}`, http.StatusForbidden)
			return
		}

		// Set API mode flag
		ctx = context.WithValue(ctx, "APImode", true)

		// Add user to context
		ctx = context.WithValue(ctx, auth.UserContextKey, user)

		// Continue with the enhanced context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// FeatureAccessMiddleware restricts access to specific features
func (cfg *MiddlewareConfig) FeatureAccessMiddleware(feature string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip check in dev mode
			if cfg.DevMode && !cfg.SkipSignatureCheck {
				next.ServeHTTP(w, r)
				return
			}

			// Check if feature has NoAuth flag set
			if nav, exists := ExtraNavs[feature]; exists && nav.NoAuth {
				next.ServeHTTP(w, r)
				return
			}

			// Get user from context
			ctx := r.Context()
			userObj := ctx.Value(auth.UserContextKey)
			if userObj == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			user, ok := userObj.(*auth.UserData)
			if !ok || user == nil {
				http.Error(w, "Invalid user data", http.StatusInternalServerError)
				return
			}

			if !user.HasAccess(auth.RoleAccess, auth.Role(feature)) {
				http.Error(w, "Access denied", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// WithAuth wrapper for API and FeatureAccessMiddleware
func (cfg *MiddlewareConfig) WithAuth(feature string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := recoverMiddleware(next)

		if strings.HasPrefix(feature, "API") {
			return cfg.APIAuthMiddleware(handler)
		}

		return cfg.FeatureAccessMiddleware(feature)(handler)
	}
}

// getUserFromToken validates a JWT token and retrieves the associated user
func getUserFromToken(ctx context.Context, authService *auth.AuthService, tokenString, jwtSecret string) (*auth.UserData, error) {
	if tokenString == "" {
		return nil, ErrEmptyToken
	}

	// Parse and validate JWT
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: invalid claims format", ErrInvalidToken)
	}

	// Get user ID from subject claim
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return nil, fmt.Errorf("%w: missing subject", ErrInvalidToken)
	}

	// Get user from cache using ID from token
	user, err := authService.GetUserByID(ctx, sub)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	return user, nil
}
