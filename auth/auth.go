package auth

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

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

// AuthService provides authentication and authorization services
type AuthService struct {
	client   SupabaseClient
	repo     UserRepo
	cache    *UserCache
	logger   *log.Logger
	config   *AuthConfig
	shutdown chan struct{}
	wg       sync.WaitGroup
}

// AuthServiceOption is a functional option for configuring the auth service
type AuthServiceOption func(*AuthService) error

// WithLogger sets a custom logger for the auth service
func WithLogger(logger *log.Logger) AuthServiceOption {
	return func(s *AuthService) error {
		if logger == nil {
			return fmt.Errorf("nil logger provided")
		}
		s.logger = logger
		return nil
	}
}

// WithCache sets a custom cache for the auth service
func WithCache(cache *UserCache) AuthServiceOption {
	return func(s *AuthService) error {
		if cache == nil {
			return fmt.Errorf("nil cache provided")
		}
		s.cache = cache
		return nil
	}
}

// WithRepository sets a custom user repository
func WithRepository(repo UserRepo) AuthServiceOption {
	return func(s *AuthService) error {
		if repo == nil {
			return fmt.Errorf("nil repository provided")
		}
		s.repo = repo
		return nil
	}
}

// NewAuthService creates a new AuthService with options
func NewAuthService(client SupabaseClient, config *AuthConfig, options ...AuthServiceOption) (*AuthService, error) {
	if client == nil {
		return nil, fmt.Errorf("nil client provided")
	}

	if config == nil {
		return nil, fmt.Errorf("nil config provided")
	}

	// Create service with default values
	service := &AuthService{
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
	if config.SBase.RefreshInterval > 0 {
		service.wg.Add(1)
		go service.startPeriodicRefresh()
	}

	service.logger.Printf("Auth service initialized successfully")
	return service, nil
}

// startPeriodicRefresh starts a goroutine that periodically refreshes the cache
func (s *AuthService) startPeriodicRefresh() {
	defer s.wg.Done()

	refreshInterval := s.config.SBase.RefreshInterval
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
func (s *AuthService) RefreshCache(ctx context.Context) error {
	return s.cache.LoadInitialData(ctx, s.repo)
}

// GetUserByID retrieves a user by ID with cache
func (s *AuthService) GetUserByID(ctx context.Context, userID string) (*UserData, error) {
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
func (s *AuthService) GetUserFromContext(ctx context.Context) (*UserData, error) {
	if ctx == nil {
		return nil, fmt.Errorf("nil context")
	}
	// Try to get user directly from context
	return s.cache.GetUserFromContext(ctx)
}

// parseUserData parses UserData from a map
func (s *AuthService) parseUserData(record map[string]interface{}) (*UserData, error) {
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
			if m, ok := v.(map[string]map[string]map[string]string); ok {
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
func (s *AuthService) GetUserFeatures(ctx context.Context, userID string) (map[string]map[string]map[string]string, error) {
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// If features are already loaded, return them
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
func (s *AuthService) CanAccessFeature(user *UserData, feature Feature) bool {
	if user == nil || !feature.IsValid() {
		return false
	}
	featureStr := string(feature)

	return user.HasAccess(FeatureAccess, featureStr)
}

// ApplyAuthVarsToPageVars maps user features to PageVars dynamically
func (s *AuthService) ApplyAuthVarsToPageVars(user *UserData, pageVars map[string]interface{}) {
	if user == nil || pageVars == nil {
		return
	}

	// Set basic user info
	pageVars["UserID"] = user.ID
	pageVars["UserEmail"] = user.Email
	pageVars["UserTier"] = user.Tier
	pageVars["UserRole"] = user.Role

	// Set flag for having any features enabled
	pageVars["HasFeatures"] = user.Features

	// First, map HasAccess for each feature (top-level access)
	for _, feature := range AllFeatures() {
		featureStr := string(feature)
		pageVars["Has"+featureStr] = user.Features[featureStr]
		pageVars["Can"+featureStr] = user.Features[featureStr]
	}

	// Then, dynamically map feature flags
	if user.Features != nil {
		// For each category in Features (Search, Newspaper, etc.)
		for category, features := range user.Features {
			// For each feature set in the category
			for featureSet, settings := range features {
				// For each setting/flag in the feature set
				for flagName, flagValue := range settings {
					// Create different types of keys for the PageVars

					// Full path as key (e.g., "Search.Global.CanDownloadCSV")
					fullPath := category + "." + featureSet + "." + flagName
					pageVars[fullPath] = flagValue

					// Map directly by flag name
					pageVars[flagName] = flagValue

					// Map with Can/Is/Has prefix based on type
					if IsBooleanValue(flagValue) {
						boolValue := (flagValue == "true" || flagValue == "enabled" || flagValue == "yes" || flagValue == "1")

						// Key with proper prefix
						var prefixedKey string
						if strings.HasPrefix(flagName, "Can") || strings.HasPrefix(flagName, "Is") || strings.HasPrefix(flagName, "Has") {
							prefixedKey = flagName
						} else if strings.HasSuffix(flagName, "Enabled") {
							// Convert -> Enabled -> Can
							name := strings.TrimSuffix(flagName, "Enabled")
							prefixedKey = "Can" + name
						} else if strings.HasSuffix(flagName, "Disabled") {
							// Convert -> Disabled -> Can (inverted)
							name := strings.TrimSuffix(flagName, "Disabled")
							prefixedKey = "Can" + name
							// Special case: if the value is "NONE", it means "enabled"
							if flagValue == "NONE" {
								boolValue = true
							} else {
								boolValue = !boolValue
							}
						} else {
							// Convert -> Can
							prefixedKey = "Can" + flagName
						}
						// Set the boolean value with the appropriate key
						pageVars[prefixedKey] = boolValue
					}
				}
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
func (s *AuthService) Shutdown(ctx context.Context) error {
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
