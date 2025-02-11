package cache

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mtgban/mtgban-website/auth/models"
	"github.com/mtgban/mtgban-website/auth/repo"
)

/*
Cache interface defines the methods for the user cache system.
It provides functionality to retrieve, store, and manage user data in the cache.
*/
type Cache interface {
	GetAllUsers() map[string]*models.UserData
	GetUser(userID string) (*models.UserData, error)
	SetUser(user *models.UserData) error
	DeleteUser(userID string) error
	GetLastModified(userID string) time.Time
	GetLastSync() time.Time
	GetUserFromContext(ctx context.Context) (*models.UserData, error)
	UpdateLastSync()
	GetMetrics() (hits uint64, misses uint64)
	LoadInitialData(ctx context.Context, repo repo.UserRepository) error
	Shutdown(ctx context.Context) error
}

// CacheOptions defines the configuration parameters for the user cache system.
// It controls capacity management, schedule cleanup, and token handling behavior.
type CacheOptions struct {
	// Logging configuration
	Logger    *log.Logger
	LogPrefix string
	LogFlags  int

	// Time-based controls
	CleanupInterval time.Duration // How often to run the cleanup routine
	DefaultTTL      time.Duration // Default time-to-live for cache entries
	GracePeriod     time.Duration // Time window after expiry where entries can still be served
	TokenTTL        time.Duration // How long JWT tokens remain valid

	// Performance tuning
	RefreshThreshold   float64       // Load factor at which to trigger early cleanup (0.0-1.0)
	RefreshConcurrency int           // Number of concurrent refresh operations
	BackgroundRefresh  bool          // Whether to refresh entries before they expire
	RefreshBatchSize   int           // Number of entries to refresh in one batch
	RefreshInterval    time.Duration // How often to refresh entries in background

	// Monitoring and metrics
	EnableMetrics      bool          // Whether to collect cache performance metrics
	MetricsBufferSize  int           // Size of metrics history buffer
	AlertThreshold     int           // Number of errors before triggering alerts
	MonitoringInterval time.Duration // How often to collect metrics

	// Security settings
	RequireTokenValidation bool          // Whether to validate tokens on every cache access
	TokenValidationTimeout time.Duration // Maximum time for token validation operations
	AllowStaleData         bool          // Whether to serve expired data during high load
}

type CacheMetrics struct {
	Hits             atomic.Uint64
	Misses           atomic.Uint64
	Evictions        atomic.Uint64
	CapacityWarnings atomic.Uint64
	ExpirationEvents atomic.Uint64
	mu               sync.RWMutex
}

func DefaultCacheOptions() *CacheOptions {
	return &CacheOptions{
		// Core settings
		LogPrefix: "[CACHE] ",
		LogFlags:  log.LstdFlags | log.Lshortfile,

		// Time windows
		CleanupInterval: 10 * time.Minute,
		DefaultTTL:      24 * time.Hour,
		GracePeriod:     5 * time.Minute,
		TokenTTL:        1 * time.Hour,

		// Performance settings
		RefreshThreshold:   0.75,
		RefreshConcurrency: 4,
		BackgroundRefresh:  true,
		RefreshBatchSize:   100,
		RefreshInterval:    15 * time.Minute,

		// Monitoring
		EnableMetrics:      true,
		MetricsBufferSize:  1000,
		AlertThreshold:     50,
		MonitoringInterval: 1 * time.Minute,

		// Security
		RequireTokenValidation: true,
		TokenValidationTimeout: 5 * time.Second,
		AllowStaleData:         false,
	}
}

// ValidateOptions validates the provided cache options and ensures they are configured correctly.
// It checks for valid capacity settings, time windows, and security parameters.
func ValidateOptions(opts *CacheOptions) error {
	if opts == nil {
		return fmt.Errorf("nil options provided")
	}

	// Time window validation
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

	// Performance settings validation
	if opts.RefreshThreshold <= 0 || opts.RefreshThreshold >= 1.0 {
		return fmt.Errorf("refresh threshold must be between 0 and 1")
	}

	if opts.RefreshConcurrency < 1 {
		return fmt.Errorf("refresh concurrency must be at least 1")
	}

	if opts.BackgroundRefresh && opts.RefreshInterval < time.Minute {
		return fmt.Errorf("refresh interval must be at least one minute when background refresh is enabled")
	}

	// Monitoring settings validation
	if opts.EnableMetrics && opts.MetricsBufferSize < 1 {
		return fmt.Errorf("metrics buffer size must be positive when metrics are enabled")
	}

	if opts.MonitoringInterval < time.Second {
		return fmt.Errorf("monitoring interval must be at least one second")
	}

	return nil
}
