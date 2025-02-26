package auth

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

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

var (
	ErrEntryExpired = fmt.Errorf("cache entry has expired")
	ErrInvalidInput = fmt.Errorf("invalid input parameters")
	ErrCacheFull    = fmt.Errorf("cache has reached maximum capacity")
)

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
