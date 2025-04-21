package main

import (
	"errors"
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================================
// Constants and Types
// ============================================================================================

// CacheConfig defines the configuration for the cache
type CacheConfig struct {
	TTL             int    `json:"ttl"`
	CleanupInterval int    `json:"cleanup_interval"`
	MaxSize         int    `json:"max_size"`
	Metrics         string `json:"metrics"`
}

// CacheMetrics defines the metrics for the session cache
type CacheMetrics struct {
	Hits            int64
	Misses          int64
	Evictions       int64
	Size            int64
	LastCleanupTime time.Time
}

// SessionCache is a memory-based cache for user sessions
type SessionCache struct {
	config      CacheConfig
	sessions    map[string]*UserSession
	mutex       sync.RWMutex
	metrics     CacheMetrics
	stopCleanup chan struct{}
}

// Cache interface defines the methods for the cache
type Cache interface {
	Get(userID string) (*UserSession, bool)
	Set(session *UserSession) error
	Delete(userID string)
	Cleanup()
	GetMetrics() CacheMetrics
	Close() error
}

// InitCacheConfig initializes the cache config
func InitCacheConfig(config AuthConfig) CacheConfig {
	cacheConfig := CacheConfig{
		TTL:             config.Cache.TTL,
		CleanupInterval: config.Cache.CleanupInterval,
		MaxSize:         config.Cache.MaxSize,
		Metrics:         config.Cache.Metrics,
	}
	return cacheConfig
}

// NewSessionCache creates a new SessionCache
func NewSessionCache(config CacheConfig) *SessionCache {
	if DebugMode {
		log.Printf("[DEBUG] NewSessionCache called with config: %+v", config)
	}
	// init cache
	cache := &SessionCache{
		config:      config,
		sessions:    make(map[string]*UserSession),
		metrics:     CacheMetrics{},
		stopCleanup: make(chan struct{}),
	}

	if DebugMode {
		log.Printf("[DEBUG] Session cache map created. Initial size: %d", len(cache.sessions))
	}
	// Start background cleanup if interval > 0
	if config.CleanupInterval > 0 {
		if DebugMode {
			log.Printf("[DEBUG] Starting session cache cleanup worker with interval %d seconds", config.CleanupInterval)
		}
		go cache.startCleanupWorker()
	} else if DebugMode {
		log.Printf("[DEBUG] Session cache cleanup worker disabled as CleanupInterval is %d", config.CleanupInterval)
	}
	// return cache
	return cache
}

// startCleanupWorker starts a background goroutine to periodically clean the session cache
func (c *SessionCache) startCleanupWorker() {
	ticker := time.NewTicker(time.Duration(c.config.CleanupInterval) * time.Second)
	defer ticker.Stop()

	if DebugMode {
		log.Printf("[DEBUG] Session cache cleanup worker started.")
	}

	for {
		select {
		case <-ticker.C:
			if DebugMode {
				log.Printf("[DEBUG] Session cache cleanup worker received tick, initiating cleanup.")
			}
			c.Cleanup()
		case <-c.stopCleanup:
			if DebugMode {
				log.Printf("[DEBUG] Session cache cleanup worker received stop signal, exiting.")
			}
			return
		}
	}
}

// Get retrieves a session from the cache by userID
func (c *SessionCache) Get(userID string) (*UserSession, bool) {
	if DebugMode {
		log.Printf("[DEBUG] Session cache Get called for userID: %s", maskID(userID))
	}
	c.mutex.RLock()
	session, found := c.sessions[userID]
	if !found {
		c.mutex.RUnlock()
		atomic.AddInt64(&c.metrics.Misses, 1)
		if DebugMode {
			log.Printf("[DEBUG] Session cache MISS for userID: %s (Not Found)", maskID(userID))
		}
		return nil, false
	}

	// check expiration
	if time.Since(session.LastActive) > time.Duration(c.config.TTL)*time.Second {
		c.mutex.RUnlock()
		if DebugMode {
			log.Printf("[DEBUG] Session cache MISS for userID: %s (Expired, created at %s, TTL %ds)", maskID(userID), session.CreatedAt.Format(time.RFC3339), c.config.TTL)
		}
		// found expired entry, delete and uptick misses
		c.Delete(userID)
		atomic.AddInt64(&c.metrics.Misses, 1)
		return nil, false
	}

	// found and not expired, uptick hits and copy under RLock
	atomic.AddInt64(&c.metrics.Hits, 1)
	sessionCopy := deepCopySession(session)

	c.mutex.RUnlock()

	if DebugMode {
		log.Printf("[DEBUG] Session cache HIT for userID: %s. Session LastActive: %s", maskID(userID), session.LastActive.Format(time.RFC3339))
		// Log session details from the copy
		if sessionCopy != nil && sessionCopy.User != nil {
			log.Printf("[DEBUG] Session details for user %s: Role=%s, Tier=%s", maskEmail(sessionCopy.User.Email), sessionCopy.User.Role, sessionCopy.User.Tier)
		}
		log.Printf("[DEBUG] Session cache returning deep copy for userID: %s", maskID(userID))
	}

	// Update LastActive on the original session in the cache.
	// goroutine to make this non-blocking for the request handler.
	go func(userID string) {
		c.mutex.Lock()
		defer c.mutex.Unlock()
		// Look up again under the write lock in case it was deleted concurrently
		if sessionToUpdate, foundAgain := c.sessions[userID]; foundAgain {
			sessionToUpdate.LastActive = time.Now()
			if DebugMode {
				log.Printf("[DEBUG] Session cache: Updated LastActive for userID: %s to %s", maskID(userID), sessionToUpdate.LastActive.Format(time.RFC3339))
			}
		} else {
			if DebugMode {
				log.Printf("[DEBUG] Session cache: Could not update LastActive for userID: %s - session not found concurrently.", maskID(userID))
			}
		}
	}(userID)

	// return deep copy
	return sessionCopy, true
}

// Set adds a session to the cache
func (c *SessionCache) Set(session *UserSession) error {
	if session == nil || session.UserId == "" {
		if DebugMode {
			log.Printf("[DEBUG] Session cache Set error: Invalid session (nil or empty user ID)")
		}
		return errors.New("invalid session: nil or empty user ID")
	}
	// Get ID before potential deep copy issue
	userID := session.UserId
	if DebugMode {
		log.Printf("[DEBUG] Session cache Set called for userID: %s", maskID(userID))
	}
	// acquire lock
	c.mutex.Lock()
	defer c.mutex.Unlock()

	session.LastActive = time.Now()
	if session.CreatedAt.IsZero() {
		session.CreatedAt = time.Now()
	}
	copiedSession := deepCopySession(session)
	c.sessions[userID] = copiedSession

	if DebugMode {
		log.Printf("[DEBUG] Session cache stored deep copy for userID: %s. Current size: %d", userID, len(c.sessions))
	}
	// update size metric
	c.metrics.Size = int64(len(c.sessions))

	return nil
}

// Delete removes a session from the cache by userID
func (c *SessionCache) Delete(userID string) {
	if DebugMode {
		log.Printf("[DEBUG] Session cache Delete called for userID: %s", userID)
	}
	// acquire lock
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// check if key exists before deleting
	_, exists := c.sessions[userID]
	if exists {
		delete(c.sessions, userID)
		if DebugMode {
			log.Printf("[DEBUG] Session cache removed session for userID: %s. New size: %d", userID, len(c.sessions))
		}
		// update size metric
		c.metrics.Size = int64(len(c.sessions))
		// uptick evictions
		atomic.AddInt64(&c.metrics.Evictions, 1)
	} else {
		if DebugMode {
			log.Printf("[DEBUG] Session cache Delete called for userID: %s, but session was not found.", userID)
		}
	}
}

// Cleanup removes expired sessions and enforces cache size limits
func (c *SessionCache) Cleanup() {
	if DebugMode {
		log.Printf("[DEBUG] Session cache Cleanup started. Current size: %d", len(c.sessions))
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	var evictionCount int64
	initialSize := len(c.sessions)
	now := time.Now()

	// Find and remove expired sessions
	if DebugMode {
		log.Printf("[DEBUG] Session cache Cleanup checking for expired sessions (TTL %ds)...", c.config.TTL)
	}
	for userID, session := range c.sessions {
		// check if expired
		if now.Sub(session.LastActive) > time.Duration(c.config.TTL)*time.Second {
			delete(c.sessions, userID)
			evictionCount++
			if DebugMode {
				log.Printf("[DEBUG] Session cache Cleanup removing expired session for user: %s (LastActive: %s)", maskID(userID), session.LastActive.Format(time.RFC3339))
			}
		}
	}
	if DebugMode {
		log.Printf("[DEBUG] Session cache Cleanup removed %d expired sessions. Current size: %d", evictionCount, len(c.sessions))
	}

	// If still over size limit, remove oldest sessions
	if c.config.MaxSize > 0 && len(c.sessions) > c.config.MaxSize {
		if DebugMode {
			log.Printf("[DEBUG] Session cache Cleanup checking size limit. Current size (%d) exceeds max size (%d).", len(c.sessions), c.config.MaxSize)
		}

		sizeEvictionCount := int64(0)

		// Convert to slice for sorting
		type sessionRecency struct {
			userID     string
			lastActive time.Time
		}

		recencies := make([]sessionRecency, 0, len(c.sessions))
		for id, s := range c.sessions {
			recencies = append(recencies, sessionRecency{id, s.LastActive})
		}

		// Sort by recency (oldest LastActive first)
		sort.Slice(recencies, func(i, j int) bool {
			return recencies[i].lastActive.Before(recencies[j].lastActive)
		})

		// Remove oldest entries until we're under the limit
		sessionsToRemove := len(c.sessions) - c.config.MaxSize
		if sessionsToRemove > 0 {
			for i := 0; i < sessionsToRemove; i++ {
				userIDToRemove := recencies[i].userID
				delete(c.sessions, userIDToRemove)
				evictionCount++ // Total evictions
				sizeEvictionCount++
				if DebugMode {
					log.Printf("[DEBUG] Session cache Cleanup removing oldest session for user: %s (LastActive: %s) due to size limit.", maskID(userIDToRemove), recencies[i].lastActive.Format(time.RFC3339))
				}
			}
		}

		if DebugMode {
			log.Printf("[DEBUG] Session cache Cleanup removed %d sessions due to size limit. Current size: %d", sizeEvictionCount, len(c.sessions))
		}
	} else if c.config.MaxSize > 0 && DebugMode {
		log.Printf("[DEBUG] Session cache Cleanup size (%d) is within limit (%d). No size evictions needed.", len(c.sessions), c.config.MaxSize)
	} else if c.config.MaxSize <= 0 && DebugMode {
		log.Printf("[DEBUG] Session cache Cleanup size limit check skipped as MaxSize is %d", c.config.MaxSize)
	}

	// update metrics
	atomic.AddInt64(&c.metrics.Evictions, evictionCount)
	c.metrics.Size = int64(len(c.sessions))
	c.metrics.LastCleanupTime = now

	if DebugMode {
		log.Printf("[DEBUG] Session cache Cleanup finished. Initial size: %d, Final size: %d, Total evictions: %d", initialSize, len(c.sessions), evictionCount)
	}
}

// GetMetrics returns the current cache metrics
func (c *SessionCache) GetMetrics() CacheMetrics {
	metrics := CacheMetrics{
		Hits:            atomic.LoadInt64(&c.metrics.Hits),
		Misses:          atomic.LoadInt64(&c.metrics.Misses),
		Evictions:       atomic.LoadInt64(&c.metrics.Evictions),
		Size:            atomic.LoadInt64(&c.metrics.Size),
		LastCleanupTime: c.metrics.LastCleanupTime,
	}
	if DebugMode {
		log.Printf("[DEBUG] Session cache GetMetrics called. Metrics: %+v", metrics)
	}
	return metrics
}

// Close closes the session cache
func (c *SessionCache) Close() error {
	if DebugMode {
		log.Printf("[DEBUG] Session cache Close called.")
	}
	if c.stopCleanup != nil {
		close(c.stopCleanup) // Signal the worker to stop
		if DebugMode {
			log.Printf("[DEBUG] Session cache cleanup worker stop signal sent.")
		}
	}

	c.mutex.Lock()
	c.sessions = nil // Dereference the map
	c.mutex.Unlock()

	if DebugMode {
		log.Printf("[DEBUG] Session cache map set to nil. Cache closed.")
	}
	return nil
}

// deepCopySession creates a deep copy of a UserSession
func deepCopySession(src *UserSession) *UserSession {
	if src == nil {
		return nil
	}
	// shallow copy struct fields
	copied := *src

	// deep copy pointer fields
	var tokensCopy *AuthTokens
	if src.Tokens != nil {
		tokensCopy = &AuthTokens{
			CSRFToken: src.Tokens.CSRFToken,
		}
		if src.Tokens.AccessToken != nil {
			tokensCopy.AccessToken = &AccessToken{
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
		copied.Tokens = tokensCopy
	} else {
		copied.Tokens = nil
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
		copied.User = userCopy
	} else {
		copied.User = nil
	}

	// Copy permissions
	permsCopy := make(map[string]interface{}, len(src.Permissions))
	for k, v := range src.Permissions {
		permsCopy[k] = v
	}
	copied.Permissions = permsCopy

	// Copy metadata
	metaCopy := make(map[string]interface{}, len(src.Metadata))
	for k, v := range src.Metadata {
		metaCopy[k] = v
	}
	copied.Metadata = metaCopy

	return &copied
}
