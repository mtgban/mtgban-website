package main

import (
	"container/list"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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

// Cache interface defines the methods for the cache
type Cache interface {
	Get(userID string) (*UserSession, bool)
	Set(session *UserSession) error
	Delete(userID string)
	Cleanup()
	GetMetrics() CacheMetrics
	Close() error
}

// SessionCache is a memory-based cache for user sessions
type SessionCache struct {
	config        CacheConfig
	sessions      map[string]*list.Element
	sessionsList  *list.List
	mutex         sync.RWMutex
	metrics       CacheMetrics
	cleanerStop   chan struct{}
	cleanerActive atomic.Bool
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
		config:       config,
		sessions:     make(map[string]*list.Element),
		sessionsList: list.New(),
		metrics:      CacheMetrics{},
		cleanerStop:  make(chan struct{}),
	}
	// initialize cleaner paused
	cache.cleanerActive.Store(false)

	if DebugMode {
		log.Printf("[DEBUG] Session cache map created. Initial size: %d", len(cache.sessions))
	}

	return cache
}

// startCleanupWorker starts a background goroutine to periodically clean the session cache
func (c *SessionCache) startCleaner() {
	// mark active
	c.cleanerActive.Store(true)

	// create ticker
	ticker := time.NewTicker(time.Duration(c.config.CleanupInterval) * time.Second)
	defer ticker.Stop()
	// mark inactive on exit
	defer c.cleanerActive.Store(false)

	// start cleaner loop
	for {
		select {
		case <-ticker.C:
			// check if cache is empty
			c.mutex.RLock()
			cacheSize := len(c.sessions)
			c.mutex.RUnlock()

			if cacheSize >= 1 {
				if DebugMode {
					log.Printf("[DEBUG] Initiating Session cache cleaner")
				}
				// perform cleanup
				c.Cleanup()
				// reset pause
			} else {
				if DebugMode {
					log.Printf("[DEBUG] Cache is empty, stopping cleaner")
				}
				// exit goroutine
				return
			}
		case <-c.cleanerStop:
			if DebugMode {
				log.Printf("[DEBUG] Cache cleaner received stop signal")
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
	element, found := c.sessions[userID]
	if !found {
		c.mutex.RUnlock()
		atomic.AddInt64(&c.metrics.Misses, 1)
		if DebugMode {
			log.Printf("[DEBUG] Session cache MISS for userID: %s (Not Found)", maskID(userID))
		}
		return nil, false
	}

	session := element.Value.(*UserSession)

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
	// Deep copy under RLock
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

	// Update recency (move to front of list) and LastActive
	go func(userID string) {
		c.mutex.Lock()
		defer c.mutex.Unlock()
		// Look up again under the write lock in case it was deleted concurrently
		if elementToUpdate, foundAgain := c.sessions[userID]; foundAgain {
			sessionToUpdate := elementToUpdate.Value.(*UserSession)
			if time.Since(sessionToUpdate.LastActive) <= time.Duration(c.config.TTL)*time.Second {
				c.sessionsList.MoveToFront(elementToUpdate)
				sessionToUpdate.LastActive = time.Now()
				if DebugMode {
					log.Printf("[DEBUG] Session cache: Updated LastActive for userID: %s to %s", maskID(userID), sessionToUpdate.LastActive.Format(time.RFC3339))
				}
			} else {
				if DebugMode {
					log.Printf("[DEBUG] Session cache: TTL expired for userID: %s - skipping update", maskID(userID))
				}
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

	startCleaner := len(c.sessions) == 0 && !c.cleanerActive.Load() && c.config.CleanupInterval > 0

	// Update session
	session.LastActive = time.Now()
	if session.CreatedAt.IsZero() {
		session.CreatedAt = time.Now()
	}
	copiedSession := deepCopySession(session)

	if element, found := c.sessions[userID]; found {
		// Update existing element's value and move to front
		element.Value = copiedSession
		c.sessionsList.MoveToFront(element)
		if DebugMode {
			log.Printf("[DEBUG] Session cache: Updated LastActive for userID: %s to %s", maskID(userID), session.LastActive.Format(time.RFC3339))
		}
	} else {
		// Add new element to list and map
		element = c.sessionsList.PushFront(copiedSession)
		c.sessions[userID] = element
		if DebugMode {
			log.Printf("[DEBUG] Session cache added new session for userID: %s. Current size: %d", userID, len(c.sessions))
		}

		// Add item then check size limit
		if c.config.MaxSize > 0 && c.sessionsList.Len() > c.config.MaxSize {
			if DebugMode {
				log.Printf("[DEBUG] Session cache size (%d) exceeds limit (%d). Evicting oldest.", c.sessionsList.Len(), c.config.MaxSize)
			}
			// Remove rear elements until size limit is met
			for c.sessionsList.Len() > c.config.MaxSize {
				// Get oldest element
				oldestElement := c.sessionsList.Back()
				if oldestElement == nil { // shouldn't happen if Len() > 0
					break
				}
				// Remove from list and get value
				sessionToRemove := c.sessionsList.Remove(oldestElement).(*UserSession)
				delete(c.sessions, sessionToRemove.UserId) // Remove from map
				atomic.AddInt64(&c.metrics.Evictions, 1)   // uptick evictions
				if DebugMode {
					log.Printf("[DEBUG] Session cache evicted oldest session for user: %s due to size limit.", maskID(sessionToRemove.UserId))
				}
			}
			if DebugMode {
				log.Printf("[DEBUG] Session cache size after size eviction: %d", c.sessionsList.Len())
			}
		}
	}

	// Update size metric
	c.metrics.Size = int64(c.sessionsList.Len())

	if startCleaner {
		if DebugMode {
			log.Printf("[DEBUG] Session cache cleaner started")
		}
		go c.startCleaner()
	}

	return nil
}

// Close closes the session cache
func (c *SessionCache) Close() error {
	if DebugMode {
		log.Printf("[DEBUG] Session cache Close called")
	}

	// Signal cleaner to stop if active
	if c.cleanerActive.Load() {
		close(c.cleanerStop)
		if DebugMode {
			log.Printf("[DEBUG] Session cache cleanup worker stop signal sent")
		}
	}

	c.mutex.Lock()
	c.sessions = nil     // Dereference the map
	c.sessionsList = nil // Dereference the list
	c.mutex.Unlock()

	if DebugMode {
		log.Printf("[DEBUG] Session cache map set to nil. Cache closed")
	}
	return nil
}

// Delete method should now check if the cache becomes empty
func (c *SessionCache) Delete(userID string) {
	if DebugMode {
		log.Printf("[DEBUG] Session cache Delete called for userID: %s", userID)
	}
	// Acquire lock
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Check if key exists in the map
	if element, found := c.sessions[userID]; found {
		// Remove from map and list
		delete(c.sessions, userID)
		c.sessionsList.Remove(element)
		if DebugMode {
			log.Printf("[DEBUG] Session cache removed session for userID: %s. New size: %d", userID, len(c.sessions))
		}
		// Update size metric
		c.metrics.Size = int64(c.sessionsList.Len())
		// Uptick evictions
		atomic.AddInt64(&c.metrics.Evictions, 1)
	} else {
		if DebugMode {
			log.Printf("[DEBUG] Session cache Delete called for userID: %s, but session was not found", userID)
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
	initialSize := c.sessionsList.Len() // get list size
	now := time.Now()

	// Find and remove expired sessions
	if DebugMode {
		log.Printf("[DEBUG] Session cache Cleanup checking for expired sessions (TTL %ds)...", c.config.TTL)
	}

	// Iterate over list elements
	elementsToRemove := []*list.Element{}
	for e := c.sessionsList.Front(); e != nil; e = e.Next() {
		session := e.Value.(*UserSession)
		if now.Sub(session.LastActive) > time.Duration(c.config.TTL)*time.Second {
			elementsToRemove = append(elementsToRemove, e)
		}
	}

	// Remove expired sessions
	for _, e := range elementsToRemove {
		sessionsToRemove := c.sessionsList.Remove(e).(*UserSession)
		delete(c.sessions, sessionsToRemove.UserId)
		evictionCount++
		if DebugMode {
			log.Printf("[DEBUG] Session cache Cleanup removing expired session for user: %s (LastActive: %s)", maskID(sessionsToRemove.UserId), sessionsToRemove.LastActive.Format(time.RFC3339))
		}
	}

	// Update size metric
	if DebugMode {
		log.Printf("[DEBUG] Session cache Cleanup removed %d expired sessions. Current size: %d", evictionCount, len(c.sessions))
	}

	// If still over size limit, remove oldest sessions
	if c.config.MaxSize > 0 && c.sessionsList.Len() > c.config.MaxSize {
		if DebugMode {
			log.Printf("[DEBUG] Session cache Cleanup checking size limit. Current size (%d) exceeds max size (%d).", len(c.sessions), c.config.MaxSize)
		}

		sizeEvictionCount := int64(0)
		sessionsToRemove := c.sessionsList.Len() - c.config.MaxSize

		if sessionsToRemove > 0 {
			for i := 0; i < sessionsToRemove; i++ {
				oldestElement := c.sessionsList.Back()
				if oldestElement == nil {
					break
				}
				sessionToRemove := c.sessionsList.Remove(oldestElement).(*UserSession)
				delete(c.sessions, sessionToRemove.UserId)
				evictionCount++
				sizeEvictionCount++
				if DebugMode {
					log.Printf("[DEBUG] Session cache Cleanup removing oldest session for user: %s (LastActive: %s) due to size limit.", maskID(sessionToRemove.UserId), sessionToRemove.LastActive.Format(time.RFC3339))
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
	c.metrics.Size = int64(c.sessionsList.Len())
	c.metrics.LastCleanupTime = now

	if DebugMode {
		log.Printf("[DEBUG] Session cache Cleanup finished. Initial size: %d, Final size: %d, Total evictions: %d", initialSize, len(c.sessions), evictionCount)
	}
}

// GetMetrics returns the current cache metrics
func (c *SessionCache) GetMetrics() CacheMetrics {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	metrics := CacheMetrics{
		Hits:            atomic.LoadInt64(&c.metrics.Hits),
		Misses:          atomic.LoadInt64(&c.metrics.Misses),
		Evictions:       atomic.LoadInt64(&c.metrics.Evictions),
		Size:            c.metrics.Size,
		LastCleanupTime: c.metrics.LastCleanupTime,
	}
	if DebugMode {
		log.Printf("[DEBUG] Session cache GetMetrics called. Metrics: %+v", metrics)
	}
	return metrics
}

// ExportMetricsToJson writes the current cache metrics as JSON to the provided writer.
func (c *SessionCache) ExportMetricsToJson(w io.Writer) error {
	metrics := c.GetMetrics() // Get metrics

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	err := encoder.Encode(metrics)
	if err != nil {
		log.Printf("[ERROR] Session cache ExportMetricsToJson failed to encode metrics: %v", err)
		return fmt.Errorf("failed to encode metrics: %w", err)
	}
	if DebugMode {
		log.Printf("[DEBUG] Session cache ExportMetricsToJson successfully wrote metrics")
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
