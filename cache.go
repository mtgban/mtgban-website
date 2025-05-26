package main

import (
	"container/list"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"maps"

	"github.com/the-muppet/supabase-go"
)

type UserPerms map[string]map[string]any

var supabaseClient *supabase.Client
var sessionCache *SessionCache

type UserSession struct {
	Id           string
	Email        string
	Role         string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	Signature    string
	CreatedAt    time.Time
	LastActive   time.Time
	Permissions  UserPerms
}

type CacheMetrics struct {
	Hits            int64
	Misses          int64
	Evictions       int64
	Size            int64
	LastCleanupTime time.Time
}

type CacheConfig struct {
	TTL             int
	CleanupInterval int
	MaxSize         int
	DevMode         bool
}

type SessionCache struct {
	Config       CacheConfig
	sessions     map[string]*list.Element
	sessionsList *list.List
	mutex        sync.RWMutex
	metrics      CacheMetrics
	cleanerStop  chan struct{}
	cleanerWg    sync.WaitGroup
}

type DBConfig struct {
	Url            string `json:"url"`
	AnonKey        string `json:"anon_key"`
	RoleKey        string `json:"role_key"`
	WebhookEnabled bool   `json:"webhook_enabled"`
}

func getSupabaseClient() *supabase.Client {
	client := supabase.CreateClient(Config.Auth.DB.Url, Config.Auth.DB.RoleKey)
	if client == nil {
		log.Fatal("Failed to create Supabase client")
	}
	return client
}

func getUserClient() *supabase.Client {
	client := supabase.CreateClient(Config.Auth.DB.Url, Config.Auth.DB.AnonKey)
	if client == nil {
		log.Fatal("Failed to create Supabase client")
	}
	return client
}

// NewSessionCache creates a new cache instance
func NewSessionCache(Config CacheConfig) *SessionCache {
	if Config.DevMode {
		log.Printf("[DEBUG] Creating new session cache with Config: %+v", Config)
	}

	cache := &SessionCache{
		Config:       Config,
		sessions:     make(map[string]*list.Element),
		sessionsList: list.New(),
		metrics:      CacheMetrics{},
		cleanerStop:  make(chan struct{}),
	}

	if Config.CleanupInterval > 0 {
		cache.cleanerWg.Add(1)
		go cache.startCleaner()
		if Config.DevMode {
			log.Printf("[DEBUG] Started session cache cleaner with interval: %d seconds", Config.CleanupInterval)
		}
	}

	return cache
}

func (c *SessionCache) startCleaner() {
	defer c.cleanerWg.Done()

	if c.Config.CleanupInterval <= 0 {
		if c.Config.DevMode {
			log.Printf("[DEBUG] Cache cleaner exiting due to invalid interval: %d", c.Config.CleanupInterval)
		}
		return
	}

	ticker := time.NewTicker(time.Duration(c.Config.CleanupInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.Cleanup()
		case <-c.cleanerStop:
			if c.Config.DevMode {
				log.Println("[DEBUG] Cache cleaner received stop signal")
			}
			return
		}
	}
}

func (c *SessionCache) Get(userID string) (*UserSession, bool) {
	if c.Config.DevMode {
		log.Printf("[DEBUG] Session cache Get called for userID: %s", maskID(userID))
	}

	c.mutex.RLock()
	element, ok := c.sessions[userID]
	if !ok {
		c.mutex.RUnlock()
		atomic.AddInt64(&c.metrics.Misses, 1)
		return nil, false
	}

	session := element.Value.(*UserSession)

	if time.Since(session.LastActive) > time.Duration(c.Config.TTL)*time.Second {
		c.mutex.RUnlock()
		go c.Delete(userID)
		atomic.AddInt64(&c.metrics.Misses, 1)
		return nil, false
	}

	sessionCopy := deepCopySession(session)
	c.mutex.RUnlock()

	go func(userID string) {
		c.mutex.Lock()
		defer c.mutex.Unlock()

		if element, found := c.sessions[userID]; found {
			session := element.Value.(*UserSession)
			c.sessionsList.MoveToFront(element)
			session.LastActive = time.Now()
		}
	}(userID)

	atomic.AddInt64(&c.metrics.Hits, 1)
	return sessionCopy, true
}

func (c *SessionCache) Set(session *UserSession) error {
	if session == nil || session.Id == "" {
		return fmt.Errorf("session or session ID cannot be empty")
	}

	if c.Config.DevMode {
		log.Printf("[DEBUG] Session cache Set called for userID: %s", maskID(session.Id))
	}

	now := time.Now()
	session.LastActive = now
	if session.CreatedAt.IsZero() {
		session.CreatedAt = now
	}

	sessionCopy := deepCopySession(session)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if element, found := c.sessions[session.Id]; found {
		element.Value = sessionCopy
		c.sessionsList.MoveToFront(element)
	} else {
		element := c.sessionsList.PushFront(sessionCopy)
		c.sessions[session.Id] = element

		if c.Config.MaxSize > 0 && c.sessionsList.Len() > c.Config.MaxSize {
			c.evictOldest()
		}
	}

	c.metrics.Size = int64(c.sessionsList.Len())
	return nil
}

func (c *SessionCache) evictOldest() {
	for c.sessionsList.Len() > c.Config.MaxSize {
		oldest := c.sessionsList.Back()
		if oldest == nil {
			break
		}

		session := c.sessionsList.Remove(oldest).(*UserSession)
		delete(c.sessions, session.Id)
		atomic.AddInt64(&c.metrics.Evictions, 1)

		if c.Config.DevMode {
			log.Printf("[DEBUG] Evicted oldest session for userID: %s", maskID(session.Id))
		}
	}
}

func (c *SessionCache) Delete(userID string) {
	if c.Config.DevMode {
		log.Printf("[DEBUG] Session cache Delete called for userID: %s", maskID(userID))
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if element, found := c.sessions[userID]; found {
		delete(c.sessions, userID)
		c.sessionsList.Remove(element)
		atomic.AddInt64(&c.metrics.Evictions, 1)
		c.metrics.Size = int64(c.sessionsList.Len())
	}
}

func (c *SessionCache) Cleanup() {
	if c.Config.DevMode {
		log.Printf("[DEBUG] Session cache Cleanup started")
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	ttlDuration := time.Duration(c.Config.TTL) * time.Second

	var evictionCount int64
	elementsToRemove := []*list.Element{}

	for e := c.sessionsList.Front(); e != nil; e = e.Next() {
		session := e.Value.(*UserSession)
		if now.Sub(session.LastActive) > ttlDuration {
			elementsToRemove = append(elementsToRemove, e)
		}
	}

	for _, e := range elementsToRemove {
		session := c.sessionsList.Remove(e).(*UserSession)
		delete(c.sessions, session.Id)
		evictionCount++

		if c.Config.DevMode {
			log.Printf("[DEBUG] Removed expired session for userID: %s", maskID(session.Id))
		}
	}

	if c.Config.MaxSize > 0 && c.sessionsList.Len() > c.Config.MaxSize {
		oldestToRemove := c.sessionsList.Len() - c.Config.MaxSize
		for i := 0; i < oldestToRemove; i++ {
			oldest := c.sessionsList.Back()
			if oldest == nil {
				break
			}

			session := c.sessionsList.Remove(oldest).(*UserSession)
			delete(c.sessions, session.Id)
			evictionCount++

			if c.Config.DevMode {
				log.Printf("[DEBUG] Removed oldest session for userID: %s due to size limit", maskID(session.Id))
			}
		}
	}

	atomic.AddInt64(&c.metrics.Evictions, evictionCount)
	c.metrics.Size = int64(c.sessionsList.Len())
	c.metrics.LastCleanupTime = now

	if c.Config.DevMode {
		log.Printf("[DEBUG] Cleanup finished. Removed %d sessions. Current size: %d", evictionCount, c.sessionsList.Len())
	}
}

func (c *SessionCache) Close() error {
	if c.Config.DevMode {
		log.Printf("[DEBUG] Closing session cache")
	}

	close(c.cleanerStop)
	c.cleanerWg.Wait()

	c.mutex.Lock()
	c.sessions = nil
	c.sessionsList = nil
	c.mutex.Unlock()

	return nil
}

func (c *SessionCache) GetMetrics() CacheMetrics {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return CacheMetrics{
		Hits:            atomic.LoadInt64(&c.metrics.Hits),
		Misses:          atomic.LoadInt64(&c.metrics.Misses),
		Evictions:       atomic.LoadInt64(&c.metrics.Evictions),
		Size:            c.metrics.Size,
		LastCleanupTime: c.metrics.LastCleanupTime,
	}
}

func (c *SessionCache) StoreSupabaseSession(authResponse map[string]any) (*UserSession, error) {
	user, ok := authResponse["user"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("user data not found in auth response")
	}

	userID, _ := user["id"].(string)
	email, _ := user["email"].(string)
	role, _ := user["role"].(string)

	if userID == "" {
		return nil, fmt.Errorf("user ID not found in auth response")
	}

	accessToken, _ := authResponse["access_token"].(string)
	refreshToken, _ := authResponse["refresh_token"].(string)
	expiresIn, _ := authResponse["expires_in"].(float64)

	var signature string
	if appMetadata, ok := user["app_metadata"].(map[string]any); ok {
		if sig, ok := appMetadata["sig"].(string); ok {
			signature = sig
		}
	}

	expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second)

	session := &UserSession{
		Id:           userID,
		Email:        email,
		Role:         role,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		Signature:    signature,
		CreatedAt:    time.Now(),
		LastActive:   time.Now(),
		Permissions:  make(UserPerms),
	}

	if signature != "" {
		permissions, err := decodeAndParseSignature(signature)
		if err == nil {
			session.Permissions = permissions
		}
	}

	// Store in cache
	err := c.Set(session)
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (c *SessionCache) GetUserPermissions(userID string) (UserPerms, bool) {
	session, found := c.Get(userID)
	if !found {
		return nil, false
	}

	return session.Permissions, true
}

// deepCopySession creates a deep copy of a UserSession
func deepCopySession(src *UserSession) *UserSession {
	if src == nil {
		return nil
	}

	// Copy basic fields
	dst := &UserSession{
		Id:           src.Id,
		Email:        src.Email,
		Role:         src.Role,
		AccessToken:  src.AccessToken,
		RefreshToken: src.RefreshToken,
		ExpiresAt:    src.ExpiresAt,
		Signature:    src.Signature,
		CreatedAt:    src.CreatedAt,
		LastActive:   src.LastActive,
		Permissions:  make(UserPerms),
	}

	// Deep copy permissions
	if src.Permissions != nil {
		for k, v := range src.Permissions {
			if v != nil {
				dst.Permissions[k] = make(map[string]any)
				maps.Copy(dst.Permissions[k], v)
			}
		}
	}

	return dst
}

func decodeAndParseSignature(signature string) (UserPerms, error) {
	// Clean the signature by removing line breaks
	cleanSig := strings.ReplaceAll(strings.ReplaceAll(signature, "\n", ""), "\r", "")

	// Decode from base64
	decodedBytes, err := base64.StdEncoding.DecodeString(cleanSig)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %v", err)
	}

	decodedSig := string(decodedBytes)

	// signature format is "email:permissions:timestamp"
	parts := strings.SplitN(decodedSig, ":", 3)

	permissions := make(UserPerms)
	if len(parts) >= 2 {
		permJson := parts[1]
		err := json.Unmarshal([]byte(permJson), &permissions)
		if err != nil {
			return nil, fmt.Errorf("failed to parse permissions JSON: %v", err)
		}
	}

	return permissions, nil
}

func maskID(id string) string {
	if len(id) <= 8 {
		return "****"
	}
	return id[:4] + "****" + id[len(id)-4:]
}
