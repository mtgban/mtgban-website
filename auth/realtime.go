package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	_ "github.com/lib/pq"
)

// Resource represents a protectable resource
type Resource struct {
	Type string
	ID   string
}

// UserPermissions contains a user's complete permission set
type UserPermissions struct {
	UserID    string
	Email     string
	Role      string
	Tier      string
	Status    string
	Features  map[string]interface{}
	Resources map[string][]string
	RawData   map[string]interface{}
}

// WebsocketManager handles websocket connections and broadcasts
type WebsocketManager struct {
	clients       map[*websocket.Conn]string // map of connections to user IDs
	clientsMutex  sync.RWMutex
	upgrader      websocket.Upgrader
	logger        *log.Logger
	authVerifier  func(string) (string, error) // Function to verify auth tokens
	subscriptions map[string][]*websocket.Conn // map of user IDs to connections
	subsMutex     sync.RWMutex
}

// PermissionMessage represents a permission change message
type PermissionMessage struct {
	Type      string      `json:"type"`
	UserID    string      `json:"user_id"`
	TableName string      `json:"table_name"`
	Data      interface{} `json:"data"`
}

// Config holds configuration for the AuthServer
type Config struct {
	DB               *sql.DB
	JWTSecret        string
	Logger           *log.Logger
	CacheTTL         time.Duration
	RealtimeCallback func(userID string) // Optional callback when permissions change
}

// NewWebsocketManager creates a new websocket manager
func NewWebsocketManager(logger *log.Logger, client SupabaseClient) *WebsocketManager {
	if logger == nil {
		logger = log.New(log.Writer(), "[WS] ", log.LstdFlags)
	}

	if client == nil {
		logger.Println("WARNING: Supabase client is nil, websocket notifications will not work")
	}

	return &WebsocketManager{
		clients:       make(map[*websocket.Conn]string),
		subscriptions: make(map[string][]*websocket.Conn),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
		logger: log.New(log.Writer(), "[WSKT] ", log.LstdFlags),
	}
}

// WebsocketHandler handles websocket connections
func (wm *WebsocketManager) WebsocketHandler(w http.ResponseWriter, r *http.Request) {
	// Extract token for authentication
	token := ExtractToken(r)
	if token == "" {
		http.Error(w, "Unauthorized - no token provided", http.StatusUnauthorized)
		return
	}

	// Verify token and get user ID
	userID, err := wm.authVerifier(token)
	if err != nil {
		http.Error(w, "Unauthorized - invalid token", http.StatusUnauthorized)
		return
	}

	// Upgrade HTTP connection to WebSocket
	conn, err := wm.upgrader.Upgrade(w, r, nil)
	if err != nil {
		wm.logger.Printf("Error upgrading to websocket: %v", err)
		return
	}

	// Register the new client
	wm.clientsMutex.Lock()
	wm.clients[conn] = userID
	wm.clientsMutex.Unlock()

	// Register subscription for the user
	wm.subsMutex.Lock()
	if _, exists := wm.subscriptions[userID]; !exists {
		wm.subscriptions[userID] = make([]*websocket.Conn, 0)
	}
	wm.subscriptions[userID] = append(wm.subscriptions[userID], conn)
	wm.subsMutex.Unlock()

	wm.logger.Printf("New websocket connection for user %s", userID)

	// Handle client messages and disconnection
	go wm.handleConnection(conn, userID)
}

// handleConnection processes messages from the client and handles disconnection
func (wm *WebsocketManager) handleConnection(conn *websocket.Conn, userID string) {
	defer func() {
		// Remove client on disconnect
		wm.clientsMutex.Lock()
		delete(wm.clients, conn)
		wm.clientsMutex.Unlock()

		// Remove from subscriptions
		wm.subsMutex.Lock()
		conns := wm.subscriptions[userID]
		for i, c := range conns {
			if c == conn {
				// Remove this connection from the slice
				wm.subscriptions[userID] = append(conns[:i], conns[i+1:]...)
				break
			}
		}
		// If no connections left for this user, clean up the map entry
		if len(wm.subscriptions[userID]) == 0 {
			delete(wm.subscriptions, userID)
		}
		wm.subsMutex.Unlock()

		// Close the connection
		conn.Close()
		wm.logger.Printf("Websocket connection closed for user %s", userID)
	}()

	// Set read deadline and pong handler for keepalive
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	// Send a welcome message
	welcomeMsg := PermissionMessage{
		Type:   "connected",
		UserID: userID,
		Data:   map[string]interface{}{"message": "Connected to permissions service"},
	}
	err := conn.WriteJSON(welcomeMsg)
	if err != nil {
		wm.logger.Printf("Error sending welcome message: %v", err)
		return
	}

	// Simple message handler - just to keep the connection alive
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
		// Reset read deadline when we receive any message
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	}
}

// NotifyPermissionChange notifies a user about permission changes
func (wm *WebsocketManager) NotifyPermissionChange(userID, tableName string, data interface{}) {
	msg := PermissionMessage{
		Type:      "permission_change",
		UserID:    userID,
		TableName: tableName,
		Data:      data,
	}

	// Send to all connections for this user
	wm.subsMutex.RLock()
	conns, exists := wm.subscriptions[userID]
	wm.subsMutex.RUnlock()

	if !exists || len(conns) == 0 {
		return
	}

	for _, conn := range conns {
		err := conn.WriteJSON(msg)
		if err != nil {
			wm.logger.Printf("Error sending message to user %s: %v", userID, err)
			// Connection might be bad, but we'll let the read handler clean it up
		}
	}

	wm.logger.Printf("Notified user %s of permission change in %s", userID, tableName)
}

// StartPingService starts a goroutine that pings all clients periodically
func (wm *WebsocketManager) StartPingService(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				// Send ping to all clients
				wm.clientsMutex.RLock()
				for conn := range wm.clients {
					err := conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(10*time.Second))
					if err != nil {
						// If ping fails, the connection might be bad
						continue
					}
				}
				wm.clientsMutex.RUnlock()
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}

// refreshUserPermissions removes a user from cache and triggers a refresh
func (s *AuthServer) refreshUserPermissions(userID string) {
	// Use a map to track which users we're already processing to avoid duplicates
	if _, processing := s.refreshProcessing.LoadOrStore(userID, true); processing {
		// Already processing this user, skip
		return
	}

	// Remove from cache
	s.permissionsCache.Delete(userID)

	// Notify callback if registered
	if s.realtimeCallback != nil {
		go s.realtimeCallback(userID)
	}

	// Notify connected websocket clients
	if s.websocket != nil {
		go s.websocket.NotifyPermissionChange(userID, "permissions", map[string]interface{}{
			"action":    "refresh",
			"timestamp": time.Now().Unix(),
		})
	}

	// Mark as done processing
	s.refreshProcessing.Delete(userID)
}

// GetUserPermissions retrieves a user's complete permission set
func (s *AuthServer) GetUserPermissions(ctx context.Context, userID string) (*UserPermissions, error) {
	// Check cache first
	if cachedPerms, found := s.permissionsCache.Load(userID); found {
		return cachedPerms.(*UserPermissions), nil
	}

	// Not in cache, fetch from database
	var jsonData []byte
	err := s.db.QueryRowContext(ctx,
		"SELECT public.get_user_access_json($1)", userID).Scan(&jsonData)

	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	// Parse the JSON data
	var data map[string]json.RawMessage
	err = json.Unmarshal(jsonData, &data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user permissions: %w", err)
	}
}
