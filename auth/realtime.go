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
		logger:       log.New(log.Writer(), "[WSKT] ", log.LstdFlags),
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
			"action": "refresh",
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

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yourdomain/auth"
	_ "github.com/lib/pq"
)

func main() {
	// Setup logger
	logger := log.New(os.Stdout, "[AUTH-SERVER] ", log.LstdFlags)
	
	// Connect to the database
	db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		logger.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()
	
	// Initialize auth server with Supabase Realtime
	authServer, err := auth.NewAuthServer(auth.Config{
		DB:             db,
		SupabaseURL:    os.Getenv("SUPABASE_URL"),
		SupabaseKey:    os.Getenv("SUPABASE_KEY"),
		JWTSecret:      os.Getenv("SUPABASE_JWT_SECRET"),
		Logger:         logger,
		CacheTTL:       10 * time.Minute,
		RealtimeCallback: func(userID string) {
			logger.Printf("Permission change detected for user %s", userID)
			// Could implement WebSocket notifications here if needed
		},
	})
	
	if err != nil {
		logger.Fatalf("Failed to initialize auth server: %v", err)
	}
	
	// Create a server
	mux := http.NewServeMux()
	
	// Protected routes using the auth middleware
	mux.Handle("/api/dashboard", authServer.AuthMiddleware("page", "dashboard")(dashboardHandler()))
	mux.Handle("/api/admin", authServer.AuthMiddleware("page", "admin")(adminHandler()))
	mux.Handle("/api/data/export", authServer.AuthMiddleware("feature", "can_download_csv")(exportHandler()))
	
	// Admin routes for managing permissions
	mux.Handle("/api/admin/permissions/grant", authServer.AuthMiddleware("page", "admin")(grantPermissionHandler(authServer)))
	mux.Handle("/api/admin/permissions/revoke", authServer.AuthMiddleware("page", "admin")(revokePermissionHandler(authServer)))
	
	// API endpoint to check if user has access to a specific resource
	mux.Handle("/api/auth/check-access", checkAccessHandler(authServer))
	
	// API endpoint to get all permissions for a user
	mux.Handle("/api/auth/permissions", getUserPermissionsHandler(authServer))
	
	// Start the server
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	
	// Start the server in a goroutine
	go func() {
		logger.Printf("Starting server on :8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Server error: %v", err)
		}
	}()
	
	// Set up graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	
	// Wait for interrupt signal
	<-stop
	logger.Println("Shutting down server...")
	
	// Create a deadline for the shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// Shutdown the auth server first
	authServer.Shutdown()
	
	// Shutdown the HTTP server
	if err := server.Shutdown(ctx); err != nil {
		logger.Fatalf("Server shutdown failed: %v", err)
	}
	
	logger.Println("Server stopped gracefully")
}

// dashboardHandler handles the dashboard API endpoint
func dashboardHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get user permissions from context
		userPerms, ok := auth.GetUserPermsFromContext(r.Context())
		if !ok {
			http.Error(w, "User permissions not found in context", http.StatusInternalServerError)
			return
		}
		
		// Use the permissions to customize the response
		response := map[string]interface{}{
			"user": map[string]interface{}{
				"id":    userPerms.UserID,
				"email": userPerms.Email,
				"role":  userPerms.Role,
				"tier":  userPerms.Tier,
			},
			"dashboard": map[string]interface{}{
				"charts":       getAvailableCharts(userPerms),
				"dataAccess":   getAccessibleData(userPerms),
				"exportAccess": hasExportAccess(userPerms),
			},
		}
		
		// Return the response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// adminHandler handles the admin API endpoint
func adminHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get user permissions from context
		userPerms, ok := auth.GetUserPermsFromContext(r.Context())
		if !ok {
			http.Error(w, "User permissions not found in context", http.StatusInternalServerError)
			return
		}
		
		// For admin panel, we could include all accessible resources
		response := map[string]interface{}{
			"user": map[string]interface{}{
				"id":    userPerms.UserID,
				"email": userPerms.Email,
				"role":  userPerms.Role,
				"tier":  userPerms.Tier,
			},
			"adminAccess": userPerms.Resources,
		}
		
		// Return the response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// exportHandler handles data export
func exportHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Generate a CSV or other export format
		// For demo purposes, we'll just return JSON
		
		exportData := []map[string]interface{}{
			{"id": 1, "name": "Item 1", "value": 42.5},
			{"id": 2, "name": "Item 2", "value": 18.2},
			{"id": 3, "name": "Item 3", "value": 95.7},
		}
		
		// Return the data
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=export.json")
		json.NewEncoder(w).Encode(exportData)
	}
}

// grantPermissionHandler processes permission grants
func grantPermissionHandler(authServer *auth.AuthServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// This should be a POST request
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		
		// Parse request
		var req struct {
			UserID       string `json:"user_id"`
			ResourceType string `json:"resource_type"`
			ResourceID   string `json:"resource_id"`
		}
		
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		
		// Get admin user ID for auditing
		adminID, _ := auth.GetUserIDFromContext(r.Context())
		
		// Grant access
		err := authServer.GrantAccess(r.Context(), req.UserID, auth.Resource{
			Type: req.ResourceType,
			ID:   req.ResourceID,
		}, adminID)
		
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to grant access: %v", err), http.StatusInternalServerError)
			return
		}
		
		// Return success
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Access granted successfully",
		})
	}
}

// revokePermissionHandler processes permission revocations
func revokePermissionHandler(authServer *auth.AuthServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// This should be a POST request
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		
		// Parse request
		var req struct {
			UserID       string `json:"user_id"`
			ResourceType string `json:"resource_type"`
			ResourceID   string `json:"resource_id"`
		}
		
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		
		// Revoke access
		err := authServer.RevokeAccess(r.Context(), req.UserID, auth.Resource{
			Type: req.ResourceType,
			ID:   req.ResourceID,
		})
		
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to revoke access: %v", err), http.StatusInternalServerError)
			return
		}
		
		// Return success
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Access revoked successfully",
		})
	}
}

// checkAccessHandler checks if a user has access to a specific resource
func checkAccessHandler(authServer *auth.AuthServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract token
		token := auth.ExtractToken(r)
		if token == "" {
			http.Error(w, "Unauthorized - no token provided", http.StatusUnauthorized)
			return
		}
		
		// Verify token and get user ID
		userID, err := authServer.VerifyToken(token)
		if err != nil {
			http.Error(w, "Unauthorized - invalid token", http.StatusUnauthorized)
			return
		}
		
		// Get resource type and ID from query parameters
		resourceType := r.URL.Query().Get("type")
		resourceID := r.URL.Query().Get("id")
		
		if resourceType == "" || resourceID == "" {
			http.Error(w, "Missing resource parameters", http.StatusBadRequest)
			return
		}
		
		// Check access
		hasAccess, err := authServer.HasAccess(r.Context(), userID, auth.Resource{
			Type: resourceType,
			ID:   resourceID,
		})
		
		if err != nil {
			http.Error(w, fmt.Sprintf("Error checking access: %v", err), http.StatusInternalServerError)
			return
		}
		
		// Return result
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"hasAccess": hasAccess,
		})
	}
}

// getUserPermissionsHandler returns all permissions for a user
func getUserPermissionsHandler(authServer *auth.AuthServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract token
		token := auth.ExtractToken(r)
		if token == "" {
			http.Error(w, "Unauthorized - no token provided", http.StatusUnauthorized)
			return
		}
		
		// Verify token and get user ID
		userID, err := authServer.VerifyToken(token)
		if err != nil {
			http.Error(w, "Unauthorized - invalid token", http.StatusUnauthorized)
			return
		}
		
		// Get permissions
		perms, err := authServer.GetUserPermissions(r.Context(), userID)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error getting permissions: %v", err), http.StatusInternalServerError)
			return
		}
		
		// Return permissions
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(perms)
	}
}

// Helper functions for the dashboard handler

func getAvailableCharts(perms *auth.UserPermissions) []string {
	charts := []string{"basic"}
	
	// Check if user has access to additional charts
	resourceIDs, exists := perms.Resources["feature"]
	if exists {
		for _, id := range resourceIDs {
			if id == "advanced_charts" {
				charts = append(charts, "advanced")
			}
			if id == "premium_charts" {
				charts = append(charts, "premium")
			}
		}
	}
	
	// Tier-based chart access
	switch perms.Tier {
	case "vintage", "legacy":
		charts = append(charts, "vintage")
	case "modern":
		charts = append(charts, "modern")
	}
	
	return charts
}

func getAccessibleData(perms *auth.UserPermissions) []string {
	data := []string{"public"}
	
	// Check tier-based data access
	switch perms.Tier {
	case "vintage":
		data = append(data, "vintage", "legacy", "modern", "pioneer")
	case "legacy":
		data = append(data, "legacy", "modern", "pioneer")
	case "modern":
		data = append(data, "modern", "pioneer")
	case "pioneer":
		data = append(data, "pioneer")
	}
	
	return data
}

func hasExportAccess(perms *auth.UserPermissions) bool {
	// Check feature access
	resourceIDs, exists := perms.Resources["feature"]
	if exists {
		for _, id := range resourceIDs {
			if id == "can_download_csv" {
				return true
			}
		}
	}
	
	// Role-based override
	if perms.Role == "admin" || perms.Role == "root" {
		return true
	}
	
	return false
}