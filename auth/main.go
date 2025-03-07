package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"github.com/mtgban/mtgban-website/auth/cache"
	"github.com/mtgban/mtgban-website/auth/config"
	"github.com/mtgban/mtgban-website/auth/realtime"
	"github.com/mtgban/mtgban-website/auth/supabase"
)

// AuthServer handles authentication and authorization
type AuthServer struct {
	db               interface{} // Database connection (use your specific DB type)
	supabaseClient   *supabase.Client
	jwtSecret        string
	logger           *log.Logger
	cacheTTL         time.Duration
	listenerCtx      context.Context
	listenerCancel   context.CancelFunc
	listenerActive   bool
	permissionsCache sync.Map
	realtimeCallback func(map[string]interface{})
}

// App represents the main application
type App struct {
	Router     *mux.Router
	AuthServer *AuthServer
	DB         interface{} // Your database type
}

// AuthOptions represents options for the auth server
type AuthOptions struct {
	DB               interface{}
	SupabaseURL      string
	SupabaseKey      string
	JWTSecret        string
	Logger           *log.Logger
	CacheTTL         time.Duration
	RealtimeCallback func(map[string]interface{})
}

// AuthComponents represents the components needed for auth
type AuthComponents struct {
	Auth             interface{} // Your auth service type
	WebsocketManager interface{} // Your websocket manager type
	Supabase         *supabase.Client
	Logger           *log.Logger
}

// Global variables properly initialized
// Global variables properly initialized
var authConfig = config.AuthConfig()
var cacheService = cache.InitCache()
var authService = auth.InitAuth()
var realtimeService = realtime.InitRealtime()

// Helper function to get string from map
func getString(data map[string]interface{}, key string) string {
	if val, ok := data[key].(string); ok {
		return val
	}
	return ""
}

// NewAuthServer creates a new auth server
func NewAuthServer(options AuthOptions) (*AuthServer, error) {
	if options.DB == nil {
		return nil, fmt.Errorf("database connection is required")
	}

	if options.SupabaseURL == "" || options.SupabaseKey == "" {
		return nil, fmt.Errorf("Supabase URL and key are required")
	}

	if options.JWTSecret == "" {
		return nil, fmt.Errorf("JWT secret is required")
	}

	if options.Logger == nil {
		options.Logger = log.New(os.Stdout, "[AUTH] ", log.LstdFlags)
	}

	if options.CacheTTL == 0 {
		options.CacheTTL = 10 * time.Minute
	}

	// Initialize Supabase client
	supabaseClient := supabase.CreateClient(options.SupabaseURL, options.SupabaseKey)

	// Create the auth server
	ctx, cancel := context.WithCancel(context.Background())
	server := &AuthServer{
		db:               options.DB,
		supabaseClient:   supabaseClient,
		jwtSecret:        options.JWTSecret,
		logger:           options.Logger,
		cacheTTL:         options.CacheTTL,
		listenerCtx:      ctx,
		listenerCancel:   cancel,
		realtimeCallback: options.RealtimeCallback,
	}

	// Start the Supabase Realtime listener
	go server.startRealtimeListener()

	return server, nil
}

// startRealtimeListener sets up the Supabase Realtime subscription
func (s *AuthServer) startRealtimeListener() {
	s.listenerActive = true
	s.logger.Println("Starting Supabase Realtime listener")

	// Define the channel options
	channelOptions := supabase.RealtimeChannelOptions{
		Config: map[string]interface{}{
			"postgres_changes": []map[string]interface{}{
				{
					"event":  "*",
					"schema": "public",
					"table":  "user_permissions",
				},
				{
					"event":  "*",
					"schema": "public",
					"table":  "resource_permissions",
				},
				{
					"event":  "*",
					"schema": "auth",
					"table":  "sessions",
				},
			},
		},
	}

	// Create the channel
	channel, err := s.supabaseClient.Realtime.Channel("auth-changes", channelOptions)
	if err != nil {
		s.logger.Printf("Error creating realtime channel: %v", err)
		return
	}

	// Handle subscription to user_permissions
	channel.On("postgres_changes", "public:user_permissions", func(payload map[string]interface{}) {
		s.handlePermissionChange(payload)
	})

	// Handle subscription to resource_permissions
	channel.On("postgres_changes", "public:resource_permissions", func(payload map[string]interface{}) {
		s.handleResourcePermissionChange(payload)
	})

	// Handle subscription to sessions
	channel.On("postgres_changes", "auth:sessions", func(payload map[string]interface{}) {
		s.handleSessionChange(payload)
	})

	// Subscribe to the channel
	err = channel.Subscribe()
	if err != nil {
		s.logger.Printf("Error subscribing to channel: %v", err)
		return
	}

	// Keep the listener running until context is canceled
	<-s.listenerCtx.Done()
	s.logger.Println("Stopping Supabase Realtime listener")

	// Unsubscribe from the channel
	_ = channel.Unsubscribe()
	s.listenerActive = false
}

// handlePermissionChange handles changes to the user_permissions table
func (s *AuthServer) handlePermissionChange(payload map[string]interface{}) {
	s.logger.Printf("Permission change detected: %v", payload)

	// Extract the record from the payload
	record, ok := payload["record"].(map[string]interface{})
	if !ok {
		s.logger.Println("Error: Could not extract record from payload")
		return
	}

	// Get the change event type
	eventType, ok := payload["eventType"].(string)
	if !ok {
		s.logger.Println("Error: Could not determine event type")
		return
	}

	// Extract user ID
	userID, ok := record["user_id"].(string)
	if !ok {
		s.logger.Println("Error: Could not extract user ID from record")
		return
	}

	s.logger.Printf("Processing permission change for user %s: %s", userID, eventType)

	// Invalidate cache for this user
	s.permissionsCache.Delete(userID)

	// If callback is defined, call it
	if s.realtimeCallback != nil {
		callbackData := map[string]interface{}{
			"type":     "permission_change",
			"user_id":  userID,
			"event":    eventType,
			"record":   record,
			"metadata": payload,
		}
		s.realtimeCallback(callbackData)
	}
}

// handleResourcePermissionChange handles changes to the resource_permissions table
func (s *AuthServer) handleResourcePermissionChange(payload map[string]interface{}) {
	s.logger.Printf("Resource permission change detected: %v", payload)

	// Extract the record from the payload
	record, ok := payload["record"].(map[string]interface{})
	if !ok {
		s.logger.Println("Error: Could not extract record from payload")
		return
	}

	// Get the change event type
	eventType, ok := payload["eventType"].(string)
	if !ok {
		s.logger.Println("Error: Could not determine event type")
		return
	}

	// Extract resource type and resource ID
	resourceType, ok := record["resource_type"].(string)
	if !ok {
		s.logger.Println("Error: Could not extract resource type from record")
		return
	}

	resourceID, ok := record["resource_id"].(string)
	if !ok {
		s.logger.Println("Error: Could not extract resource ID from record")
		return
	}

	// Extract user ID
	userID, ok := record["user_id"].(string)
	if !ok {
		s.logger.Println("Error: Could not extract user ID from record")
		return
	}

	s.logger.Printf("Processing resource permission change for user %s, resource %s:%s: %s",
		userID, resourceType, resourceID, eventType)

	// Invalidate cache for this user
	s.permissionsCache.Delete(userID)

	// If callback is defined, call it
	if s.realtimeCallback != nil {
		callbackData := map[string]interface{}{
			"type":          "resource_permission_change",
			"user_id":       userID,
			"resource_type": resourceType,
			"resource_id":   resourceID,
			"event":         eventType,
			"record":        record,
			"metadata":      payload,
		}
		s.realtimeCallback(callbackData)
	}
}

// handleSessionChange handles changes to the sessions table
func (s *AuthServer) handleSessionChange(payload map[string]interface{}) {
	s.logger.Printf("Session change detected: %v", payload)

	// Extract the record from the payload
	record, ok := payload["record"].(map[string]interface{})
	if !ok {
		s.logger.Println("Error: Could not extract record from payload")
		return
	}

	// Get the change event type
	eventType, ok := payload["eventType"].(string)
	if !ok {
		s.logger.Println("Error: Could not determine event type")
		return
	}

	// Extract user ID
	userID, ok := record["user_id"].(string)
	if !ok {
		s.logger.Println("Error: Could not extract user ID from record")
		return
	}

	// Extract session ID
	sessionID, ok := record["id"].(string)
	if !ok {
		s.logger.Println("Error: Could not extract session ID from record")
		return
	}

	// Check if this is a deletion event (logout or session expiry)
	if eventType == "DELETE" {
		s.logger.Printf("Session deleted for user %s: %s", userID, sessionID)
		// Invalidate cache for this user to ensure fresh permissions check on next request
		s.permissionsCache.Delete(userID)
	} else if eventType == "INSERT" {
		s.logger.Printf("New session created for user %s: %s", userID, sessionID)
		// Optionally refresh cache with latest permissions
		go func() {
			_, err := s.GetUserPermissions(context.Background(), userID)
			if err != nil {
				s.logger.Printf("Error refreshing permissions for user %s: %v", userID, err)
			}
		}()
	}

	// If callback is defined, call it
	if s.realtimeCallback != nil {
		callbackData := map[string]interface{}{
			"type":       "session_change",
			"user_id":    userID,
			"session_id": sessionID,
			"event":      eventType,
			"record":     record,
			"metadata":   payload,
		}
		s.realtimeCallback(callbackData)
	}
}

// GetUserPermissions retrieves a user's complete permission set
func (s *AuthServer) GetUserPermissions(ctx context.Context, userID string) (*UserPermissions, error) {
	// Check cache first
	if cachedPerms, found := s.permissionsCache.Load(userID); found {
		return cachedPerms.(*UserPermissions), nil
	}

	// Parse the JSON data
	var data map[string]json.RawMessage
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return nil, fmt.Errorf("failed to parse user data: %w", err)
	}

	// Check for error
	if _, hasError := data["error"]; hasError {
		return nil, fmt.Errorf("user not found: %s", userID)
	}

	// Parse user data
	var userData map[string]interface{}
	if err := json.Unmarshal(data["user"], &userData); err != nil {
		return nil, fmt.Errorf("failed to parse user data: %w", err)
	}

	// Parse resources data
	var resourcesData map[string][]string
	if err := json.Unmarshal(data["access"], &resourcesData); err != nil {
		return nil, fmt.Errorf("failed to parse resources data: %w", err)
	}

	// Extract feature flags
	features, _ := userData["features"].(map[string]interface{})
	if features == nil {
		features = make(map[string]interface{})
	}

	// Create permissions object
	permissions := &UserPermissions{
		UserID:    userID,
		Email:     getString(userData, "email"),
		Role:      getString(userData, "role"),
		Tier:      getString(userData, "tier"),
		Status:    getString(userData, "status"),
		Features:  features,
		Resources: resourcesData,
		RawData:   userData,
	}

	// Store in cache
	s.permissionsCache.Store(userID, permissions)

	// Set up cache expiration
	go func() {
		time.Sleep(s.cacheTTL)
		s.permissionsCache.Delete(userID)
	}()

	return permissions, nil
}

// HasAccess checks if a user has access to a resource
func (s *AuthServer) HasAccess(ctx context.Context, userID string, resource Resource) (bool, error) {
	// Get permissions
	permissions, err := s.GetUserPermissions(ctx, userID)
	if err != nil {
		return false, err
	}

	// Admin role always has access
	if permissions.Role == "admin" || permissions.Role == "root" {
		return true, nil
	}

	// Check if the resource type exists in the user's resources
	resourceIDs, exists := permissions.Resources[resource.Type]
	if !exists {
		return false, nil
	}

	// Check if the resource ID is in the list
	for _, id := range resourceIDs {
		if id == resource.ID {
			return true, nil
		}
	}

	return false, nil
}

// HasFeature checks if a user has a specific feature enabled
func (s *AuthServer) HasFeature(ctx context.Context, userID string, featureName string) (bool, error) {
	// Get the user's permissions
	permissions, err := s.GetUserPermissions(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get user permissions: %w", err)
	}

	// Check if the user is an admin (admins have all features)
	if permissions.Role == "admin" || permissions.Role == "root" {
		return true, nil
	}

	// Navigate through the features map using dot notation
	// For example, "Download.CSV.Enabled" would check permissions.Features["Download"]["CSV"]["Enabled"]
	parts := strings.Split(featureName, ".")
	current := permissions.Features

	for i, part := range parts {
		// If we're at the last part, check if it's true
		if i == len(parts)-1 {
			if val, ok := current[part]; ok {
				// Check if the value is a boolean
				if enabled, ok := val.(bool); ok {
					return enabled, nil
				}
				// Check if the value is a string that can be converted to a boolean
				if strVal, ok := val.(string); ok {
					return strVal == "true" || strVal == "1" || strVal == "yes" || strVal == "enabled", nil
				}
				// If it's not a boolean or string, return false
				return false, nil
			}
			return false, nil
		}

		// If not at the last part, navigate deeper into the map
		if nested, ok := current[part].(map[string]interface{}); ok {
			current = nested
		} else {
			// If there's no nested map, the feature doesn't exist
			return false, nil
		}
	}

	// If we get here, something went wrong with the navigation
	return false, nil
}

// VerifyToken verifies a JWT token and extracts the user ID
func (s *AuthServer) VerifyToken(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.jwtSecret), nil
	})

	if err != nil {
		return "", fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return "", fmt.Errorf("token is invalid")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid claims format")
	}

	// Get user ID from claims
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return "", fmt.Errorf("missing subject claim")
	}

	return sub, nil
}

// AuthMiddleware creates middleware to protect routes
func (s *AuthServer) AuthMiddleware(resourceType, resourceID string) func(http.Handler) http.Handler {
	// Implementation omitted for brevity
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
		})
	}
}

// LoginRedirectHandler handles redirects from auth service
func (s *AuthServer) LoginRedirectHandler() http.HandlerFunc {
	// Implementation omitted for brevity
	return func(w http.ResponseWriter, r *http.Request) {}
}

// RenderPage renders a page with the given template and data
func (s *AuthServer) RenderPage(w http.ResponseWriter, r *http.Request, templateName string, data map[string]interface{}) {
	// Implementation omitted for brevity
}

// ExtractToken extracts a token from the request
func ExtractToken(r *http.Request) string {
	// Implementation omitted for brevity
	return ""
}

// NewApp creates a new application
func NewApp(authServer *AuthServer, client interface{}) *App {
	app := &App{
		Router:     mux.NewRouter(),
		AuthServer: authServer,
		client:     client,
	}
	app.setupRoutes()
	return app
}

// setupRoutes sets up all application routes
func (a *App) setupRoutes() {
	// Static files
	a.Router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	// Auth redirect handler - this handles redirects from your auth service
	a.Router.HandleFunc("/auth/callback", a.AuthServer.LoginRedirectHandler())

	// Public routes
	a.Router.HandleFunc("/", a.homeHandler).Methods("GET")
	a.Router.HandleFunc("/login", a.loginHandler).Methods("GET")

	// Protected routes with different resource requirements
	dashboard := a.Router.PathPrefix("/dashboard").Subrouter()
	dashboard.Use(a.AuthServer.AuthMiddleware("page", "dashboard"))
	dashboard.HandleFunc("", a.dashboardHandler).Methods("GET")

	admin := a.Router.PathPrefix("/admin").Subrouter()
	admin.Use(a.AuthServer.AuthMiddleware("page", "admin"))
	admin.HandleFunc("", a.adminHandler).Methods("GET")
	admin.HandleFunc("/users", a.adminUsersHandler).Methods("GET")

	// API routes
	api := a.Router.PathPrefix("/api").Subrouter()
	api.Use(a.AuthServer.AuthMiddleware("api", "data"))
	api.HandleFunc("/data", a.apiDataHandler).Methods("GET")
}

// Run starts the application
func (a *App) Run(addr string) {
	log.Fatal(http.ListenAndServe(addr, a.Router))
}

// homeHandler handles the home page
func (a *App) homeHandler(w http.ResponseWriter, r *http.Request) {
	// For public pages, we might still want to know who the user is if they're logged in
	token := ExtractToken(r)
	if token != "" {
		userID, err := a.AuthServer.VerifyToken(token)
		if err == nil {
			// Get the user's permissions
			permissions, err := a.AuthServer.GetUserPermissions(r.Context(), userID)
			if err == nil {
				// Render home page with user data
				a.AuthServer.RenderPage(w, r, "home", map[string]interface{}{
					"LoggedIn": true,
					"Email":    permissions.Email,
				})
				return
			}
		}
	}

	// Render home page without user data
	tmpl, _ := template.ParseFiles("templates/home.gohtml", "templates/base.gohtml")
	tmpl.ExecuteTemplate(w, "base", map[string]interface{}{
		"LoggedIn": false,
	})
}

// loginHandler handles the login page
func (a *App) loginHandler(w http.ResponseWriter, r *http.Request) {
	// This is just a simple page that will redirect to your auth provider (Supabase Auth, Auth0, etc.)
	tmpl, _ := template.ParseFiles("templates/login.gohtml", "templates/base.gohtml")
	tmpl.ExecuteTemplate(w, "base", map[string]interface{}{
		"SupabaseURL": os.Getenv("SUPABASE_URL"),
		"RedirectURL": os.Getenv("AUTH_REDIRECT_URL"),
	})
}

// dashboardHandler handles the dashboard page
func (a *App) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	// Get user permissions from context
	userPerms, ok := r.Context().Value("user_permissions").(*UserPermissions)
	if !ok {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}

	// Render dashboard with user data
	a.AuthServer.RenderPage(w, r, "dashboard", map[string]interface{}{
		"Email": userPerms.Email,
		"Items": getDashboardItems(r.Context(), a.DB),
	})
}

// getDashboardItems gets items for the dashboard
func getDashboardItems(ctx context.Context, db interface{}) []interface{} {
	// Implementation omitted for brevity
	return []interface{}{}
}

// getAdminStats gets stats for the admin dashboard
func getAdminStats(ctx context.Context, db interface{}) map[string]interface{} {
	// Implementation omitted for brevity
	return map[string]interface{}{}
}

// getAllUsers gets all users
func getAllUsers(ctx context.Context, db interface{}) []interface{} {
	// Implementation omitted for brevity
	return []interface{}{}
}

// adminHandler handles the admin page
func (a *App) adminHandler(w http.ResponseWriter, r *http.Request) {
	// Since we're using the AuthMiddleware, we know the user has access to the admin page
	a.AuthServer.RenderPage(w, r, "admin", map[string]interface{}{
		"Stats": getAdminStats(r.Context(), a.DB),
	})
}

// adminUsersHandler handles the admin users page
func (a *App) adminUsersHandler(w http.ResponseWriter, r *http.Request) {
	// You might want to check for additional permissions here
	userID, _ := r.Context().Value("user_id").(string)
	hasManageUsers, err := a.AuthServer.HasAccess(r.Context(), userID, Resource{
		Type: "feature",
		ID:   "manage_users",
	})

	if err != nil || !hasManageUsers {
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
		return
	}

	a.AuthServer.RenderPage(w, r, "admin_users", map[string]interface{}{
		"Users": getAllUsers(r.Context(), a.DB),
	})
}

// apiDataHandler handles the API data endpoint
func (a *App) apiDataHandler(w http.ResponseWriter, r *http.Request) {
	// Get user permissions from context
	userPerms, ok := r.Context().Value("user_permissions").(*UserPermissions)
	if !ok {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}

	// Check if user has download permissions
	userID, _ := r.Context().Value("user_id").(string)
	canDownload, err := a.AuthServer.HasFeature(r.Context(), userID, "Download.CSV.Enabled")

	if err != nil {
		http.Error(w, "Error checking permissions", http.StatusInternalServerError)
		return
	}

	// Set JSON content type
	w.Header().Set("Content-Type", "application/json")

	// Different response based on permissions
	if canDownload {
		w.Write([]byte(`{"data": [{"id": 1, "name": "Item 1"}, {"id": 2, "name": "Item 2"}], "can_download": true}`))
	} else {
		w.Write([]byte(`{"data": [{"id": 1, "name": "Item 1"}, {"id": 2, "name": "Item 2"}], "can_download": false}`))
	}
}


func main() {

	func main() {
		// Example usage of the imported modules
		authService := auth.NewAuthService()
		configService := config.NewConfigService()
		cacheService := cache.NewCacheService()
		modelsService := models.NewModelsService()
		serviceService := service.NewServiceService()
		realtimeService := realtime.NewRealtimeService()
		webhookService := webhook.NewWebhookService()
		appService := app.NewAppService()
	
		log.Println(authService, configService, cacheService, modelsService, serviceService, realtimeService, webhookService, appService)
	}
	// Initialize database
	configPath := "config.json"

	data, err := ioutil.ReadFile(configPath)
	Config, err := LoadAuthConfig(data)

	// Read the configuration file as bytes
	config, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}
	// Initialize Supabase client
	authConfig := config.AuthConfig()
	client, err := InitSupabaseClient(authConfig.SupabaseURL, authConfig.SupabaseKey)
	if err != nil {
		log.Fatalf("Failed to initialize Supabase client: %v", err)
	}
	// Create logger
	logger := log.New(os.Stdout, "[AUTH] ", log.LstdFlags)

	// Initialize auth server
	authServer, err := NewAuthServer(AuthOptions{
		DB:           client,
		SupabaseURL:  authConfig.SupabaseURL,
		SupabaseKey:  authConfig.SupabaseKey,
		JWTSecret:    authConfig.JWTSecret,
		Logger:       logger,
		CacheTTL:     10 * time.Minute,
	})

	if err != nil {
		logger.Fatalf("Failed to initialize auth server: %v", err)
	}

	// Create and run application
	app := NewApp(authServer, client)
	logger.Printf("Starting server on %s", authConfig.ServerAddress)
	app.Run(authConfig.ServerAddress)
}
	
	return &config.Config{
		ServerAddress: ":8080",
		SupabaseURL:   os.Getenv("SUPABASE_URL"),
		SupabaseKey:   os.Getenv("SUPABASE_KEY"),
		JWTSecret:     os.Getenv("JWT_SECRET"),
		DatabaseURL:   os.Getenv("DATABASE_URL"),
	}
}

// initDatabase initializes a database connection
func initDatabase(databaseURL string) interface{} {
	// Implementation omitted for brevity
	return nil
}
