package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/leemcloughlin/logfile"
)

// ==========================================================================
// Middleware Definitions & Helpers
// ==========================================================================

// Chain function to apply multiple middlewares to a handler
func Chain(h http.HandlerFunc, middlewares ...Middleware) http.HandlerFunc {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}

// MiddlewareRegistry defines named middleware chains for different route types
type MiddlewareRegistry struct {
	chains map[string][]Middleware
}

// NewMiddlewareRegistry creates a new registry with standard middleware chains
func NewMiddlewareRegistry() *MiddlewareRegistry {
	return &MiddlewareRegistry{
		chains: map[string][]Middleware{},
	}
}

// RegisterChain adds or updates a middleware chain with a given name
func (mr *MiddlewareRegistry) RegisterChain(name string, middlewares ...Middleware) {
	mr.chains[name] = middlewares
}

// ApplyMiddleware applies the named middleware chain to a handler
func (mr *MiddlewareRegistry) ApplyMiddleware(name string, handler http.Handler) http.Handler {
	chain, exists := mr.chains[name]
	if !exists {
		log.Printf("WARNING: Unknown middleware chain %s, using raw handler", name)
		return handler
	}

	handlerFunc := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	})

	return Chain(handlerFunc, chain...)
}

// WrapFunc wraps an http.HandlerFunc with the named middleware chain
func (mr *MiddlewareRegistry) WrapFunc(name string, fn http.HandlerFunc) http.Handler {
	return mr.ApplyMiddleware(name, http.HandlerFunc(fn))
}

// HandleRoute registers a route with the appropriate middleware chain
func (mr *MiddlewareRegistry) HandleRoute(mux *http.ServeMux, pattern string, handler http.Handler, chainName string) {
	mux.Handle(pattern, mr.ApplyMiddleware(chainName, handler))
}

// HandleRouteFunc registers a handler function with the appropriate middleware chain
func (mr *MiddlewareRegistry) HandleRouteFunc(mux *http.ServeMux, pattern string, fn http.HandlerFunc, chainName string) {
	mux.Handle(pattern, mr.WrapFunc(chainName, fn))
}

// cssMiddleware is a specialized middleware to ensure CSS files are served with the correct MIME type
func cssMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(strings.Split(r.URL.Path, "?")[0], ".css") {
			w.Header().Set("Content-Type", "text/css")
		}
		next.ServeHTTP(w, r)
	})
}

// InjectAuthServiceMiddleware adds the AuthService instance to the request context.
func InjectAuthServiceMiddleware(authSvc *AuthService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), authServiceKey, authSvc)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GetAuthServiceFromContext(ctx context.Context) (*AuthService, bool) {
	authService, ok := ctx.Value(authServiceKey).(*AuthService)
	if !ok {
		log.Println("ERROR: AuthService not found in request context!")
		return nil, false
	}
	return authService, true
}

// ==========================================================================
// Middleware Configuration
// ==========================================================================

// initMiddlewareRegistry creates and configures the middleware registry
func initMiddlewareRegistry(auth *AuthService) *MiddlewareRegistry {
	registry := NewMiddlewareRegistry()

	// Core middleware for most routes
	registry.RegisterChain("core",
		auth.Recover,
		auth.RequestLogger,
		auth.AuthContext,
	)

	// Minimal core middleware without AuthContext
	registry.RegisterChain("core-no-auth",
		auth.Recover,
		auth.RequestLogger,
	)

	// Authentication-related middleware chains
	registry.RegisterChain("auth",
		auth.Recover,
		auth.RequestLogger,
	)

	registry.RegisterChain("auth-assets",
		auth.Recover,
		auth.RequestLogger,
	)

	// Protected route middleware chains
	registry.RegisterChain("protected",
		auth.Recover,
		auth.RequestLogger,
		auth.AuthContext,
		auth.AuthRequired,
	)

	registry.RegisterChain("csrf-protected",
		auth.Recover,
		auth.RequestLogger,
		auth.AuthContext,
		auth.AuthRequired,
		auth.CSRFProtection,
	)

	registry.RegisterChain("api-protected",
		auth.Recover,
		auth.RequestLogger,
		auth.AuthContext,
		auth.AuthRequired,
	)

	return registry
}

// ==========================================================================
// Handlers
// ==========================================================================

type Handlers struct {
	// Group handlers by domain
	Auth struct {
		Login           http.HandlerFunc
		Signup          http.HandlerFunc
		Logout          http.HandlerFunc
		ForgotPassword  http.HandlerFunc
		GetUser         http.HandlerFunc
		RefreshToken    http.HandlerFunc
		HandleAuthAsset http.HandlerFunc
	}

	Public struct {
		Home           http.HandlerFunc
		RandomSearch   http.HandlerFunc
		RandomSealed   http.HandlerFunc
		Redirect       http.HandlerFunc
		Favicon        http.HandlerFunc
		OpenSearchDesc http.HandlerFunc
	}

	API struct {
		Search     http.HandlerFunc
		Suggest    http.HandlerFunc
		Price      http.HandlerFunc
		CKMirror   http.HandlerFunc
		TCGHandler http.HandlerFunc
	}

	// DynamicNavHandlers are populated from ExtraNavs
	DynamicNavHandlers map[string]http.HandlerFunc
}

// NewHandlers initializes all handlers
func NewHandlers(auth *AuthService) *Handlers {
	h := &Handlers{
		DynamicNavHandlers: make(map[string]http.HandlerFunc),
	}

	// Initialize Auth handlers
	h.Auth.Login = auth.LoginAPI
	h.Auth.Signup = auth.SignupAPI
	h.Auth.Logout = auth.LogoutAPI
	h.Auth.ForgotPassword = auth.ForgotPasswordAPI
	h.Auth.GetUser = auth.GetUserAPI
	h.Auth.RefreshToken = auth.RefreshTokenAPI
	h.Auth.HandleAuthAsset = auth.handleAuthAsset

	// Initialize Public handlers
	h.Public.Home = Home
	h.Public.RandomSearch = RandomSearch
	h.Public.RandomSealed = RandomSealedSearch
	h.Public.Redirect = Redirect
	h.Public.Favicon = Favicon
	h.Public.OpenSearchDesc = OpenSearchDesc

	// Initialize API handlers
	h.API.Search = SearchAPI
	h.API.Suggest = SuggestAPI
	h.API.Price = PriceAPI
	h.API.CKMirror = CKMirrorAPI
	h.API.TCGHandler = TCGHandler

	// Populate dynamic nav handlers
	for key, nav := range ExtraNavs {
		h.DynamicNavHandlers[key] = nav.Handle
	}

	return h
}

// setupStaticRoutes configures routes for static assets
func setupStaticRoutes(mux *http.ServeMux) {
	cssHandler := cssMiddleware(&FileSystem{http.Dir("css")})
	mux.Handle("/css/", http.StripPrefix("/css/", cssHandler))
	mux.Handle("/img/", http.StripPrefix("/img/", &FileSystem{http.Dir("img")}))
	mux.Handle("/js/", http.StripPrefix("/js/", &FileSystem{http.Dir("js")}))
	mux.HandleFunc("/favicon.ico", Favicon)
	mux.Handle("/img/opensearch.xml", http.HandlerFunc(OpenSearchDesc))
}

// setupPublicRoutes configures routes that are publicly accessible
func setupPublicRoutes(mux *http.ServeMux, mr *MiddlewareRegistry) {
	mux.HandleFunc("/go/", Redirect)
	mr.HandleRouteFunc(mux, "/random", RandomSearch, "core")
	mr.HandleRouteFunc(mux, "/randomsealed", RandomSealedSearch, "core")

	mux.HandleFunc("/discord", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, Config.DiscordInviteLink, http.StatusFound)
	})

	mr.HandleRouteFunc(mux, "/", Home, "core")
	mr.HandleRouteFunc(mux, "/home", Home, "core")
}

// setupAuthRoutes configures authentication-related routes
func setupAuthRoutes(mux *http.ServeMux, mr *MiddlewareRegistry, auth *AuthService) {
	logoutHandler := http.HandlerFunc(auth.LogoutAPI)
	authAssetHandler := http.HandlerFunc(auth.handleAuthAsset)

	// Login endpoints
	mux.Handle("/next-api/auth/login", mr.WrapFunc("auth", auth.LoginAPI))
	mux.Handle("/next-api/auth/signup", mr.WrapFunc("auth", auth.SignupAPI))
	mux.Handle("/next-api/auth/forgot-password", mr.WrapFunc("auth", auth.ForgotPasswordAPI))
	mux.Handle("/next-api/auth/me", mr.WrapFunc("protected", auth.GetUserAPI))

	// Token refresh
	mux.Handle("/next-api/auth/refresh-token", mr.WrapFunc("auth", auth.RefreshTokenAPI))

	// Logout
	mux.Handle("/next-api/auth/logout", mr.WrapFunc("auth", logoutHandler))

	// Auth assets
	mux.Handle("/auth/", mr.ApplyMiddleware("auth-assets", authAssetHandler))
	mux.Handle("/_next/", mr.ApplyMiddleware("auth-assets", authAssetHandler))
}

// setupDynamicNavRoutes configures routes from ExtraNavs with appropriate protection
func setupDynamicNavRoutes(mux *http.ServeMux, mr *MiddlewareRegistry) {
	// Register routes for each navigation item from ExtraNavs
	for key, nav := range ExtraNavs {
		// Set up logging
		logFile, err := logfile.New(&logfile.LogFile{
			FileName:    path.Join(LogDir, key+".log"),
			MaxSize:     500 * 1024,
			Flags:       logfile.FileOnly,
			OldVersions: 2,
		})
		if err != nil {
			log.Printf("Failed to create logFile for %s: %s", key, err)
			LogPages[key] = log.New(os.Stderr, "", log.LstdFlags)
		} else {
			LogPages[key] = log.New(logFile, "", log.LstdFlags)
		}

		// Apply appropriate middleware chain based on route requirements
		middlewareChain := "protected"
		if nav.CanPOST {
			if !strings.Contains(nav.Name, "Search") {
				middlewareChain = "csrf-protected"
			}
		}

		mux.Handle(nav.Link, mr.ApplyMiddleware(middlewareChain, http.HandlerFunc(nav.Handle)))

		// Also apply to subpages
		for _, subPage := range nav.SubPages {
			mux.Handle(subPage, mr.ApplyMiddleware(middlewareChain, http.HandlerFunc(nav.Handle)))
		}
	}
}

// setupAPIRoutes configures both public and protected API endpoints
func setupAPIRoutes(mux *http.ServeMux, mr *MiddlewareRegistry) {
	// Public API routes
	mr.HandleRouteFunc(mux, "/api/search/", SearchAPI, "core")
	mux.HandleFunc("/api/opensearch.xml", OpenSearchDesc)
	mr.HandleRouteFunc(mux, "/api/suggest", SuggestAPI, "core-no-auth")

	// Protected API routes
	mr.HandleRouteFunc(mux, "/search/oembed", Search, "core-no-auth")
	mr.HandleRouteFunc(mux, "/api/mtgban/", PriceAPI, "api-protected")
	mr.HandleRouteFunc(mux, "/api/mtgjson/ck.json", API, "api-protected")
	mr.HandleRouteFunc(mux, "/api/tcgplayer/", TCGHandler, "api-protected")
	mr.HandleRouteFunc(mux, "/api/cardkingdom/pricelist.json", CKMirrorAPI, "api-protected")
}

// ==========================================================================
// Main Router Assembly
// ==========================================================================

// setupRouter initializes the HTTP router and configures all routes
func setupRouter(auth *AuthService) *http.ServeMux {
	mux := http.NewServeMux()
	middlewares := initMiddlewareRegistry(auth)
	setupStaticRoutes(mux)
	setupPublicRoutes(mux, middlewares)
	setupAuthRoutes(mux, middlewares, auth)
	setupDynamicNavRoutes(mux, middlewares)
	setupAPIRoutes(mux, middlewares)
	return mux
}

// ==========================================================================
// Server Configuration
// ==========================================================================

// configureServer creates and configures the HTTP server
func configureServer(handler http.Handler) *http.Server {
	return &http.Server{
		Addr:    ":" + Config.Port,
		Handler: handler,
	}
}

func setupServer(authService *AuthService) *http.Server {
	mux := setupRouter(authService)
	injectorMiddleware := InjectAuthServiceMiddleware(authService)
	var finalHandler http.Handler = mux
	finalHandler = injectorMiddleware(finalHandler)
	srv := configureServer(finalHandler)
	return srv
}
