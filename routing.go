package main

import (
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

// ==========================================================================
// Middleware Configuration
// ==========================================================================

// initMiddlewareRegistry creates and configures the middleware registry
func initMiddlewareRegistry() *MiddlewareRegistry {
	registry := NewMiddlewareRegistry()

	// Core middleware for most routes
	registry.RegisterChain("core",
		authService.Recover,
		authService.RequestLogger,
		authService.AuthContext,
	)

	// Minimal core middleware without AuthContext
	registry.RegisterChain("core-no-auth",
		authService.Recover,
		authService.RequestLogger,
	)

	// Authentication-related middleware chains
	registry.RegisterChain("auth",
		authService.Recover,
		authService.RequestLogger,
	)

	registry.RegisterChain("auth-assets",
		authService.Recover,
		authService.RequestLogger,
	)

	// Protected route middleware chains
	registry.RegisterChain("protected",
		authService.Recover,
		authService.RequestLogger,
		authService.AuthContext,
		authService.AuthRequired,
		authService.SpoofMiddleware,
	)

	registry.RegisterChain("csrf-protected",
		authService.Recover,
		authService.RequestLogger,
		authService.AuthContext,
		authService.AuthRequired,
		authService.SpoofMiddleware,
		authService.CSRFProtection,
	)

	registry.RegisterChain("api-protected",
		authService.Recover,
		authService.RequestLogger,
		authService.AuthContext,
		authService.AuthRequired,
	)

	return registry
}

// ==========================================================================
// Route Setup Functions
// ==========================================================================

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
func setupAuthRoutes(mux *http.ServeMux, mr *MiddlewareRegistry) {
	logoutHandler := http.HandlerFunc(authService.LogoutAPI)
	authAssetHandler := http.HandlerFunc(authService.handleAuthAsset)

	// Login endpoints
	mux.Handle("/next-api/auth/login", mr.WrapFunc("auth", authService.LoginAPI))
	mux.Handle("/next-api/auth/signup", mr.WrapFunc("auth", authService.SignupAPI))
	mux.Handle("/next-api/auth/forgot-password", mr.WrapFunc("auth", authService.ForgotPasswordAPI))
	mux.Handle("/next-api/auth/me", mr.WrapFunc("protected", authService.GetUserAPI))

	// Token refresh
	mux.Handle("/next-api/auth/refresh-token", mr.WrapFunc("auth", authService.RefreshTokenAPI))

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
func setupRouter() *http.ServeMux {
	mux := http.NewServeMux()
	middlewares := initMiddlewareRegistry()
	setupStaticRoutes(mux)
	setupPublicRoutes(mux, middlewares)
	setupAuthRoutes(mux, middlewares)
	setupDynamicNavRoutes(mux, middlewares)
	setupAPIRoutes(mux, middlewares)
	return mux
}

// ==========================================================================
// Server Configuration
// ==========================================================================

// configureServer creates and configures the HTTP server
func configureServer(mux *http.ServeMux) *http.Server {
	return &http.Server{
		Addr:    ":" + Config.Port,
		Handler: mux,
	}
}
