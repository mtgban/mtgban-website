package main

import (
	"context"
	"log"
	"net/http"
	"strings"
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
