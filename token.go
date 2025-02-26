package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mtgban/mtgban-website/auth"
)

func noSigning(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer recoverPanic(r, w)
		next.ServeHTTP(w, r)
	})
}

func enforceSigning(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer recoverPanic(r, w)

		token := extractToken(r)
		pageVars := genPageNav("Error", token)

		if !UserRateLimiter.Allow(getUserEmail(token)) && r.URL.Path != "/admin" {
			pageVars.Title = "Rate Limit Exceeded"
			pageVars.ErrorMessage = "You have made too many requests. Please try again later."
			render(w, "home.html", pageVars)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		user, err := authService.GetUserFromContext(ctx)
		if err != nil {
			pageVars.Title = "Unauthorized"
			pageVars.ErrorMessage = "You are not authorized to access this page."
			render(w, "home.html", pageVars)
			return
		}

		for _, navName := range OrderNav {
			nav := ExtraNavs[navName]
			if r.URL.Path == nav.Link {
				if !authService.CanAccessFeature(user, auth.Feature(navName)) {
					pageVars = genPageNav(nav.Name, token)
					pageVars.Title = "Unauthorized"
					pageVars.ErrorMessage = "You are not authorized to access this page."
					render(w, nav.Page, pageVars)
					return
				}
				break
			}
		}

		ctx = context.WithValue(ctx, auth.UserContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Helper functions for auth
func extractToken(r *http.Request) string {
	token := r.Header.Get("Authorization")
	if token != "" {
		return strings.TrimPrefix(token, "Bearer ")
	}

	token = r.URL.Query().Get("token")
	if token != "" {
		return token
	}

	cookie, err := r.Cookie("MTGBAN")
	if err == nil {
		return cookie.Value
	}

	return ""
}

func getUserEmail(token string) string {
	if token == "" {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	user, err := authService.GetUserFromContext(ctx)
	if err != nil {
		return ""
	}

	return user.Email
}

func enforceAPISigning(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer recoverPanic(r, w)

		w.Header().Add("RateLimit-Limit", fmt.Sprint(APIRequestsPerSec))
		w.Header().Add("Content-Type", "application/json")

		token := extractToken(r)
		if token == "" {
			http.Error(w, `{"error": "missing token"}`, http.StatusUnauthorized)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		user, err := authService.GetUserFromContext(ctx)
		if err != nil {
			http.Error(w, `{"error": "invalid or expired token"}`, http.StatusUnauthorized)
			return
		}

		if !user.HasAccess(auth.FeatureAccess, API) {
			http.Error(w, `{"error": "insufficient permissions"}`, http.StatusForbidden)
			return
		}

		ctx = context.WithValue(ctx, auth.UserContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func extractAndValidateToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", &auth.AuthError{
			Code:    http.StatusUnauthorized,
			Message: "Missing authorization header",
		}
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		return "", &auth.AuthError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid authorization format",
		}
	}

	return tokenString, nil
}

func GetUserFromToken(ctx context.Context, tokenString string) (*auth.UserData, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return authService.GetUserFromContext(ctx)
	})

	if err != nil {
		return nil, &auth.AuthError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid token",
			Err:     err,
		}
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, &auth.AuthError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid token claims",
		}
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		return nil, &auth.AuthError{
			Code:    http.StatusUnauthorized,
			Message: "No user ID in token",
		}
	}

	return authService.GetUserByID(ctx, userID)
}

func cryptoSecureCompare(b1 []byte, b2 []byte) bool {
	if len(b1) != len(b2) {
		return false
	}

	for i := range b1 {
		if b1[i] != b2[i] {
			return false
		}
	}
	return true
}
