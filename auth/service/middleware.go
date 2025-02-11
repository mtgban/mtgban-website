package service

import (
	"context"
	"net/http"

	"github.com/mtgban/mtgban-website/auth/models"
)

func (s *AuthService) AuthMiddleware(requiredRole models.UserRole) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			newCtx, err := s.authenticateAndAuthorize(ctx, r, requiredRole)
			if err != nil {
				s.handleAuthError(w, err)
				return
			}

			next.ServeHTTP(w, r.WithContext(newCtx))
		})
	}
}

func (s *AuthService) handleAuthError(w http.ResponseWriter, err error) {
	if authErr, ok := err.(*models.AuthError); ok {
		s.logger.Printf("Authentication error: %v, code: %d", authErr, authErr.Code)
		http.Error(w, authErr.Message, authErr.Code)
		return
	}

	s.logger.Printf("Internal server error: %v", err)
	http.Error(w, "Internal server error", http.StatusInternalServerError)
}

func (s *AuthService) authenticateAndAuthorize(ctx context.Context, r *http.Request, requiredRole models.UserRole) (context.Context, error) {
	if err := ctx.Err(); err != nil {
		return ctx, &models.AuthError{
			Code:    http.StatusServiceUnavailable,
			Message: "Request cancelled or timed out",
			Err:     err,
		}
	}

	token, err := s.extractAndValidateToken(r)
	if err != nil {
		return ctx, err
	}

	user, err := s.GetUserFromToken(ctx, token)
	if err != nil {
		return ctx, err
	}

	if !s.HasRequiredRole(user.Role, requiredRole) {
		return ctx, &models.AuthError{
			Code:    http.StatusForbidden,
			Message: "Insufficient permissions",
		}
	}

	return context.WithValue(ctx, models.UserContextKey, user), nil
}
