package service

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/mtgban/mtgban-website/auth/models"
)

func (s *AuthService) GetUserFromContext(ctx context.Context) (*models.UserData, error) {
	if ctx == nil {
		return nil, fmt.Errorf("nil context")
	}

	value := ctx.Value(models.UserContextKey)
	if value == nil {
		return nil, fmt.Errorf("no user in context")
	}

	user, ok := value.(*models.UserData)
	if !ok {
		return nil, fmt.Errorf("invalid user type in context")
	}

	return user, nil
}

func (s *AuthService) GetUser(ctx context.Context, userID string) (*models.UserData, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context error: %w", err)
	}

	cacheUser, err := s.cache.GetUser(userID)
	if err != nil {
		s.logger.Printf("Cache error for user %s: %v", userID, err)
	} else if cacheUser != nil {
		return cacheUser, nil
	}

	dbUser, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, &models.AuthError{
			Code:    http.StatusNotFound,
			Message: "User not found",
			Err:     err,
		}
	}

	if err := s.cache.SetUser(dbUser); err != nil {
		s.logger.Printf("Warning: failed to update cache for user %s: %v", userID, err)
	}

	return dbUser, nil
}

func (s *AuthService) parseUserData(record map[string]interface{}) (*models.UserData, error) {
	roleStr, ok := record["role"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid role field")
	}
	role := models.UserRole(roleStr)
	if !role.IsValid() {
		return nil, fmt.Errorf("invalid role value: %s", roleStr)
	}

	userData := &models.UserData{
		ID:   record["id"].(string),
		Role: role,
	}

	if ts, ok := record["created_at"].(string); ok {
		createdAt, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			return nil, fmt.Errorf("invalid created_at timestamp: %w", err)
		}
		userData.CreatedAt = createdAt
	}

	if ts, ok := record["last_sign_in"].(string); ok {
		lastSignIn, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			return nil, fmt.Errorf("invalid last_sign_in timestamp: %w", err)
		}
		userData.LastSignIn = lastSignIn
	}

	return userData, nil
}
