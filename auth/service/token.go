package service

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mtgban/mtgban-website/auth/models"
)

func (s *AuthService) extractAndValidateToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", &models.AuthError{
			Code:    http.StatusUnauthorized,
			Message: "Missing authorization header",
		}
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		return "", &models.AuthError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid authorization format",
		}
	}

	return tokenString, nil
}

func (s *AuthService) GetUserFromToken(ctx context.Context, tokenString string) (*models.UserData, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.config.Auth.WebhookSecretKey, nil
	})

	if err != nil {
		return nil, &models.AuthError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid token",
			Err:     err,
		}
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, &models.AuthError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid token claims",
		}
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		return nil, &models.AuthError{
			Code:    http.StatusUnauthorized,
			Message: "No user ID in token",
		}
	}

	return s.GetUser(ctx, userID)
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
