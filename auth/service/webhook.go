package service

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/mtgban/mtgban-website/auth/models"
)

func (s *AuthService) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		http.Error(w, "Invalid content type", http.StatusUnsupportedMediaType)
		return
	}

	if s.config.Auth.WebhookSecretKey != "" {
		if !cryptoSecureCompare(
			[]byte(r.Header.Get("X-Webhook-Secret")),
			[]byte(s.config.Auth.WebhookSecretKey),
		) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	var payload models.WebhookPayload
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(&payload); err != nil {
		s.logger.Printf("Failed to decode webhook payload: %v", err)
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	if payload.Type == "" || payload.Table == "" {
		s.logger.Printf("Missing required fields in webhook payload")
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	validTypes := map[string]bool{
		"INSERT": true,
		"UPDATE": true,
		"DELETE": true,
	}

	if !validTypes[payload.Type] {
		s.logger.Printf("Invalid webhook type: %s", payload.Type)
		http.Error(w, "Invalid webhook type", http.StatusBadRequest)
		return
	}

	if payload.Table != "users" {
		s.logger.Printf("Skipping webhook for non-user table: %s", payload.Table)
		w.WriteHeader(http.StatusOK)
		return
	}

	func() {
		defer func() {
			if r := recover(); r != nil {
				s.logger.Printf("Panic in webhook handler: %v", r)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
		}()

		switch payload.Type {
		case "INSERT", "UPDATE":
			if err := s.handleUserUpsert(payload.Record); err != nil {
				s.logger.Printf("Failed to handle user upsert: %v", err)
				http.Error(w, "Failed to process user data", http.StatusBadRequest)
				return
			}

		case "DELETE":
			if err := s.handleUserDelete(payload.Record); err != nil {
				s.logger.Printf("Failed to handle user delete: %v", err)
				http.Error(w, "Failed to process deletion", http.StatusBadRequest)
				return
			}
		}
	}()

	w.WriteHeader(http.StatusOK)
}

func (s *AuthService) handleUserUpsert(record map[string]interface{}) error {
	userData, err := s.parseUserData(record)
	if err != nil {
		return fmt.Errorf("failed to parse user data: %w", err)
	}

	s.cache.SetUser(userData)
	s.logger.Printf("Updated cache for user %s via webhook", userData.ID)
	return nil
}

func (s *AuthService) handleUserDelete(record map[string]interface{}) error {
	userID, ok := record["id"].(string)
	if !ok {
		return fmt.Errorf("invalid or missing user ID in delete record")
	}

	s.cache.DeleteUser(userID)
	s.logger.Printf("Removed user %s from cache via webhook", userID)
	return nil
}
