package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	maxWebhookBodySize = 1 << 20 // 1MB limit
	webhookTimeout     = 30 * time.Second
)

// WebhookHandler encapsulates webhook handling logic
type WebhookHandler struct {
	service       *AuthService
	secretKey     string
	allowedTypes  map[string]bool
	allowedTables map[string]bool
}

// NewWebhookHandler creates a new webhook handler
func NewWebhookHandler(service *AuthService, secretKey string) *WebhookHandler {
	if secretKey == "" {
		service.logger.Println("WARNING: Webhook secret key is not set")
	}

	return &WebhookHandler{
		service:   service,
		secretKey: secretKey,
		allowedTypes: map[string]bool{
			"INSERT": true,
			"UPDATE": true,
			"DELETE": true,
		},
		allowedTables: map[string]bool{
			"active_subscribers":       true,
			"active_subscribers_table": true,
			"profiles":                 true,
		},
	}
}

// verifyWebhookSecret securely compares provided secret with configured secret
func (h *WebhookHandler) verifyWebhookSecret(providedSecret string) bool {
	if h.secretKey == "" || providedSecret == "" {
		return false
	}

	return subtle.ConstantTimeCompare(
		[]byte(providedSecret),
		[]byte(h.secretKey),
	) == 1
}

// parseWebhookPayload safely parses and validates webhook payload
func (h *WebhookHandler) parseWebhookPayload(body io.Reader) (*WebhookPayload, error) {
	// Parse webhook payload
	var payload WebhookPayload
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(&payload); err != nil {
		return nil, fmt.Errorf("invalid payload format: %w", err)
	}

	// Validate webhook payload
	if payload.Type == "" {
		return nil, fmt.Errorf("missing required field: type")
	}

	if payload.Table == "" {
		return nil, fmt.Errorf("missing required field: table")
	}

	// Validate operation type
	if !h.allowedTypes[payload.Type] {
		return nil, fmt.Errorf("invalid webhook type: %s", payload.Type)
	}

	// Check if this is a relevant table
	if !h.allowedTables[payload.Table] {
		return nil, fmt.Errorf("unsupported table: %s", payload.Table)
	}

	return &payload, nil
}

// EnforceWebhookSigning is a middleware that verifies webhook requests
func (h *WebhookHandler) EnforceWebhookSigning(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Basic method and content-type validation
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		contentType := r.Header.Get("Content-Type")
		if contentType != "application/json" {
			http.Error(w, "Invalid content type", http.StatusUnsupportedMediaType)
			return
		}

		// Extract and verify webhook signature
		headerSecret := r.Header.Get("X-Webhook-Secret")
		if headerSecret == "" {
			headerSecret = r.Header.Get("secret")
		}

		if !h.verifyWebhookSecret(headerSecret) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Proceed to next handler
		next.ServeHTTP(w, r)
	})
}

// HandleWebhook processes incoming webhook requests
func (h *WebhookHandler) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	// Limit request body size to prevent abuse
	r.Body = http.MaxBytesReader(w, r.Body, maxWebhookBodySize)

	// Set a timeout
	ctx, cancel := context.WithTimeout(r.Context(), webhookTimeout)
	defer cancel()
	r = r.WithContext(ctx)

	// Basic validation
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "Invalid content type", http.StatusUnsupportedMediaType)
		return
	}

	// Verify webhook signature backup check
	headerSecret := r.Header.Get("X-Webhook-Secret")
	if headerSecret == "" {
		headerSecret = r.Header.Get("secret")
	}

	if !h.verifyWebhookSecret(headerSecret) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse webhook payload
	payload, err := h.parseWebhookPayload(r.Body)
	if err != nil {
		h.service.logger.Printf("Failed to parse webhook payload: %v", err)
		http.Error(w, fmt.Sprintf("Invalid payload: %v", err), http.StatusBadRequest)
		return
	}

	// Process webhook
	func() {
		defer func() {
			if r := recover(); r != nil {
				h.service.logger.Printf("Panic in webhook handler: %v", r)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
		}()

		switch payload.Type {
		case "INSERT", "UPDATE":
			if err := h.handleUserUpsert(payload.Record); err != nil {
				h.service.logger.Printf("Failed to handle user upsert: %v", err)
				http.Error(w, "Failed to process user data", http.StatusBadRequest)
				return
			}

		case "DELETE":
			if err := h.handleUserDelete(payload.Record); err != nil {
				h.service.logger.Printf("Failed to handle user delete: %v", err)
				http.Error(w, "Failed to process deletion", http.StatusBadRequest)
				return
			}
		}
	}()

	w.WriteHeader(http.StatusOK)
}

// handleUserUpsert processes a user insert or update webhook
func (h *WebhookHandler) handleUserUpsert(record map[string]interface{}) error {

	userData, err := h.service.parseUserData(record)
	if err != nil {
		return fmt.Errorf("failed to parse user data: %w", err)
	}

	// Add the user to cache
	if err := h.service.cache.SetUser(userData); err != nil {
		return fmt.Errorf("failed to update cache: %w", err)
	}

	h.service.logger.Printf("Updated cache for user %s via webhook", userData.ID)
	return nil
}

// handleUserDelete processes a user deletion webhook
func (h *WebhookHandler) handleUserDelete(record map[string]interface{}) error {
	// Try to extract user ID from various keys
	var userID string
	for _, key := range []string{"id", "uuid", "user_id"} {
		if val, ok := record[key].(string); ok && val != "" {
			userID = val
			break
		}
	}

	if userID == "" {
		return fmt.Errorf("invalid or missing user ID in delete record")
	}

	// Remove the user from cache
	if err := h.service.cache.DeleteUser(userID); err != nil {
		return fmt.Errorf("failed to delete from cache: %w", err)
	}

	h.service.logger.Printf("Removed user %s from cache via webhook", userID)
	return nil
}

// RegisterWebhookHandlers sets up the webhook routes
func RegisterWebhookHandlers(router *http.ServeMux, authService *AuthService) {
	handler := NewWebhookHandler(authService, authService.config.SBase.SupabaseSecret)

	// Create the handler chain with middleware
	handlerChain := handler.EnforceWebhookSigning(
		http.HandlerFunc(handler.HandleWebhook),
	)

	// Register webhook endpoints
	router.Handle("/admin/updates", handlerChain)
	router.Handle("/webhook/auth", handlerChain)
}
