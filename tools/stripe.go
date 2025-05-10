package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/checkout/session"
	"github.com/stripe/stripe-go/v82/customer"
	"github.com/stripe/stripe-go/v82/invoice"
	"github.com/stripe/stripe-go/v82/paymentmethod"
	"github.com/stripe/stripe-go/v82/product"
	"github.com/stripe/stripe-go/v82/subscription"
	"github.com/stripe/stripe-go/v82/webhook"
	"github.com/the-muppet/supabase-go"
)

type StripeConfig struct {
	APIKey        string `json:"api_key"`
	WebhookSecret string `json:"webhook_secret"`
	SuccessURL    string `json:"success_url"`
	CancelURL     string `json:"cancel_url"`
}

// StripeService handles all Stripe integration
type StripeService struct {
	client           *supabase.Client
	auth             *supabase.Auth
	apiKey           string
	webhookSecret    string
	productTierMap   map[string]string
	successURL       string
	cancelURL        string
	billingPortalURL string
}

// NewStripeService creates a new Stripe service
func NewStripeService(
	client *supabase.Client,
	auth *supabase.Auth,
	apiKey string,
	webhookSecret string,
	successURL string,
	cancelURL string,
	billingPortalURL string,
) *StripeService {
	// Initialize Stripe with API key
	stripe.Key = apiKey

	return &StripeService{
		client:           client,
		auth:             auth,
		apiKey:           apiKey,
		webhookSecret:    webhookSecret,
		productTierMap:   make(map[string]string),
		successURL:       successURL,
		cancelURL:        cancelURL,
		billingPortalURL: billingPortalURL,
	}
}

// LoadProductTierMapping loads the mapping from Stripe products to application tiers
func (s *StripeService) LoadProductTierMapping(ctx context.Context) error {
	// Query the database for product to tier mapping
	var products []map[string]interface{}
	err := s.client.DB.From("stripe_products").
		Select("id,metadata").
		Execute(&products)

	if err != nil {
		return fmt.Errorf("failed to load product-tier mapping: %w", err)
	}

	// Reset the map
	s.productTierMap = make(map[string]string)

	// Process products
	for _, prod := range products {
		id, ok := prod["id"].(string)
		if !ok {
			continue
		}

		metadata, ok := prod["metadata"].(map[string]interface{})
		if !ok {
			continue
		}

		tier, ok := metadata["tier"].(string)
		if ok && tier != "" {
			s.productTierMap[id] = tier
		}
	}

	return nil
}

// StripeHandler is the main HTTP handler for Stripe-related routes
func (s *StripeService) StripeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch path {
		case "/api/stripe/create-checkout":
			s.HandleCreateCheckoutSession(w, r)
		case "/api/stripe/subscription-success":
			s.HandleSubscriptionSuccess(w, r)
		case "/api/stripe/subscription-cancel":
			s.HandleSubscriptionCancel(w, r)
		case "/api/stripe/webhook":
			s.HandleStripeWebhook(w, r)
		case "/api/stripe/subscription":
			s.HandleGetSubscription(w, r)
		case "/api/stripe/subscription/update":
			s.HandleUpdateSubscription(w, r)
		case "/api/stripe/subscription/cancel":
			s.HandleCancelSubscription(w, r)
		case "/api/stripe/subscription/reactivate":
			s.HandleReactivateSubscription(w, r)
		case "/api/stripe/create-billing-portal":
			s.HandleCreateBillingPortal(w, r)
		case "/api/stripe/payment-methods":
			s.HandleGetPaymentMethods(w, r)
		case "/api/stripe/payment-methods/add":
			s.HandleAddPaymentMethod(w, r)
		case "/api/stripe/payment-methods/default":
			s.HandleSetDefaultPaymentMethod(w, r)
		case "/api/stripe/payment-methods/remove":
			s.HandleRemovePaymentMethod(w, r)
		case "/api/stripe/invoices":
			s.HandleGetInvoices(w, r)
		case "/api/stripe/upcoming-invoice":
			s.HandleGetUpcomingInvoice(w, r)
		default:
			http.NotFound(w, r)
		}
	}
}

// Response types
type ErrorResponse struct {
	Error string `json:"error"`
}

type SuccessResponse struct {
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// CreateCheckoutSessionRequest represents the request to create a checkout session
type CreateCheckoutSessionRequest struct {
	PriceID     string `json:"price_id"`
	CustomerID  string `json:"customer_id,omitempty"`
	SuccessURL  string `json:"success_url,omitempty"`
	CancelURL   string `json:"cancel_url,omitempty"`
	TrialPeriod int64  `json:"trial_period,omitempty"`
}

// CreateCheckoutSessionResponse represents the response after creating a checkout session
type CreateCheckoutSessionResponse struct {
	SessionID   string `json:"session_id"`
	CheckoutURL string `json:"checkout_url"`
}

func respondWithError(w http.ResponseWriter, i int, s string) {
	http.Error(w, s, i)
}

func respondWithJSON(w http.ResponseWriter, i int, successResponse SuccessResponse) {
	panic("unimplemented")
}

// HandleCreateCheckoutSession creates a Stripe checkout for subscription
func (s *StripeService) HandleCreateCheckoutSession(w http.ResponseWriter, r *http.Request) {
	// Check if this is a POST request
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get user ID from context or JWT
	userID, err := getUserIDFromRequest(r, s.auth, s.client)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse request
	var req CreateCheckoutSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Validate input
	if req.PriceID == "" {
		respondWithError(w, http.StatusBadRequest, "Price ID is required")
		return
	}

	// Get or create customer
	customerID, err := s.getOrCreateCustomer(r.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get or create customer: %v", err))
		return
	}

	// Use custom URLs if provided, otherwise use default
	successURL := s.successURL
	if req.SuccessURL != "" {
		successURL = req.SuccessURL
	}

	cancelURL := s.cancelURL
	if req.CancelURL != "" {
		cancelURL = req.CancelURL
	}

	// Create checkout session parameters
	params := &stripe.CheckoutSessionParams{
		Customer: stripe.String(customerID),
		Mode:     stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(req.PriceID),
				Quantity: stripe.Int64(1),
			},
		},
		SuccessURL: stripe.String(successURL),
		CancelURL:  stripe.String(cancelURL),
	}

	// Create checkout session
	session, err := session.New(params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to create checkout session: %v", err))
		return
	}

	// Return checkout URL
	response := CreateCheckoutSessionResponse{
		SessionID:   session.ID,
		CheckoutURL: session.URL,
	}

	respondWithJSON(w, http.StatusOK, response)
}

// HandleSubscriptionSuccess processes successful subscription
func (s *StripeService) HandleSubscriptionSuccess(w http.ResponseWriter, r *http.Request) {
	// Get session ID from query parameters
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		respondWithError(w, http.StatusBadRequest, "Session ID is required")
		return
	}

	// Retrieve checkout session
	sess, err := session.Get(sessionID, nil)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to retrieve session: %v", err))
		return
	}

	// Get customer ID
	customerID := sess.Customer.ID

	// Get user ID from customer
	userID, err := s.getUserIDFromCustomer(r.Context(), customerID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to retrieve user: %v", err))
		return
	}

	// Get subscription
	subscriptionID := sess.Subscription.ID
	if subscriptionID == "" {
		respondWithError(w, http.StatusInternalServerError, "No subscription found in session")
		return
	}

	// Update user subscription in database
	err = s.updateUserSubscription(r.Context(), userID, customerID, subscriptionID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to update subscription: %v", err))
		return
	}

	// Get subscription details
	sub, err := subscription.Get(subscriptionID, nil)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to retrieve subscription: %v", err))
		return
	}

	// Get product ID from subscription
	productID := ""
	if len(sub.Items.Data) > 0 {
		productID = sub.Items.Data[0].Price.Product.ID
	}

	// Map product to tier and update user tier
	if productID != "" {
		tierName, ok := s.productTierMap[productID]
		if ok && tierName != "" {
			err = s.auth.UpdateUserTier(r.Context(), userID, tierName)
			if err != nil {
				// Log error but continue
				fmt.Printf("Failed to update user tier: %v\n", err)
			}
		} else {
			// Try to get tier from metadata
			prod, err := product.Get(productID, nil)
			if err == nil {
				if tierName, ok := prod.Metadata["tier"]; ok && tierName != "" {
					err = s.auth.UpdateUserTier(r.Context(), userID, tierName)
					if err != nil {
						// Log error but continue
						fmt.Printf("Failed to update user tier: %v\n", err)
					}
				}
			}
		}
	}

	// Redirect to success page
	http.Redirect(w, r, s.successURL, http.StatusSeeOther)
}

// HandleSubscriptionCancel handles subscription cancellation
func (s *StripeService) HandleSubscriptionCancel(w http.ResponseWriter, r *http.Request) {
	// Simply redirect to cancel URL
	http.Redirect(w, r, s.cancelURL, http.StatusSeeOther)
}

// HandleStripeWebhook processes Stripe webhook events
func (s *StripeService) HandleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	// Read request body
	payload, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Failed to read request body")
		return
	}

	// Get Stripe signature from header
	sig := r.Header.Get("Stripe-Signature")
	if sig == "" {
		respondWithError(w, http.StatusBadRequest, "Stripe signature missing")
		return
	}

	// Verify webhook signature
	event, err := webhook.ConstructEvent(payload, sig, s.webhookSecret)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, fmt.Sprintf("Invalid webhook signature: %v", err))
		return
	}

	// Process event based on type
	switch event.Type {
	case "checkout.session.completed":
		err = s.processCheckoutSessionCompleted(r.Context(), event)
	case "customer.subscription.created":
		err = s.processSubscriptionCreated(r.Context(), event)
	case "customer.subscription.updated":
		err = s.processSubscriptionUpdated(r.Context(), event)
	case "customer.subscription.deleted":
		err = s.processSubscriptionDeleted(r.Context(), event)
	case "invoice.payment_failed":
		err = s.processPaymentFailed(r.Context(), event)
	case "invoice.paid":
		err = s.processInvoicePaid(r.Context(), event)
	case "customer.updated":
		err = s.processCustomerUpdated(r.Context(), event)
	}

	if err != nil {
		// Log error but return 200 to Stripe to acknowledge receipt
		fmt.Printf("Error processing webhook: %v\n", err)
	}

	// Return success to Stripe
	respondWithJSON(w, http.StatusOK, SuccessResponse{
		Message: "Webhook processed successfully",
	})
}

// processCheckoutSessionCompleted handles checkout.session.completed event
func (s *StripeService) processCheckoutSessionCompleted(ctx context.Context, event stripe.Event) error {
	var session stripe.CheckoutSession
	err := json.Unmarshal(event.Data.Raw, &session)
	if err != nil {
		return fmt.Errorf("failed to unmarshal session: %w", err)
	}

	// Skip if not subscription mode
	if session.Mode != stripe.CheckoutSessionModeSubscription {
		return nil
	}

	// Skip if no subscription
	if session.Subscription == nil {
		return nil
	}

	// Get customer ID
	customerID := session.Customer.ID
	if customerID == "" {
		return errors.New("no customer in session")
	}

	// Get user ID from customer
	userID, err := s.getUserIDFromCustomer(ctx, customerID)
	if err != nil {
		return fmt.Errorf("failed to get user from customer: %w", err)
	}

	// Get subscription
	subscriptionID := session.Subscription.ID
	if subscriptionID == "" {
		return errors.New("no subscription in session")
	}

	// Update user subscription in database
	err = s.updateUserSubscription(ctx, userID, customerID, subscriptionID)
	if err != nil {
		return fmt.Errorf("failed to update subscription: %w", err)
	}

	// Get subscription details
	sub, err := subscription.Get(subscriptionID, nil)
	if err != nil {
		return fmt.Errorf("failed to get subscription: %w", err)
	}

	// Get product ID from subscription
	productID := ""
	if len(sub.Items.Data) > 0 {
		productID = sub.Items.Data[0].Price.Product.ID
	}

	// Map product to tier and update user tier
	if productID != "" {
		tierName, ok := s.productTierMap[productID]
		if ok && tierName != "" {
			err = s.auth.UpdateUserTier(ctx, userID, tierName)
			if err != nil {
				return fmt.Errorf("failed to update tier: %w", err)
			}
		} else {
			// Try to get tier from metadata
			prod, err := product.Get(productID, nil)
			if err == nil {
				if tierName, ok := prod.Metadata["tier"]; ok && tierName != "" {
					err = s.auth.UpdateUserTier(ctx, userID, tierName)
					if err != nil {
						return fmt.Errorf("failed to update tier: %w", err)
					}
				}
			}
		}
	}

	// Track subscription event
	err = s.trackSubscriptionEvent(ctx, userID, "subscription_created", map[string]interface{}{
		"subscription_id": subscriptionID,
		"customer_id":     customerID,
		"product_id":      productID,
	})
	if err != nil {
		return fmt.Errorf("failed to track event: %w", err)
	}

	return nil
}

// processSubscriptionCreated handles customer.subscription.created event
func (s *StripeService) processSubscriptionCreated(ctx context.Context, event stripe.Event) error {
	var sub stripe.Subscription
	err := json.Unmarshal(event.Data.Raw, &sub)
	if err != nil {
		return fmt.Errorf("failed to unmarshal subscription: %w", err)
	}

	// Get customer ID
	customerID := sub.Customer.ID
	if customerID == "" {
		return errors.New("no customer in subscription")
	}

	// Get user ID from customer
	userID, err := s.getUserIDFromCustomer(ctx, customerID)
	if err != nil {
		return fmt.Errorf("failed to get user from customer: %w", err)
	}

	// Update user subscription in database
	err = s.updateUserSubscription(ctx, userID, customerID, sub.ID)
	if err != nil {
		return fmt.Errorf("failed to update subscription: %w", err)
	}

	// Get product ID from subscription
	productID := ""
	if len(sub.Items.Data) > 0 {
		productID = sub.Items.Data[0].Price.Product.ID
	}

	// Map product to tier and update user tier
	if productID != "" {
		tierName, ok := s.productTierMap[productID]
		if ok && tierName != "" {
			oldTier, err := s.getUserTier(ctx, userID)
			if err == nil {
				err = s.auth.UpdateUserTier(ctx, userID, tierName)
				if err != nil {
					return fmt.Errorf("failed to update tier: %w", err)
				}

				// Track tier change
				err = s.trackTierChanges(ctx, userID, oldTier, tierName)
				if err != nil {
					return fmt.Errorf("failed to track tier change: %w", err)
				}
			}
		}
	}

	// Track subscription event
	err = s.trackSubscriptionEvent(ctx, userID, "subscription_created", map[string]interface{}{
		"subscription_id": sub.ID,
		"customer_id":     customerID,
		"product_id":      productID,
	})
	if err != nil {
		return fmt.Errorf("failed to track event: %w", err)
	}

	return nil
}

// processSubscriptionUpdated handles customer.subscription.updated event
func (s *StripeService) processSubscriptionUpdated(ctx context.Context, event stripe.Event) error {
	var sub stripe.Subscription
	err := json.Unmarshal(event.Data.Raw, &sub)
	if err != nil {
		return fmt.Errorf("failed to unmarshal subscription event data: %w", err)
	}

	// Get customer ID from the subscription object
	customerID := sub.Customer.ID
	if customerID == "" {
		return errors.New("no customer ID found in subscription event")
	}

	userID, err := s.getUserIDFromCustomer(ctx, customerID)
	if err != nil {
		// If we can't link the customer, we can't update their tier. Log and return.
		fmt.Printf("WARN: Could not find user ID for customer %s during subscription update. Error: %v\n", customerID, err)
		return fmt.Errorf("failed to get user ID from customer %s: %w", customerID, err)
	}

	// get the new product ID and price ID from the subscription object
	var newProductID string
	var newPriceID string
	if len(sub.Items.Data) > 0 && sub.Items.Data[0].Price != nil {
		newPriceID = sub.Items.Data[0].Price.ID
		if sub.Items.Data[0].Price.Product != nil {
			newProductID = sub.Items.Data[0].Price.Product.ID
		} else {
			fmt.Printf("WARN: Subscription item %s for user %s is missing product information.\n", sub.Items.Data[0].ID, userID)
			return fmt.Errorf("subscription item %s is missing product information", sub.Items.Data[0].ID)
		}
	} else {
		fmt.Printf("WARN: Subscription %s for user %s has no items or price data.\n", sub.ID, userID)
		return fmt.Errorf("subscription %s has no items or price data", sub.ID)
	}

	newTierName := "free" // Default to free if we can't determine the tier
	if newProductID != "" {
		var tierErr error
		newTierName, tierErr = s.getTierFromProduct(ctx, newProductID)
		if tierErr != nil {
			// Log the error, but continue (in case of unmapped|new product)
			fmt.Printf("WARN: Could not map product ID %s to a tier for user %s. Error: %v\n", newProductID, userID, tierErr)
		}
	}

	// get users current tier from supabase
	oldTier, tierErr := s.getUserTier(ctx, userID)
	if tierErr != nil {
		fmt.Printf("WARN: Could not retrieve current tier for user %s. Error: %v\n", userID, tierErr)
		oldTier = "" // Assume unknown or no previous tier for comparison purposes
	}

	// Compare the new tier and old tier and update if different
	if newTierName != "" && newTierName != oldTier {
		fmt.Printf("INFO: Tier change detected for user %s. Old: '%s', New: '%s' (from product %s)\n", userID, oldTier, newTierName, newProductID)
		err = s.auth.UpdateUserTier(ctx, userID, newTierName)
		if err != nil {
			// Log the error, continue
			fmt.Printf("ERROR: Failed to update user %s tier to %s: %v\n", userID, newTierName, err)
		} else {
			// Tier updated successfully, track the change
			err = s.trackTierChanges(ctx, userID, oldTier, newTierName)
			if err != nil {
				fmt.Printf("WARN: Failed to track tier change for user %s: %v\n", userID, err)
			}
		}
	} else if newTierName == "" && oldTier != "free" {
		fmt.Printf("INFO: User %s subscription updated to product %s which has no mapped tier. Current app tier is %s. Downgrading to free.\n", userID, newProductID, oldTier)
		err = s.downgradeToFreeTier(ctx, userID)
		if err != nil {
			fmt.Printf("ERROR: Failed to downgrade user %s to free tier after unmapped product update: %v\n", userID, err)
		} else {
			err = s.trackTierChanges(ctx, userID, oldTier, "free")
			if err != nil {
				fmt.Printf("WARN: Failed to track downgrade tier change for user %s: %v\n", userID, err)
			}
		}
	}

	subscriptionID := sub.ID
	var periodEnd *time.Time

	if sub.Items != nil && len(sub.Items.Data) > 0 {
		firstItem := sub.Items.Data[0]
		if firstItem.CurrentPeriodEnd > 0 {
			t := time.Unix(firstItem.CurrentPeriodEnd, 0)
			periodEnd = &t
			fmt.Printf("INFO: Using CurrentPeriodEnd from first item %s: %v\n", firstItem.ID, t)
		} else {
			fmt.Printf("WARN: First subscription item %s for subscription %s has invalid CurrentPeriodEnd timestamp (%d)\n", firstItem.ID, sub.ID, firstItem.CurrentPeriodEnd)
		}
	} else {
		fmt.Printf("WARN: Cannot determine period end for subscription %s because it has no items.\n", sub.ID)
	}

	updateParams := map[string]interface{}{
		"subscription_id":      subscriptionID,
		"customer_id":          customerID,
		"status":               string(sub.Status),
		"current_period_end":   periodEnd,
		"cancel_at_period_end": sub.CancelAtPeriodEnd,
		"updated_at":           time.Now(),
	}

	err := s.client.DB.From("stripe_customers").
		Update(updateParams).
		Eq("user_id", userID).
		Execute()

	eventDetails := map[string]interface{}{
		"subscription_id":      subscriptionID,
		"customer_id":          customerID,
		"new_product_id":       newProductID,
		"new_price_id":         newPriceID,
		"status":               string(sub.Status),
		"cancel_at_period_end": sub.CancelAtPeriodEnd,
		"event_timestamp":      time.Unix(event.Created, 0).UTC().Format(time.RFC3339),
	}

	if len(event.Data.PreviousAttributes) > 0 {
		var previousData map[string]interface{}
		if json.Unmarshal(event.Data.PreviousAttributes, &previousData) == nil {
			eventDetails["previous_attributes"] = previousData
		}
	}

	trackErr := s.trackSubscriptionEvent(ctx, userID, "subscription_updated", eventDetails)
	if trackErr != nil {
		fmt.Printf("WARN: Failed to track subscription_updated event for user %s: %v\n", userID, trackErr)
	}

	fmt.Printf("INFO: Successfully processed subscription update for user %s (Sub ID: %s)\n", userID, subscriptionID)
	return nil
}

// processSubscriptionDeleted handles customer.subscription.deleted event
func (s *StripeService) processSubscriptionDeleted(ctx context.Context, event stripe.Event) error {
	var sub stripe.Subscription
	err := json.Unmarshal(event.Data.Raw, &sub)
	if err != nil {
		return fmt.Errorf("failed to unmarshal subscription: %w", err)
	}

	// Get customer ID
	customerID := sub.Customer.ID
	if customerID == "" {
		return errors.New("no customer in subscription")
	}

	// Get user ID from customer
	userID, err := s.getUserIDFromCustomer(ctx, customerID)
	if err != nil {
		return fmt.Errorf("failed to get user from customer: %w", err)
	}

	// Get current tier before downgrading
	oldTier, err := s.getUserTier(ctx, userID)
	if err != nil {
		oldTier = ""
	}

	// Downgrade to free tier
	err = s.downgradeToFreeTier(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to downgrade tier: %w", err)
	}

	// Clear subscription in database
	params := map[string]interface{}{
		"subscription_id":    nil,
		"current_period_end": nil,
		"updated_at":         time.Now(),
	}

	_, err = s.client.DB.From("stripe_customers").
		Update(params).
		Eq("user_id", userID).
		Execute(nil)
	if err != nil {
		return fmt.Errorf("failed to clear subscription: %w", err)
	}

	// Track tier change
	err = s.trackTierChanges(ctx, userID, oldTier, "free")
	if err != nil {
		return fmt.Errorf("failed to track tier change: %w", err)
	}

	// Track subscription event
	err = s.trackSubscriptionEvent(ctx, userID, "subscription_deleted", map[string]interface{}{
		"subscription_id": sub.ID,
		"customer_id":     customerID,
	})
	if err != nil {
		return fmt.Errorf("failed to track event: %w", err)
	}

	return nil
}

// processPaymentFailed handles invoice.payment_failed event
func (s *StripeService) processPaymentFailed(ctx context.Context, event stripe.Event) error {
	var inv stripe.Invoice
	err := json.Unmarshal(event.Data.Raw, &inv)
	if err != nil {
		return fmt.Errorf("failed to unmarshal invoice: %w", err)
	}

	// Get customer ID
	customerID := inv.Customer.ID
	if customerID == "" {
		return errors.New("no customer in invoice")
	}

	// Get user ID from customer
	userID, err := s.getUserIDFromCustomer(ctx, customerID)
	if err != nil {
		return fmt.Errorf("failed to get user from customer: %w", err)
	}

	// Get subscription ID
	subscriptionID := ""
	if inv.Subscription != nil {
		subscriptionID = inv.Subscription.ID
	}

	// Track payment failure
	err = s.trackSubscriptionEvent(ctx, userID, "payment_failed", map[string]interface{}{
		"invoice_id":      inv.ID,
		"customer_id":     customerID,
		"subscription_id": subscriptionID,
		"amount_due":      inv.AmountDue,
		"attempt_count":   inv.AttemptCount,
	})
	if err != nil {
		return fmt.Errorf("failed to track event: %w", err)
	}

	// If subscription is still active, no need to downgrade yet
	if subscriptionID != "" {
		sub, err := subscription.Get(subscriptionID, nil)
		if err == nil && sub.Status != stripe.SubscriptionStatusUnpaid && sub.Status != stripe.SubscriptionStatusIncomplete {
			return nil
		}
	}

	// If payment is still failing after multiple attempts, downgrade to free tier
	if inv.AttemptCount > 3 {
		// Get current tier before downgrading
		oldTier, err := s.getUserTier(ctx, userID)
		if err != nil {
			oldTier = ""
		}

		// Downgrade to free tier
		err = s.downgradeToFreeTier(ctx, userID)
		if err != nil {
			return fmt.Errorf("failed to downgrade tier: %w", err)
		}

		// Track tier change
		err = s.trackTierChanges(ctx, userID, oldTier, "free")
		if err != nil {
			return fmt.Errorf("failed to track tier change: %w", err)
		}
	}

	return nil
}

// processInvoicePaid handles invoice.paid event
func (s *StripeService) processInvoicePaid(ctx context.Context, event stripe.Event) error {
	var inv stripe.Invoice
	err := json.Unmarshal(event.Data.Raw, &inv)
	if err != nil {
		return fmt.Errorf("failed to unmarshal invoice: %w", err)
	}

	// Get customer ID
	customerID := inv.Customer.ID
	if customerID == "" {
		return errors.New("no customer in invoice")
	}

	// Get user ID from customer
	userID, err := s.getUserIDFromCustomer(ctx, customerID)
	if err != nil {
		return fmt.Errorf("failed to get user from customer: %w", err)
	}

	// Get subscription ID
	subscriptionID := ""
	if inv.Subscription != nil {
		subscriptionID = inv.Subscription.ID
	}

	// Track payment success
	err = s.trackSubscriptionEvent(ctx, userID, "payment_succeeded", map[string]interface{}{
		"invoice_id":      inv.ID,
		"customer_id":     customerID,
		"subscription_id": subscriptionID,
		"amount_paid":     inv.AmountPaid,
		"invoice_number":  inv.Number,
	})
	if err != nil {
		return fmt.Errorf("failed to track event: %w", err)
	}

	return nil
}

// processCustomerUpdated handles customer.updated event
func (s *StripeService) processCustomerUpdated(ctx context.Context, event stripe.Event) error {
	var cust stripe.Customer
	err := json.Unmarshal(event.Data.Raw, &cust)
	if err != nil {
		return fmt.Errorf("failed to unmarshal customer: %w", err)
	}

	// Get user ID from customer
	userID, err := s.getUserIDFromCustomer(ctx, cust.ID)
	if err != nil {
		return fmt.Errorf("failed to get user from customer: %w", err)
	}

	// Check if default payment method changed
	var oldDefaultPaymentMethod string
	var previousObj map[string]interface{}
	err = json.Unmarshal(event.Data.PreviousAttributes, &previousObj)
	if err == nil {
		if pm, ok := previousObj["invoice_settings"].(map[string]interface{}); ok {
			if dpm, ok := pm["default_payment_method"].(map[string]interface{}); ok {
				if id, ok := dpm["id"].(string); ok {
					oldDefaultPaymentMethod = id
				}
			}
		}
	}

	// Get new default payment method
	newDefaultPaymentMethod := ""
	if cust.InvoiceSettings.DefaultPaymentMethod != nil {
		newDefaultPaymentMethod = cust.InvoiceSettings.DefaultPaymentMethod.ID
	}

	// If default payment method changed, track event
	if oldDefaultPaymentMethod != "" && newDefaultPaymentMethod != "" && oldDefaultPaymentMethod != newDefaultPaymentMethod {
		err = s.trackSubscriptionEvent(ctx, userID, "payment_method_changed", map[string]interface{}{
			"customer_id":           cust.ID,
			"old_payment_method_id": oldDefaultPaymentMethod,
			"new_payment_method_id": newDefaultPaymentMethod,
		})
		if err != nil {
			return fmt.Errorf("failed to track event: %w", err)
		}
	}

	return nil
}

// SubscriptionDetailsResponse represents the response for subscription details
type SubscriptionDetailsResponse struct {
	ID                string    `json:"id"`
	CustomerID        string    `json:"customer_id"`
	Status            string    `json:"status"`
	CurrentPeriodEnd  time.Time `json:"current_period_end"`
	CancelAtPeriodEnd bool      `json:"cancel_at_period_end"`
	ProductID         string    `json:"product_id"`
	ProductName       string    `json:"product_name"`
	Price             int64     `json:"price"`
	Currency          string    `json:"currency"`
	Interval          string    `json:"interval"`
	Tier              string    `json:"tier"`
}

// HandleGetSubscription gets current subscription details
func (s *StripeService) HandleGetSubscription(w http.ResponseWriter, r *http.Request) {
	// Check if this is a GET request
	if r.Method != http.MethodGet {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get user ID from context or JWT
	userID, err := getUserIDFromRequest(r, s.auth, s.client)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Get subscription details
	details, err := s.getSubscriptionDetails(r.Context(), userID)
	if err != nil {
		// If no subscription, return empty object with status inactive
		if err.Error() == "no subscription found" {
			respondWithJSON(w, http.StatusOK, &SubscriptionDetailsResponse{
				Status: "inactive",
			})
			return
		}

		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get subscription: %v", err))
		return
	}

	respondWithJSON(w, http.StatusOK, details)
}

// UpdateSubscriptionRequest represents the request to update a subscription
type UpdateSubscriptionRequest struct {
	PriceID string `json:"price_id"`
}

// HandleUpdateSubscription updates subscription tier
func (s *StripeService) HandleUpdateSubscription(w http.ResponseWriter, r *http.Request) {
	// Check if this is a POST request
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get user ID from context or JWT
	userID, err := getUserIDFromRequest(r, s.auth, s.client)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse request
	var req UpdateSubscriptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Validate input
	if req.PriceID == "" {
		respondWithError(w, http.StatusBadRequest, "Price ID is required")
		return
	}

	// Get current subscription
	subscriptionID, err := s.getUserSubscriptionID(r.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get subscription: %v", err))
		return
	}

	// Update subscription
	params := &stripe.SubscriptionParams{
		Items: []*stripe.SubscriptionItemsParams{
			{
				ID:    nil, // Will be set below
				Price: stripe.String(req.PriceID),
			},
		},
	}

	// Get subscription items
	sub, err := subscription.Get(subscriptionID, nil)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get subscription: %v", err))
		return
	}

	if len(sub.Items.Data) == 0 {
		respondWithError(w, http.StatusInternalServerError, "No subscription items found")
		return
	}

	// Set item ID
	params.Items[0].ID = stripe.String(sub.Items.Data[0].ID)

	// Update subscription
	updatedSub, err := subscription.Update(subscriptionID, params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to update subscription: %v", err))
		return
	}

	// Get new product ID
	productID := ""
	if len(updatedSub.Items.Data) > 0 {
		productID = updatedSub.Items.Data[0].Price.Product.ID
	}

	// Get current tier
	oldTier, err := s.getUserTier(r.Context(), userID)
	if err != nil {
		oldTier = ""
	}

	// Map product to tier and update user tier
	if productID != "" {
		tierName, ok := s.productTierMap[productID]
		if ok && tierName != "" {
			err = s.auth.UpdateUserTier(r.Context(), userID, tierName)
			if err != nil {
				// Log error but continue
				fmt.Printf("Failed to update tier: %v\n", err)
			} else {
				// Track tier change
				err = s.trackTierChanges(r.Context(), userID, oldTier, tierName)
				if err != nil {
					// Log error but continue
					fmt.Printf("Failed to track tier change: %v\n", err)
				}
			}
		} else {
			// Try to get tier from metadata
			prod, err := product.Get(productID, nil)
			if err == nil {
				if tierName, ok := prod.Metadata["tier"]; ok && tierName != "" {
					err = s.auth.UpdateUserTier(r.Context(), userID, tierName)
					if err != nil {
						// Log error but continue
						fmt.Printf("Failed to update tier: %v\n", err)
					} else {
						// Track tier change
						err = s.trackTierChanges(r.Context(), userID, oldTier, tierName)
						if err != nil {
							// Log error but continue
							fmt.Printf("Failed to track tier change: %v\n", err)
						}
					}
				}
			}
		}
	}

	// Get updated subscription details
	details, err := s.getSubscriptionDetails(r.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get updated subscription: %v", err))
		return
	}

	respondWithJSON(w, http.StatusOK, details)
}

// HandleCancelSubscription cancels subscription
func (s *StripeService) HandleCancelSubscription(w http.ResponseWriter, r *http.Request) {
	// Check if this is a POST request
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get user ID from context or JWT
	userID, err := getUserIDFromRequest(r, s.auth, s.client)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Get current subscription
	subscriptionID, err := s.getUserSubscriptionID(r.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get subscription: %v", err))
		return
	}

	// Cancel subscription at period end
	params := &stripe.SubscriptionParams{
		CancelAtPeriodEnd: stripe.Bool(true),
	}

	// Update subscription
	_, err = subscription.Update(subscriptionID, params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to cancel subscription: %v", err))
		return
	}

	// Get updated subscription details
	details, err := s.getSubscriptionDetails(r.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get updated subscription: %v", err))
		return
	}

	respondWithJSON(w, http.StatusOK, details)
}

// HandleReactivateSubscription reactivates cancelled subscription
func (s *StripeService) HandleReactivateSubscription(w http.ResponseWriter, r *http.Request) {
	// Check if this is a POST request
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get user ID from context or JWT
	userID, err := getUserIDFromRequest(r, s.auth, s.client)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Get current subscription
	subscriptionID, err := s.getUserSubscriptionID(r.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get subscription: %v", err))
		return
	}

	// Reactivate subscription
	params := &stripe.SubscriptionParams{
		CancelAtPeriodEnd: stripe.Bool(false),
	}

	// Update subscription
	_, err = subscription.Update(subscriptionID, params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to reactivate subscription: %v", err))
		return
	}

	// Get updated subscription details
	details, err := s.getSubscriptionDetails(r.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get updated subscription: %v", err))
		return
	}

	respondWithJSON(w, http.StatusOK, details)
}

// BillingPortalResponse represents the response for creating a billing portal session
type BillingPortalResponse struct {
	URL string `json:"url"`
}

// HandleCreateBillingPortal creates customer portal session
func (s *StripeService) HandleCreateBillingPortal(w http.ResponseWriter, r *http.Request) {
	// Check if this is a POST request
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get user ID from context or JWT
	userID, err := getUserIDFromRequest(r, s.auth, s.client)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Get customer ID
	customerID, err := s.getUserCustomerID(r.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get customer: %v", err))
		return
	}

	// Create billing portal session
	session, err := s.createBillingPortalSession(customerID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to create portal session: %v", err))
		return
	}

	// Return portal URL
	response := BillingPortalResponse{
		URL: session,
	}

	respondWithJSON(w, http.StatusOK, response)
}

// HandleGetPaymentMethods gets user's payment methods
func (s *StripeService) HandleGetPaymentMethods(w http.ResponseWriter, r *http.Request) {
	// Check if this is a GET request
	if r.Method != http.MethodGet {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get user ID from context or JWT
	userID, err := getUserIDFromRequest(r, s.auth, s.client)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Get customer ID
	customerID, err := s.getUserCustomerID(r.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get customer: %v", err))
		return
	}

	// Get payment methods
	methods, err := s.getPaymentMethods(customerID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get payment methods: %v", err))
		return
	}

	respondWithJSON(w, http.StatusOK, SuccessResponse{
		Message: "Payment methods retrieved successfully",
		Data:    methods,
	})
}

// SetupIntentResponse represents the response for creating a setup intent
type SetupIntentResponse struct {
	ClientSecret string `json:"client_secret"`
}

// HandleAddPaymentMethod adds a new payment method
func (s *StripeService) HandleAddPaymentMethod(w http.ResponseWriter, r *http.Request) {
	// Check if this is a POST request
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get user ID from context or JWT
	userID, err := getUserIDFromRequest(r, s.auth, s.client)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Get customer ID
	customerID, err := s.getUserCustomerID(r.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get customer: %v", err))
		return
	}

	// Create setup intent
	setupIntent, err := s.createSetupIntent(customerID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to create setup intent: %v", err))
		return
	}

	// Return client secret
	response := SetupIntentResponse{
		ClientSecret: setupIntent,
	}

	respondWithJSON(w, http.StatusOK, response)
}

// SetDefaultPaymentMethodRequest represents the request to set a default payment method
type SetDefaultPaymentMethodRequest struct {
	PaymentMethodID string `json:"payment_method_id"`
}

// HandleSetDefaultPaymentMethod sets default payment method
func (s *StripeService) HandleSetDefaultPaymentMethod(w http.ResponseWriter, r *http.Request) {
	// Check if this is a POST request
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get user ID from context or JWT
	userID, err := getUserIDFromRequest(r, s.auth, s.client)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse request
	var req SetDefaultPaymentMethodRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Validate input
	if req.PaymentMethodID == "" {
		respondWithError(w, http.StatusBadRequest, "Payment method ID is required")
		return
	}

	// Get customer ID
	customerID, err := s.getUserCustomerID(r.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get customer: %v", err))
		return
	}

	// Set default payment method
	err = s.setDefaultPaymentMethod(customerID, req.PaymentMethodID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to set default payment method: %v", err))
		return
	}

	// Get updated payment methods
	methods, err := s.getPaymentMethods(customerID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get payment methods: %v", err))
		return
	}

	respondWithJSON(w, http.StatusOK, methods)
}

// RemovePaymentMethodRequest represents the request to remove a payment method
type RemovePaymentMethodRequest struct {
	PaymentMethodID string `json:"payment_method_id"`
}

// HandleRemovePaymentMethod removes a payment method
func (s *StripeService) HandleRemovePaymentMethod(w http.ResponseWriter, r *http.Request) {
	// Check if this is a POST request
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get user ID from context or JWT
	userID, err := getUserIDFromRequest(r, s.auth, s.client)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse request
	var req RemovePaymentMethodRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Validate input
	if req.PaymentMethodID == "" {
		respondWithError(w, http.StatusBadRequest, "Payment method ID is required")
		return
	}

	// Get customer ID
	customerID, err := s.getUserCustomerID(r.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get customer: %v", err))
		return
	}

	// Remove payment method
	err = s.removePaymentMethod(req.PaymentMethodID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to remove payment method: %v", err))
		return
	}

	// Get updated payment methods
	methods, err := s.getPaymentMethods(customerID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get payment methods: %v", err))
		return
	}

	respondWithJSON(w, http.StatusOK, methods)
}

// HandleGetInvoices gets user's invoice history
func (s *StripeService) HandleGetInvoices(w http.ResponseWriter, r *http.Request) {
	// Check if this is a GET request
	if r.Method != http.MethodGet {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get user ID from context or JWT
	userID, err := getUserIDFromRequest(r, s.auth, s.client)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Get customer ID
	customerID, err := s.getUserCustomerID(r.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get customer: %v", err))
		return
	}

	// Get invoices
	invoices, err := s.getInvoices(customerID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get invoices: %v", err))
		return
	}

	respondWithJSON(w, http.StatusOK, invoices)
}

// HandleGetUpcomingInvoice gets user's upcoming invoice
func (s *StripeService) HandleGetUpcomingInvoice(w http.ResponseWriter, r *http.Request) {
	// Check if this is a GET request
	if r.Method != http.MethodGet {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get user ID from context or JWT
	userID, err := getUserIDFromRequest(r, s.auth, s.client)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Get customer ID
	customerID, err := s.getUserCustomerID(r.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get customer: %v", err))
		return
	}

	// Get subscription ID
	subscriptionID, err := s.getUserSubscriptionID(r.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get subscription: %v", err))
		return
	}

	// Get upcoming invoice
	upcomingInvoice, err := s.getUpcomingInvoice(customerID, subscriptionID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get upcoming invoice: %v", err))
		return
	}

	respondWithJSON(w, http.StatusOK, upcomingInvoice)
}

// Helper methods

// getOrCreateCustomer gets existing customer or creates a new one
func (s *StripeService) getOrCreateCustomer(ctx context.Context, userID string) (string, error) {
	// Check if customer already exists
	var customers []map[string]interface{}
	err := s.client.DB.From("stripe_customers").
		Select("customer_id").
		Eq("user_id", userID).
		Execute(&customers)

	if err == nil && len(customers) > 0 {
		if customerID, ok := customers[0]["customer_id"].(string); ok && customerID != "" {
			return customerID, nil
		}
	}

	// Get user email
	var profiles []map[string]interface{}
	err = s.client.DB.From("profiles").
		Select("email,full_name").
		Eq("id", userID).
		Execute(&profiles)

	if err != nil || len(profiles) == 0 {
		return "", errors.New("user profile not found")
	}

	email, ok := profiles[0]["email"].(string)
	if !ok || email == "" {
		return "", errors.New("user email not found")
	}

	// Get name (optional)
	name := ""
	if fullName, ok := profiles[0]["full_name"].(string); ok {
		name = fullName
	}

	// Create customer in Stripe
	params := &stripe.CustomerParams{
		Email: stripe.String(email),
	}

	if name != "" {
		params.Name = stripe.String(name)
	}

	params.AddMetadata("user_id", userID)

	cust, err := customer.New(params)
	if err != nil {
		return "", fmt.Errorf("failed to create Stripe customer: %w", err)
	}

	// Save customer in database
	customerData := map[string]interface{}{
		"user_id":     userID,
		"customer_id": cust.ID,
	}

	_, err = s.client.DB.From("stripe_customers").
		Insert(customerData).
		Execute(nil)

	if err != nil {
		return "", fmt.Errorf("failed to save customer: %w", err)
	}

	return cust.ID, nil
}

// updateUserSubscription updates user's subscription in database
func (s *StripeService) updateUserSubscription(ctx context.Context, userID, customerID, subscriptionID string) error {
	// Get subscription details
	sub, err := subscription.Get(subscriptionID, nil)
	if err != nil {
		return fmt.Errorf("failed to get subscription: %w", err)
	}

	// Get current period end
	var periodEnd time.Time
	if sub.CurrentPeriodEnd > 0 {
		periodEnd = time.Unix(sub.CurrentPeriodEnd, 0)
	}

	// Update or insert subscription
	subscriptionData := map[string]interface{}{
		"user_id":            userID,
		"customer_id":        customerID,
		"subscription_id":    subscriptionID,
		"current_period_end": periodEnd,
		"updated_at":         time.Now(),
	}

	// Check if customer exists
	var customers []map[string]interface{}
	err = s.client.DB.From("stripe_customers").
		Select("id").
		Eq("user_id", userID).
		Execute(&customers)

	if err == nil && len(customers) > 0 {
		// Update existing record
		_, err = s.client.DB.From("stripe_customers").
			Update(subscriptionData).
			Eq("user_id", userID).
			Execute(nil)
	} else {
		// Insert new record
		_, err = s.client.DB.From("stripe_customers").
			Insert(subscriptionData).
			Execute(nil)
	}

	if err != nil {
		return fmt.Errorf("failed to update subscription record: %w", err)
	}

	return nil
}

// getUserIDFromCustomer gets user ID from Stripe customer ID
func (s *StripeService) getUserIDFromCustomer(ctx context.Context, customerID string) (string, error) {
	// Check database first
	var customers []map[string]interface{}
	err := s.client.DB.From("stripe_customers").
		Select("user_id").
		Eq("customer_id", customerID).
		Execute(&customers)

	if err == nil && len(customers) > 0 {
		if userID, ok := customers[0]["user_id"].(string); ok && userID != "" {
			return userID, nil
		}
	}

	// If not found in database, check Stripe metadata
	cust, err := customer.Get(customerID, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get customer: %w", err)
	}

	if userID, ok := cust.Metadata["user_id"]; ok && userID != "" {
		return userID, nil
	}

	return "", errors.New("user ID not found for customer")
}

// getSubscriptionDetails gets detailed subscription information
func (s *StripeService) getSubscriptionDetails(ctx context.Context, userID string) (*SubscriptionDetailsResponse, error) {
	// Get subscription ID
	subscriptionID, err := s.getUserSubscriptionID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Get subscription details from Stripe
	sub, err := subscription.Get(subscriptionID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get subscription details: %w", err)
	}

	// Get product ID and price
	productID := ""
	productName := ""
	price := int64(0)
	currency := ""
	interval := ""

	if len(sub.Items.Data) > 0 {
		productID = sub.Items.Data[0].Price.Product.ID
		price = sub.Items.Data[0].Price.UnitAmount
		currency = string(sub.Items.Data[0].Price.Currency)
		interval = string(sub.Items.Data[0].Price.Recurring.Interval)

		// Get product name
		prod, err := product.Get(productID, nil)
		if err == nil {
			productName = prod.Name
		}
	}

	// Get tier from product
	tierName, _ := s.getTierFromProduct(ctx, productID)

	// Create response
	details := &SubscriptionDetailsResponse{
		ID:                sub.ID,
		CustomerID:        sub.Customer.ID,
		Status:            string(sub.Status),
		CurrentPeriodEnd:  time.Unix(sub.CurrentPeriodEnd, 0),
		CancelAtPeriodEnd: sub.CancelAtPeriodEnd,
		ProductID:         productID,
		ProductName:       productName,
		Price:             price,
		Currency:          currency,
		Interval:          interval,
		Tier:              tierName,
	}

	return details, nil
}

// getUserSubscriptionID gets user's subscription ID
func (s *StripeService) getUserSubscriptionID(ctx context.Context, userID string) (string, error) {
	var customers []map[string]interface{}
	err := s.client.DB.From("stripe_customers").
		Select("subscription_id").
		Eq("user_id", userID).
		Execute(&customers)

	if err != nil || len(customers) == 0 {
		return "", errors.New("no subscription found")
	}

	subscriptionID, ok := customers[0]["subscription_id"].(string)
	if !ok || subscriptionID == "" {
		return "", errors.New("no subscription found")
	}

	return subscriptionID, nil
}

// getUserCustomerID gets user's Stripe customer ID
func (s *StripeService) getUserCustomerID(ctx context.Context, userID string) (string, error) {
	var customers []map[string]interface{}
	err := s.client.DB.From("stripe_customers").
		Select("customer_id").
		Eq("user_id", userID).
		Execute(&customers)

	if err != nil || len(customers) == 0 {
		// Try to create customer
		customerID, err := s.getOrCreateCustomer(ctx, userID)
		if err != nil {
			return "", errors.New("no customer found")
		}
		return customerID, nil
	}

	customerID, ok := customers[0]["customer_id"].(string)
	if !ok || customerID == "" {
		return "", errors.New("no customer found")
	}

	return customerID, nil
}

// getTierFromProduct maps product ID to tier name
func (s *StripeService) getTierFromProduct(ctx context.Context, productID string) (string, error) {
	// Check cached map
	if tierName, ok := s.productTierMap[productID]; ok && tierName != "" {
		return tierName, nil
	}

	// Try to get from product metadata
	prod, err := product.Get(productID, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get product: %w", err)
	}

	if tierName, ok := prod.Metadata["tier"]; ok && tierName != "" {
		// Update cache
		s.productTierMap[productID] = tierName
		return tierName, nil
	}

	// Try to get from database
	var products []map[string]interface{}
	err = s.client.DB.From("stripe_products").
		Select("metadata").
		Eq("id", productID).
		Execute(&products)

	if err == nil && len(products) > 0 {
		if metadata, ok := products[0]["metadata"].(map[string]interface{}); ok {
			if tierName, ok := metadata["tier"].(string); ok && tierName != "" {
				// Update cache
				s.productTierMap[productID] = tierName
				return tierName, nil
			}
		}
	}

	return "", errors.New("tier not found for product")
}

// getUserTier gets user's current tier
func (s *StripeService) getUserTier(ctx context.Context, userID string) (string, error) {
	var result []map[string]interface{}
	err := s.client.DB.From("user_roles_and_tiers").
		Select("tiers").
		Eq("user_id", userID).
		Single().
		Execute(&result)

	if err != nil || len(result) == 0 {
		return "", errors.New("user tiers not found")
	}

	// Extract tier names from tiers JSON
	tiersData, ok := result[0]["tiers"].([]interface{})
	if !ok || len(tiersData) == 0 {
		return "", errors.New("no tiers found")
	}

	// Get first tier (assuming one tier per user)
	tierObj, ok := tiersData[0].(map[string]interface{})
	if !ok {
		return "", errors.New("invalid tier format")
	}

	tierName, ok := tierObj["name"].(string)
	if !ok || tierName == "" {
		return "", errors.New("tier name not found")
	}

	return tierName, nil
}

// downgradeToFreeTier downgrades user to free tier
func (s *StripeService) downgradeToFreeTier(ctx context.Context, userID string) error {
	return s.auth.UpdateUserTier(ctx, userID, "free")
}

// trackSubscriptionEvent records subscription events
func (s *StripeService) trackSubscriptionEvent(ctx context.Context, userID, eventType string, data map[string]interface{}) error {
	eventData := map[string]interface{}{
		"user_id":    userID,
		"event_type": eventType,
		"data":       data,
		"created_at": time.Now(),
	}

	_, err := s.client.DB.From("subscription_events").
		Insert(eventData).
		Execute(nil)

	return err
}

// trackTierChanges records tier changes
func (s *StripeService) trackTierChanges(ctx context.Context, userID, oldTier, newTier string) error {
	changeData := map[string]interface{}{
		"user_id":    userID,
		"old_tier":   oldTier,
		"new_tier":   newTier,
		"changed_at": time.Now(),
	}

	_, err := s.client.DB.From("tier_changes").
		Insert(changeData).
		Execute(nil)

	return err
}

// getPaymentMethods gets user's payment methods
func (s *StripeService) getPaymentMethods(customerID string) ([]map[string]interface{}, error) {
	// Get payment methods from Stripe
	params := &stripe.PaymentMethodListParams{
		Customer: stripe.String(customerID),
		Type:     stripe.String("card"),
	}

	methods := paymentmethod.List(params)

	// Get default payment method
	cust, err := customer.Get(customerID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get customer: %w", err)
	}

	defaultPaymentMethodID := ""
	if cust.InvoiceSettings.DefaultPaymentMethod != nil {
		defaultPaymentMethodID = cust.InvoiceSettings.DefaultPaymentMethod.ID
	}

	// Format payment methods
	var result []map[string]interface{}
	for methods.Next() {
		pm := methods.PaymentMethod()

		// Format card data
		cardData := map[string]interface{}{
			"brand":        string(pm.Card.Brand),
			"last4":        pm.Card.Last4,
			"exp_month":    pm.Card.ExpMonth,
			"exp_year":     pm.Card.ExpYear,
			"funding_type": string(pm.Card.Funding),
		}

		// Add to result
		result = append(result, map[string]interface{}{
			"id":   pm.ID,
			"type": pm.Type,
			"card": cardData,
			"billing_details": map[string]interface{}{
				"email": pm.BillingDetails.Email,
				"name":  pm.BillingDetails.Name,
			},
			"is_default": pm.ID == defaultPaymentMethodID,
		})
	}

	return result, nil
}

// createSetupIntent creates a setup intent for adding payment method
func (s *StripeService) createSetupIntent(customerID string) (string, error) {
	// Create setup intent
	params := &stripe.SetupIntentParams{
		Customer: stripe.String(customerID),
		Usage:    stripe.String("off_session"),
		PaymentMethodTypes: []*string{
			stripe.String("card"),
		},
	}

	si, err := stripe.SetupIntents.New(params)
	if err != nil {
		return "", fmt.Errorf("failed to create setup intent: %w", err)
	}

	return si.ClientSecret, nil
}

// setDefaultPaymentMethod sets default payment method
func (s *StripeService) setDefaultPaymentMethod(customerID, paymentMethodID string) error {
	// Update customer
	params := &stripe.CustomerParams{
		InvoiceSettings: &stripe.CustomerInvoiceSettingsParams{
			DefaultPaymentMethod: stripe.String(paymentMethodID),
		},
	}

	_, err := customer.Update(customerID, params)
	if err != nil {
		return fmt.Errorf("failed to update customer: %w", err)
	}

	return nil
}

// removePaymentMethod detaches payment method
func (s *StripeService) removePaymentMethod(paymentMethodID string) error {
	// Detach payment method
	_, err := paymentmethod.Detach(paymentMethodID, nil)
	if err != nil {
		return fmt.Errorf("failed to detach payment method: %w", err)
	}

	return nil
}

// getInvoices gets user's invoice history
func (s *StripeService) getInvoices(customerID string) ([]map[string]interface{}, error) {
	// Get invoices from Stripe
	params := &stripe.InvoiceListParams{
		Customer: stripe.String(customerID),
	}

	invoices := invoice.List(params)

	// Format invoices
	var result []map[string]interface{}
	for invoices.Next() {
		inv := invoices.Invoice()

		// Get line items
		var items []map[string]interface{}
		for _, item := range inv.Lines.Data {
			itemData := map[string]interface{}{
				"id":          item.ID,
				"description": item.Description,
				"amount":      item.Amount,
				"quantity":    item.Quantity,
			}

			// Add product info if available
			if item.Price != nil && item.Price.Product != nil {
				itemData["product_id"] = item.Price.Product.ID

				// Get product name
				prod, err := product.Get(item.Price.Product.ID, nil)
				if err == nil {
					itemData["product_name"] = prod.Name
				}
			}

			items = append(items, itemData)
		}

		// Format invoice data
		invoiceData := map[string]interface{}{
			"id":                inv.ID,
			"number":            inv.Number,
			"status":            string(inv.Status),
			"amount_due":        inv.AmountDue,
			"amount_paid":       inv.AmountPaid,
			"amount_remaining":  inv.AmountRemaining,
			"currency":          string(inv.Currency),
			"created_at":        time.Unix(inv.Created, 0),
			"due_date":          time.Unix(inv.DueDate, 0),
			"period_start":      time.Unix(inv.PeriodStart, 0),
			"period_end":        time.Unix(inv.PeriodEnd, 0),
			"payment_intent_id": inv.PaymentIntent.ID,
			"items":             items,
		}

		// Add hosted invoice URL if available
		if inv.HostedInvoiceURL != "" {
			invoiceData["hosted_invoice_url"] = inv.HostedInvoiceURL
		}

		// Add PDF URL if available
		if inv.InvoicePDF != "" {
			invoiceData["invoice_pdf"] = inv.InvoicePDF
		}

		result = append(result, invoiceData)
	}

	return result, nil
}

// getUpcomingInvoice gets user's upcoming invoice
func (s *StripeService) getUpcomingInvoice(customerID, subscriptionID string) (map[string]interface{}, error) {
	// Get upcoming invoice from Stripe
	params := &stripe.InvoiceParams{
		Customer:     stripe.String(customerID),
		Subscription: stripe.String(subscriptionID),
	}

	inv, err := invoice.GetNext(params)
	if err != nil {
		return nil, fmt.Errorf("failed to get upcoming invoice: %w", err)
	}

	// Get line items
	var items []map[string]interface{}
	for _, item := range inv.Lines.Data {
		itemData := map[string]interface{}{
			"id":          item.ID,
			"description": item.Description,
			"amount":      item.Amount,
			"quantity":    item.Quantity,
		}

		// Add product info if available
		if item.Price != nil && item.Price.Product != nil {
			itemData["product_id"] = item.Price.Product.ID

			// Get product name
			prod, err := product.Get(item.Price.Product.ID, nil)
			if err == nil {
				itemData["product_name"] = prod.Name
			}
		}

		items = append(items, itemData)
	}

	// Format invoice data
	invoiceData := map[string]interface{}{
		"amount_due":           inv.AmountDue,
		"amount_remaining":     inv.AmountRemaining,
		"currency":             string(inv.Currency),
		"period_start":         time.Unix(inv.PeriodStart, 0),
		"period_end":           time.Unix(inv.PeriodEnd, 0),
		"next_payment_attempt": time.Unix(inv.NextPaymentAttempt, 0),
		"items":                items,
	}

	return invoiceData, nil
}

// createBillingPortalSession creates a billing portal session
func (s *StripeService) createBillingPortalSession(customerID string) (string, error) {
	// Create billing portal session
	params := &stripe.BillingPortalSessionParams{
		Customer:  stripe.String(customerID),
		ReturnURL: stripe.String(s.billingPortalURL),
	}

	session, err := stripe.BillingPortalSessions.New(params)
	if err != nil {
		return "", fmt.Errorf("failed to create billing portal session: %w", err)
	}

	return session.URL, nil
}

// CreateTestSubscription creates a test subscription
func (s *StripeService) CreateTestSubscription(ctx context.Context, userID, tierName string) (string, error) {
	// Get customer ID
	customerID, err := s.getOrCreateCustomer(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("failed to get or create customer: %w", err)
	}

	// Get price ID for tier
	priceID, err := s.getPriceIDForTier(ctx, tierName)
	if err != nil {
		return "", fmt.Errorf("failed to get price for tier: %w", err)
	}

	// Create subscription
	params := &stripe.SubscriptionParams{
		Customer: stripe.String(customerID),
		Items: []*stripe.SubscriptionItemsParams{
			{
				Price:    stripe.String(priceID),
				Quantity: stripe.Int64(1),
			},
		},
	}

	sub, err := subscription.New(params)
	if err != nil {
		return "", fmt.Errorf("failed to create subscription: %w", err)
	}

	// Update user subscription in database
	err = s.updateUserSubscription(ctx, userID, customerID, sub.ID)
	if err != nil {
		return "", fmt.Errorf("failed to update subscription: %w", err)
	}

	// Update user tier
	err = s.auth.UpdateUserTier(ctx, userID, tierName)
	if err != nil {
		return "", fmt.Errorf("failed to update tier: %w", err)
	}

	return sub.ID, nil
}

// getPriceIDForTier gets price ID for a tier
func (s *StripeService) getPriceIDForTier(ctx context.Context, tierName string) (string, error) {
	// Query the database for product to price mapping
	var products []map[string]interface{}
	err := s.client.DB.From("stripe_products").
		Select("id,default_price,metadata").
		Execute(&products)

	if err != nil {
		return "", fmt.Errorf("failed to load products: %w", err)
	}

	// Find product for tier
	for _, prod := range products {
		metadata, ok := prod["metadata"].(map[string]interface{})
		if !ok {
			continue
		}

		tier, ok := metadata["tier"].(string)
		if !ok || tier != tierName {
			continue
		}

		// Get default price
		if priceID, ok := prod["default_price"].(string); ok && priceID != "" {
			return priceID, nil
		}
	}

	return "", fmt.Errorf("no price found for tier: %s", tierName)
}

// SimulateWebhookEvent simulates a Stripe webhook event
func (s *StripeService) SimulateWebhookEvent(ctx context.Context, eventType string, data map[string]interface{}) error {
	// Create event
	event := stripe.Event{
		Type: eventType,
		Data: &stripe.EventData{},
	}

	// Marshal data to JSON
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// Set event data
	json.Unmarshal(dataJSON, &event.Data.Raw)

	// Process event
	switch eventType {
	case "checkout.session.completed":
		err = s.processCheckoutSessionCompleted(ctx, event)
	case "customer.subscription.created":
		err = s.processSubscriptionCreated(ctx, event)
	case "customer.subscription.updated":
		err = s.processSubscriptionUpdated(ctx, event)
	case "customer.subscription.deleted":
		err = s.processSubscriptionDeleted(ctx, event)
	case "invoice.payment_failed":
		err = s.processPaymentFailed(ctx, event)
	default:
		return fmt.Errorf("unsupported event type: %s", eventType)
	}

	return err
}

// CleanupTestSubscriptions cleans up test data
func (s *StripeService) CleanupTestSubscriptions(ctx context.Context, userID string) error {
	// Get subscription ID
	subscriptionID, err := s.getUserSubscriptionID(ctx, userID)
	if err == nil && subscriptionID != "" {
		// Cancel subscription
		_, err = subscription.Cancel(subscriptionID, nil)
		if err != nil {
			return fmt.Errorf("failed to cancel subscription: %w", err)
		}
	}

	// Clear subscription in database
	params := map[string]interface{}{
		"subscription_id":    nil,
		"current_period_end": nil,
		"updated_at":         time.Now(),
	}

	_, err = s.client.DB.From("stripe_customers").
		Update(params).
		Eq("user_id", userID).
		Execute(nil)

	if err != nil {
		return fmt.Errorf("failed to clear subscription: %w", err)
	}

	// Downgrade to free tier
	err = s.downgradeToFreeTier(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to downgrade tier: %w", err)
	}

	return nil
}

// ValidateSubscriptionState checks if a user has the expected tier
func (s *StripeService) ValidateSubscriptionState(ctx context.Context, userID, expectedTier string) (bool, error) {
	// Get user tier
	userTier, err := s.getUserTier(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get user tier: %w", err)
	}

	return userTier == expectedTier, nil
}

// CalculateUserLifetimeValue calculates customer LTV
func (s *StripeService) CalculateUserLifetimeValue(ctx context.Context, userID string) (int64, error) {
	// Get customer ID
	customerID, err := s.getUserCustomerID(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("failed to get customer: %w", err)
	}

	// Get invoices
	params := &stripe.InvoiceListParams{
		Customer: stripe.String(customerID),
		Status:   stripe.String("paid"),
	}

	invoices := invoice.List(params)

	// Sum up paid amounts
	var total int64
	for invoices.Next() {
		inv := invoices.Invoice()
		total += inv.AmountPaid
	}

	return total, nil
}

// GenerateSubscriptionMetrics generates subscription metrics
func (s *StripeService) GenerateSubscriptionMetrics(ctx context.Context) (map[string]interface{}, error) {
	// Get all tiers
	var tiers []map[string]interface{}
	err := s.client.DB.Rpc("get_tiers", nil).Execute(&tiers)
	if err != nil {
		return nil, fmt.Errorf("failed to get tiers: %w", err)
	}

	// Calculate metrics for each tier
	tierMetrics := make(map[string]interface{})
	for _, tier := range tiers {
		tierName, ok := tier["name"].(string)
		if !ok || tierName == "" {
			continue
		}

		// Count users in this tier
		var result []map[string]interface{}
		query := fmt.Sprintf(`
			SELECT COUNT(*) as count
			FROM user_entities ue
			JOIN permission_entities pe ON ue.entity_id = pe.id
			WHERE pe.type = 'tier' AND pe.name = '%s'
		`, tierName)

		err := s.client.DB.Rpc("rpc", map[string]interface{}{
			"name": "run_query",
			"sql":  query,
		}).Execute(&result)

		if err != nil || len(result) == 0 {
			continue
		}

		count, ok := result[0]["count"].(float64)
		if !ok {
			continue
		}

		tierMetrics[tierName] = map[string]interface{}{
			"user_count": int(count),
		}
	}

	// Calculate total metrics
	var totalResult []map[string]interface{}
	query := `
		SELECT 
			COUNT(DISTINCT user_id) as total_users,
			COUNT(DISTINCT customer_id) as total_customers,
			COUNT(DISTINCT subscription_id) as total_subscriptions
		FROM stripe_customers
		WHERE subscription_id IS NOT NULL
	`

	err = s.client.DB.Rpc("rpc", map[string]interface{}{
		"name": "run_query",
		"sql":  query,
	}).Execute(&totalResult)

	if err != nil || len(totalResult) == 0 {
		return tierMetrics, nil
	}

	totalUsers, _ := totalResult[0]["total_users"].(float64)
	totalCustomers, _ := totalResult[0]["total_customers"].(float64)
	totalSubscriptions, _ := totalResult[0]["total_subscriptions"].(float64)

	// Add totals to metrics
	metrics := map[string]interface{}{
		"tiers": tierMetrics,
		"totals": map[string]interface{}{
			"users":         int(totalUsers),
			"customers":     int(totalCustomers),
			"subscriptions": int(totalSubscriptions),
		},
	}

	return metrics, nil
}
