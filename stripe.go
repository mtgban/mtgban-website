package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/stripe/stripe-go/v74"
	"github.com/stripe/stripe-go/v74/checkout/session"
	"github.com/stripe/stripe-go/v74/customer"
	"github.com/stripe/stripe-go/v74/subscription"
	"github.com/stripe/stripe-go/v74/webhook"
)

type StripeConfig struct {
	SecretKey      string
	PublishableKey string
	WebhookSecret  string
	SuccessURL     string
	CancelURL      string
	Plans          map[string]string
}

// StripeConfig defines the configuration for Stripe
var stripeConfig StripeConfig

// PlanInfo defines the information for a subscription plan
type PlanInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	PriceID     string   `json:"price_id"`
	Features    []string `json:"features"`
	Price       int64    `json:"price"`
}

// SubscriptionRequest defines the request for creating a checkout session
type SubscriptionRequest struct {
	PlanID string `json:"plan_id"`
}

// SubscriptionResponse is the response with checkout information
type SubscriptionResponse struct {
	SessionID string `json:"session_id"`
	URL       string `json:"url"`
}

// SubscriptionPlans is a map of all available subscription plans
var SubscriptionPlans = map[string]PlanInfo{}

// LoadSubscriptionPlans loads the subscription plans from supabase
func LoadSubscriptionPlans() error {
	client := getSupabaseClient()
	if client == nil {
		return fmt.Errorf("supabase client not initialized")
	}

	var plans []map[string]interface{}

	err := client.DB.From("stripe.product_plans").Select("*").Execute(&plans)

	if err != nil {
		log.Printf("Error loading subscription plans: %v", err)
		return err
	}

	for _, plan := range plans {
		id, _ := plan["product_id"].(string)
		name, _ := plan["product_name"].(string)
		description, _ := plan["product_description"].(string)
		priceID, _ := plan["price_id"].(string)
		price, _ := plan["price"].(float64)

		features := strings.Split(description, ",")

		SubscriptionPlans[id] = PlanInfo{
			Name:        name,
			Description: description,
			PriceID:     priceID,
			Features:    features,
			Price:       int64(price),
		}
	}

	return nil
}

// InitStripe initializes the Stripe configuration
func InitStripe() {
	stripeConfig = StripeConfig{
		SecretKey:      os.Getenv("STRIPE_SECRET_KEY"),
		PublishableKey: os.Getenv("STRIPE_PUBLISHABLE_KEY"),
		WebhookSecret:  os.Getenv("STRIPE_WEBHOOK_SECRET"),
		SuccessURL:     getBaseURL(nil) + "/subscription/success?session_id={CHECKOUT_SESSION_ID}",
		CancelURL:      getBaseURL(nil) + "/subscription/cancel",
	}

	if stripeConfig.SecretKey == "" {
		log.Println("Warning: STRIPE_SECRET_KEY not set. Stripe functionality will be disabled.")
		return
	}

	stripe.Key = stripeConfig.SecretKey

	if DevMode {
		log.Println("[DEBUG] Stripe initialized with API key:", maskKey(stripeConfig.SecretKey))
	}

	if err := LoadSubscriptionPlans(); err != nil {
		log.Printf("Error loading subscription plans: %v", err)
	}
}

// GetSubscriptionPlansHandler returns all available subscription plans
func GetSubscriptionPlansHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SubscriptionPlans)
}

// CreateCheckoutSessionHandler creates a Stripe checkout session
func CreateCheckoutSessionHandler(w http.ResponseWriter, r *http.Request) {
	// Get user from context
	userID := getUserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse request body
	var req SubscriptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Validate plan ID
	planInfo, ok := SubscriptionPlans[req.PlanID]
	if !ok {
		http.Error(w, "Invalid plan ID", http.StatusBadRequest)
		return
	}

	// Get or create Stripe customer
	customerID, err := getOrCreateCustomer(r.Context(), userID)
	if err != nil {
		if DevMode {
			log.Printf("[DEBUG] Failed to get/create customer: %v", err)
		}
		http.Error(w, "Failed to create customer", http.StatusInternalServerError)
		return
	}

	// Create checkout session params
	params := &stripe.CheckoutSessionParams{
		SuccessURL: stripe.String(stripeConfig.SuccessURL),
		CancelURL:  stripe.String(stripeConfig.CancelURL),
		Customer:   stripe.String(customerID),
		Mode:       stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(planInfo.PriceID),
				Quantity: stripe.Int64(1),
			},
		},
		SubscriptionData: &stripe.CheckoutSessionSubscriptionDataParams{
			Metadata: map[string]string{
				"user_id": userID,
				"plan_id": req.PlanID,
			},
		},
	}

	// Create the checkout session
	s, err := session.New(params)
	if err != nil {
		if DevMode {
			log.Printf("[DEBUG] Failed to create checkout session: %v", err)
		}
		http.Error(w, "Failed to create checkout session", http.StatusInternalServerError)
		return
	}

	// Return session ID and URL
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SubscriptionResponse{
		SessionID: s.ID,
		URL:       s.URL,
	})
}

// Helper function to get or create a Stripe customer for a user
func getOrCreateCustomer(ctx context.Context, userID string) (string, error) {
	// First check if we have stored the customer ID
	customerID, err := getStoredCustomerID(userID)
	if err == nil && customerID != "" {
		return customerID, nil
	}

	// Get user email from session
	email := getUserEmailFromContext(ctx)
	if email == "" {
		return "", fmt.Errorf("user email not found")
	}

	// Create a new customer in Stripe
	params := &stripe.CustomerParams{
		Email: stripe.String(email),
	}
	params.AddMetadata("user_id", userID)

	c, err := customer.New(params)
	if err != nil {
		return "", err
	}

	// Store the customer ID
	if err := storeCustomerID(userID, c.ID); err != nil {
		log.Printf("Warning: Failed to store customer ID: %v", err)
	}

	return c.ID, nil
}

// Helper to get user ID from context
func getUserIDFromContext(ctx context.Context) string {
	token, ok := ctx.Value("token").(string)
	if !ok || token == "" {
		return ""
	}

	claims, err := extractClaims(token)
	if err != nil {
		return ""
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		return ""
	}

	return userID
}

// Helper to get user email from context
func getUserEmailFromContext(ctx context.Context) string {
	email, ok := ctx.Value("user_email").(string)
	if !ok {
		return ""
	}
	return email
}

// StripeWebhookHandler processes webhooks from Stripe
func StripeWebhookHandler(w http.ResponseWriter, r *http.Request) {
	const MaxBodyBytes = int64(65536)
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	payload, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading webhook body: %v", err)
		http.Error(w, "Error reading request body", http.StatusServiceUnavailable)
		return
	}

	// Verify webhook signature
	event, err := webhook.ConstructEvent(payload, r.Header.Get("Stripe-Signature"), stripeConfig.WebhookSecret)
	if err != nil {
		log.Printf("Error verifying webhook signature: %v", err)
		http.Error(w, "Webhook signature verification failed", http.StatusBadRequest)
		return
	}

	// Handle the event
	if DevMode {
		log.Printf("[DEBUG] Processing webhook: %s", event.Type)
	}

	switch event.Type {
	case "checkout.session.completed":
		var session stripe.CheckoutSession
		err := json.Unmarshal(event.Data.Raw, &session)
		if err != nil {
			log.Printf("Error parsing webhook JSON: %v", err)
			http.Error(w, "Error parsing webhook", http.StatusBadRequest)
			return
		}
		handleCheckoutSessionCompleted(&session)

	case "customer.subscription.created", "customer.subscription.updated":
		var sub stripe.Subscription
		err := json.Unmarshal(event.Data.Raw, &sub)
		if err != nil {
			log.Printf("Error parsing webhook JSON: %v", err)
			http.Error(w, "Error parsing webhook", http.StatusBadRequest)
			return
		}
		handleSubscriptionUpdated(&sub)

	case "customer.subscription.deleted":
		var sub stripe.Subscription
		err := json.Unmarshal(event.Data.Raw, &sub)
		if err != nil {
			log.Printf("Error parsing webhook JSON: %v", err)
			http.Error(w, "Error parsing webhook", http.StatusBadRequest)
			return
		}
		handleSubscriptionDeleted(&sub)

	case "invoice.payment_succeeded":
		var invoice stripe.Invoice
		err := json.Unmarshal(event.Data.Raw, &invoice)
		if err != nil {
			log.Printf("Error parsing webhook JSON: %v", err)
			http.Error(w, "Error parsing webhook", http.StatusBadRequest)
			return
		}
		handlePaymentSucceeded(&invoice)

	case "invoice.payment_failed":
		var invoice stripe.Invoice
		err := json.Unmarshal(event.Data.Raw, &invoice)
		if err != nil {
			log.Printf("Error parsing webhook JSON: %v", err)
			http.Error(w, "Error parsing webhook", http.StatusBadRequest)
			return
		}
		handlePaymentFailed(&invoice)
	}

	w.WriteHeader(http.StatusOK)
}

// Handle checkout session completed event
func handleCheckoutSessionCompleted(session *stripe.CheckoutSession) {
	// The checkout completed successfully
	if DevMode {
		log.Printf("[DEBUG] Checkout completed for subscription: %s", session.Subscription.ID)
	}
}

// Handle subscription updated event
func handleSubscriptionUpdated(sub *stripe.Subscription) {
	// Extract user ID from metadata
	userID, ok := sub.Metadata["user_id"]
	if !ok || userID == "" {
		log.Printf("Warning: Subscription %s has no user_id in metadata", sub.ID)
		return
	}

	// Extract plan ID
	planID, ok := sub.Metadata["plan_id"]
	if !ok || planID == "" {
		// Try to map from the actual price ID
		for id, plan := range SubscriptionPlans {
			if sub.Items != nil && len(sub.Items.Data) > 0 {
				if sub.Items.Data[0].Price.ID == plan.PriceID {
					planID = id
					break
				}
			}
		}

		if planID == "" {
			log.Printf("Warning: Subscription %s has no plan_id in metadata", sub.ID)
			return
		}
	}

	// Update subscription status
	status := string(sub.Status)
	endDate := time.Unix(sub.CurrentPeriodEnd, 0)

	err := updateUserSubscription(userID, sub.ID, planID, status, endDate)
	if err != nil {
		log.Printf("Error updating subscription status: %v", err)
		return
	}
}

// Handle subscription deleted event
func handleSubscriptionDeleted(sub *stripe.Subscription) {
	// Extract user ID from metadata
	userID, ok := sub.Metadata["user_id"]
	if !ok || userID == "" {
		log.Printf("Warning: Subscription %s has no user_id in metadata", sub.ID)
		return
	}

	// Update subscription status
	err := updateUserSubscription(userID, sub.ID, "", "canceled", time.Now())
	if err != nil {
		log.Printf("Error updating subscription status: %v", err)
		return
	}
}

// Handle payment succeeded event
func handlePaymentSucceeded(invoice *stripe.Invoice) {
	if invoice.Subscription == nil {
		return
	}

	// Fetch the subscription to get metadata
	sub, err := subscription.Get(invoice.Subscription.ID, nil)
	if err != nil {
		log.Printf("Error fetching subscription: %v", err)
		return
	}

	// Extract user ID from metadata
	userID, ok := sub.Metadata["user_id"]
	if !ok || userID == "" {
		log.Printf("Warning: Subscription %s has no user_id in metadata", sub.ID)
		return
	}

	// Update payment status or send success notification
	log.Printf("Payment succeeded for user %s, subscription %s", userID, sub.ID)
}

// Handle payment failed event
func handlePaymentFailed(invoice *stripe.Invoice) {
	if invoice.Subscription == nil {
		return
	}

	// Fetch the subscription to get metadata
	sub, err := subscription.Get(invoice.Subscription.ID, nil)
	if err != nil {
		log.Printf("Error fetching subscription: %v", err)
		return
	}

	// Extract user ID from metadata
	userID, ok := sub.Metadata["user_id"]
	if !ok || userID == "" {
		log.Printf("Warning: Subscription %s has no user_id in metadata", sub.ID)
		return
	}

	// Update payment status or send failure notification
	log.Printf("Payment failed for user %s, subscription %s", userID, sub.ID)
}

// Update user subscription status
func updateUserSubscription(userID, subscriptionID, planID, status string, endDate time.Time) error {
	client := getSupabaseClient()
	if client == nil {
		return fmt.Errorf("supabase client not initialized")
	}

	data := map[string]interface{}{
		"user_id":            userID,
		"subscription_id":    subscriptionID,
		"plan_id":            planID,
		"status":             status,
		"current_period_end": endDate,
		"updated_at":         time.Now(),
	}

	// Check if subscription exists
	var result []map[string]interface{}
	err := client.DB.From("user_subscriptions").
		Select("id").
		Eq("user_id", userID).
		Execute(&result)

	if err != nil {
		return err
	}

	if len(result) > 0 {
		// Update existing subscription
		client.DB.
			From("user_subscriptions").
			Update(data).
			Eq("user_id", userID).
			ExecuteQuery()
	} else {
		data["created_at"] = time.Now()
		client.DB.
			From("user_subscriptions").
			Insert(data).
			ExecuteQuery()
	}

	return err
}

// Get user subscription
func getUserSubscription(userID string) (map[string]interface{}, error) {
	client := getSupabaseClient()
	if client == nil {
		return nil, fmt.Errorf("supabase client not initialized")
	}

	var result []map[string]interface{}
	err := client.DB.From("user_subscriptions").
		Select("*").
		Eq("user_id", userID).
		Execute(&result)

	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("subscription not found")
	}

	return result[0], nil
}

// Helper to create signature
func createSignature(userID, permissionsJSON string) (string, error) {
	// Format: userID:permissionsJSON:timestamp
	timestamp := strconv.FormatInt(time.Now().Add(DefaultSignatureDuration).Unix(), 10)
	signatureContent := fmt.Sprintf("%s:%s:%s", userID, permissionsJSON, timestamp)

	// Base64 encode
	return base64.StdEncoding.EncodeToString([]byte(signatureContent)), nil
}

// UserSubscriptionHandler displays user's subscription info
func UserSubscriptionHandler(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID := getUserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get user subscription
	subscription, err := getUserSubscription(userID)
	if err != nil {
		// User has no subscription
		if strings.Contains(err.Error(), "not found") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"has_subscription": false,
			})
			return
		}

		http.Error(w, "Failed to get subscription info", http.StatusInternalServerError)
		return
	}

	// Format response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"has_subscription": true,
		"subscription":     subscription,
		"plan_info":        SubscriptionPlans[subscription["plan_id"].(string)],
	})
}

// CancelSubscriptionHandler cancels a user's subscription
func CancelSubscriptionHandler(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID := getUserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get user subscription
	userSub, err := getUserSubscription(userID)
	if err != nil {
		http.Error(w, "No active subscription found", http.StatusBadRequest)
		return
	}

	subscriptionID, ok := userSub["subscription_id"].(string)
	if !ok || subscriptionID == "" {
		http.Error(w, "Invalid subscription ID", http.StatusBadRequest)
		return
	}

	// Cancel the subscription in Stripe
	_, err = subscription.Cancel(subscriptionID, &stripe.SubscriptionCancelParams{
		InvoiceNow: stripe.Bool(true),
		Prorate:    stripe.Bool(true),
	})
	if err != nil {
		log.Printf("Error cancelling subscription: %v", err)
		http.Error(w, "Failed to cancel subscription", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "canceled",
		"message": "Your subscription has been canceled",
	})
}

// SubscriptionSuccessHandler handles successful checkout
func SubscriptionSuccessHandler(w http.ResponseWriter, r *http.Request) {
	// Get session ID from query
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		http.Error(w, "Missing session ID", http.StatusBadRequest)
		return
	}

	// Verify the checkout session
	_, err := session.Get(sessionID, nil)
	if err != nil {
		log.Printf("Error retrieving session: %v", err)
		http.Error(w, "Invalid session", http.StatusBadRequest)
		return
	}

	// Render success page
	pageVars := genPageNav("Subscription Success", "")
	pageVars.Title = "Subscription Successful"
	render(w, "subscription_success.html", pageVars)
}

func SubscriptionCancelHandler(w http.ResponseWriter, r *http.Request) {
	pageVars := genPageNav("Subscription Cancelled", "")
	pageVars.Title = "Subscription Cancelled"
	pageVars.ErrorMessage = "Your subscription checkout was cancelled."
	render(w, "home.html", pageVars)
}

func maskKey(key string) string {
	if len(key) <= 8 {
		return "sk_****"
	}
	return "sk_****" + key[len(key)-4:]
}

func getStoredCustomerID(userID string) (string, error) {
	client := getSupabaseClient()
	if client == nil {
		return "", fmt.Errorf("supabase client not initialized")
	}

	var result []map[string]any
	err := client.DB.From("customers").
		Select("stripe_customer_id").
		Eq("id", userID).
		Execute(&result)
	if err != nil {
		return "", err
	}
	if len(result) == 0 {
		return "", nil // Not found
	}
	stripeID, _ := result[0]["stripe_customer_id"].(string)
	return stripeID, nil
}

func storeCustomerID(userID, customerID string) error {
	client := getSupabaseClient()
	if client == nil {
		return fmt.Errorf("supabase client not initialized")
	}

	// Upsert (insert or update) the customer record
	data := map[string]any{
		"id":                 userID,
		"stripe_customer_id": customerID,
	}
	err := client.DB.From("customers").
		Upsert(data).
		Execute(nil)
	if err != nil {
		return err
	}

	return nil
}

func SubscriptionPlansPage(w http.ResponseWriter, r *http.Request) {
	// Get user authentication status
	ctx := r.Context()
	token, _ := ctx.Value("token").(string)
	permissions, _ := ctx.Value("permissions").(map[string]map[string]any)
	
	pageVars := genPageNavWithPermissions("Subscription Plans", permissions, 0)
	pageVars.Title = "Subscription Plans"
	pageVars.IsAuthenticated = token != ""
	
	render(w, "subscription_plans.html", pageVars)
}

func SubscriptionSuccessPage(w http.ResponseWriter, r *http.Request) {
	pageVars := genPageNav("Success", "")
	pageVars.Title = "Subscription Successful"
	pageVars.InfoMessage = "Your subscription has been activated successfully!"
	render(w, "home.html", pageVars)
}
