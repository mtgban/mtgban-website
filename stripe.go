package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/stripe/stripe-go/v82"
	billingsession "github.com/stripe/stripe-go/v82/billingportal/session"
	checkoutsession "github.com/stripe/stripe-go/v82/checkout/session"
	"github.com/stripe/stripe-go/v82/customer"
	"github.com/stripe/stripe-go/v82/price"
	"github.com/stripe/stripe-go/v82/webhook"
)

func init() {
	// Load environment variables from .env file
	godotenv.Load()

	// Set Stripe API key
	stripe.Key = os.Getenv("STRIPE_SECRET_KEY")
}

// This is the webhook handler that processes Stripe events
func handleStripeWebhooks(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Get the webhook secret from environment variables
	webhookSecret := os.Getenv("STRIPE_WEBHOOK_SECRET")
	if webhookSecret == "" {
		http.Error(w, "Webhook secret not configured", http.StatusInternalServerError)
		return
	}

	// Get the signature header
	stripeSignature := r.Header.Get("Stripe-Signature")
	if stripeSignature == "" {
		http.Error(w, "No Stripe signature found", http.StatusBadRequest)
		return
	}

	// Verify the event
	event, err := webhook.ConstructEvent(body, stripeSignature, webhookSecret)
	if err != nil {
		http.Error(w, fmt.Sprintf("Webhook error: %v", err), http.StatusBadRequest)
		return
	}

	log.Printf("Received Stripe webhook event: %s", event.Type)

	// Process the event based on its type
	switch event.Type {
	case "product.created", "product.updated":
		var p stripe.Product
		err = json.Unmarshal(event.Data.Raw, &p)
		if err != nil {
			http.Error(w, "Error parsing product data", http.StatusBadRequest)
			return
		}
		err = upsertProductRecord(&p)

	case "product.deleted":
		var p stripe.Product
		err = json.Unmarshal(event.Data.Raw, &p)
		if err != nil {
			http.Error(w, "Error parsing product data", http.StatusBadRequest)
			return
		}
		err = deleteProductRecord(&p)

	case "price.created", "price.updated":
		var p stripe.Price
		err = json.Unmarshal(event.Data.Raw, &p)
		if err != nil {
			http.Error(w, "Error parsing price data", http.StatusBadRequest)
			return
		}
		err = upsertPriceRecord(&p)

	case "price.deleted":
		var p stripe.Price
		err = json.Unmarshal(event.Data.Raw, &p)
		if err != nil {
			http.Error(w, "Error parsing price data", http.StatusBadRequest)
			return
		}
		err = deletePriceRecord(&p)

	case "customer.subscription.created", "customer.subscription.updated":
		var s stripe.Subscription
		err = json.Unmarshal(event.Data.Raw, &s)
		if err != nil {
			http.Error(w, "Error parsing subscription data", http.StatusBadRequest)
			return
		}
		err = manageSubscriptionStatusChange(s.ID, s.Customer.ID, event.Type == "customer.subscription.created")

	case "customer.subscription.deleted":
		var s stripe.Subscription
		err = json.Unmarshal(event.Data.Raw, &s)
		if err != nil {
			http.Error(w, "Error parsing subscription data", http.StatusBadRequest)
			return
		}
		err = manageSubscriptionStatusChange(s.ID, s.Customer.ID, false)

	case "checkout.session.completed":
		var s stripe.CheckoutSession
		err = json.Unmarshal(event.Data.Raw, &s)
		if err != nil {
			http.Error(w, "Error parsing checkout session data", http.StatusBadRequest)
			return
		}
		if s.Mode == stripe.CheckoutSessionModeSubscription && s.Subscription != nil {
			err = manageSubscriptionStatusChange(s.Subscription.ID, s.Customer.ID, true)
		}

	default:
		log.Printf("Unhandled event type: %s", event.Type)
	}

	if err != nil {
		log.Printf("Error processing webhook: %v", err)
		http.Error(w, fmt.Sprintf("Error processing webhook: %v", err), http.StatusInternalServerError)
		return
	}

	// Return a successful response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"received": true})
}

// This creates a Stripe billing portal session
func handleStripePortal(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the request body
	var req struct {
		ReturnURL string `json:"returnUrl"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Default return URL if not specified
	returnURL := req.ReturnURL
	if returnURL == "" {
		returnURL = "/account"
	}

	// Get the site URL from environment
	siteURL := os.Getenv("SITE_URL")
	if siteURL == "" {
		siteURL = "http://localhost:8080" // fallback
	}

	// Get the authenticated user from Supabase session
	supabaseUser, err := getUserFromSupabase(r)
	if err != nil || supabaseUser == nil {
		log.Printf("User authentication error: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Not authenticated",
			"url":   getErrorRedirectURL("/signin", "Authentication required", "Please sign in to access this feature."),
		})
		return
	}

	// Get Stripe customer ID for the user
	customerID, err := getOrCreateStripeCustomer(supabaseUser.ID, supabaseUser.Email)
	if err != nil {
		log.Printf("Error getting/creating Stripe customer: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": fmt.Sprintf("Unable to access customer record: %v", err),
			"url":   getErrorRedirectURL("/account", "Payment Portal Error", "Could not create payment portal. Please try again later."),
		})
		return
	}

	// Create a Stripe billing portal session
	params := &stripe.BillingPortalSessionParams{
		Customer:  stripe.String(customerID),
		ReturnURL: stripe.String(siteURL + returnURL),
	}

	bps, err := billingsession.New(params)
	if err != nil {
		log.Printf("Error creating billing portal session: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": fmt.Sprintf("Could not create billing portal: %v", err),
			"url":   getErrorRedirectURL("/account", "Payment Portal Error", "Could not create payment portal. Please try again later."),
		})
		return
	}

	// Return the URL to redirect the user to
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"url": bps.URL,
	})
}

// This creates a Stripe checkout session
func handleCheckoutSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the request body
	var req struct {
		PriceID      string `json:"priceId"`
		RedirectPath string `json:"redirectPath"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.PriceID == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Price ID is required",
		})
		return
	}

	// Default redirect path if not specified
	redirectPath := req.RedirectPath
	if redirectPath == "" {
		redirectPath = "/account"
	}

	// Get the site URL from environment
	siteURL := os.Getenv("SITE_URL")
	if siteURL == "" {
		siteURL = "http://localhost:8080" // fallback
	}

	// Get the authenticated user from Supabase session
	supabaseUser, err := getUserFromSupabase(r)
	if err != nil || supabaseUser == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Not authenticated",
			"url":   getURL("/signin/signup"),
		})
		return
	}

	// Get price details from Stripe
	p, err := price.Get(req.PriceID, nil)
	if err != nil {
		log.Printf("Error getting price: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error":         "Price not found",
			"errorRedirect": getErrorRedirectURL(redirectPath, "Invalid Price", "The selected price is not available."),
		})
		return
	}

	// Get Stripe customer ID for the user
	customerID, err := getOrCreateStripeCustomer(supabaseUser.ID, supabaseUser.Email)
	if err != nil {
		log.Printf("Error getting/creating Stripe customer: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error":         "Unable to access customer record",
			"errorRedirect": getErrorRedirectURL(redirectPath, "Customer Error", "Unable to access customer record."),
		})
		return
	}

	// Create checkout session parameters
	params := &stripe.CheckoutSessionParams{
		AllowPromotionCodes:      stripe.Bool(true),
		BillingAddressCollection: stripe.String("required"),
		Customer:                 stripe.String(customerID),
		CustomerUpdate: &stripe.CheckoutSessionCustomerUpdateParams{
			Address: stripe.String("auto"),
		},
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(req.PriceID),
				Quantity: stripe.Int64(1),
			},
		},
		CancelURL:  stripe.String(siteURL + redirectPath),
		SuccessURL: stripe.String(siteURL + redirectPath),
	}

	// Add subscription-specific parameters if needed
	if p.Type == stripe.PriceTypeRecurring {
		params.Mode = stripe.String(string(stripe.CheckoutSessionModeSubscription))

		// Calculate trial end if applicable
		if p.Recurring != nil && p.Recurring.TrialPeriodDays > 0 {
			trialEnd := time.Now().Add(time.Duration(p.Recurring.TrialPeriodDays+1) * 24 * time.Hour).Unix()
			params.SubscriptionData = &stripe.CheckoutSessionSubscriptionDataParams{
				TrialEnd: stripe.Int64(trialEnd),
			}
		}
	} else if p.Type == stripe.PriceTypeOneTime {
		params.Mode = stripe.String(string(stripe.CheckoutSessionModePayment))
	}

	// Create a checkout session
	s, err := checkoutsession.New(params)
	if err != nil {
		log.Printf("Error creating checkout session: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error":         "Unable to create checkout session",
			"errorRedirect": getErrorRedirectURL(redirectPath, "Checkout Error", "Unable to create checkout session."),
		})
		return
	}

	// Return the session ID
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"sessionId": s.ID,
	})
}

// Helper to get or create Stripe customer for a user
func getOrCreateStripeCustomer(userID, email string) (string, error) {
	// Query Supabase for existing customer record
	customerID, err := getCustomerIDFromSupabase(userID)
	if err == nil && customerID != "" {
		// Try to retrieve the customer from Stripe
		_, err := customer.Get(customerID, nil)
		if err == nil {
			// Customer exists and is valid
			return customerID, nil
		}
	}

	// Try to find customer by email in Stripe
	params := &stripe.CustomerListParams{
		Email: stripe.String(email),
	}
	i := customer.List(params)
	if i.Next() {
		customerID = i.Customer().ID

		// Update the customer record in Supabase
		if err := updateCustomerInSupabase(userID, customerID); err != nil {
			log.Printf("Error updating customer in Supabase: %v", err)
			// Continue anyway since we found the customer
		}

		return customerID, nil
	}

	// Create a new customer in Stripe
	customerParams := &stripe.CustomerParams{
		Email: stripe.String(email),
		Metadata: map[string]string{
			"supabaseUUID": userID,
		},
	}

	newCustomer, err := customer.New(customerParams)
	if err != nil {
		return "", err
	}

	// Store the new customer ID in Supabase
	if err := updateCustomerInSupabase(userID, newCustomer.ID); err != nil {
		log.Printf("Error storing new customer in Supabase: %v", err)
		// Continue anyway since we created the customer
	}

	return newCustomer.ID, nil
}

// getUserFromSupabase extracts the user from the Supabase session in the request
func getUserFromSupabase(r *http.Request) (*struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}, error) {
	// Get the authentication token from the Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("no authorization header")
	}

	// Extract the JWT token (remove "Bearer " prefix)
	token := authHeader
	if len(authHeader) > 7 && strings.ToLower(authHeader[0:7]) == "bearer " {
		token = authHeader[7:]
	}

	// Initialize Supabase client
	client := GetServices().GetSupabaseClient()

	// Use the token to get user data
	var userData struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}

	// Get user from Supabase auth
	_, err := client.Auth.User(context.Background(), token)
	if err != nil {
		return nil, err
	}

	return &userData, nil
}

// getURL creates a full URL for the given path
func getURL(path string) string {
	siteURL := os.Getenv("SITE_URL")
	if siteURL == "" {
		siteURL = "http://localhost:8080"
	}
	return siteURL + path
}

// getErrorRedirectURL creates a URL with error parameters
func getErrorRedirectURL(path, title, message string) string {
	u, err := url.Parse(getURL(path))
	if err != nil {
		return getURL(path)
	}

	q := u.Query()
	q.Set("error", "true")
	q.Set("error_title", title)
	q.Set("error_message", message)
	u.RawQuery = q.Encode()

	return u.String()
}
