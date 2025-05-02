package main

import (
	"fmt"
	"os"

	stripe "github.com/stripe/stripe-go/v82"
)

type StripeConfig struct {
	SecretKey      string            `json:"secret_key"`
	PublishableKey string            `json:"publishable_key"`
	WebhookSecret  string            `json:"webhook_secret"`
	ProductMapping map[string]string `json:"product_mapping"`
	PriceMapping   map[string]string `json:"price_mapping"`
	SuccessURL     string            `json:"success_url"`
	CancelURL      string            `json:"cancel_url"`
}

var StripeClient *stripe.Client

func InitStripe() error {
	stripeKey := os.Getenv("STRIPE_SECRET_KEY")
	if stripeKey == "" {
		stripeKey = Config.Stripe.SecretKey
	}
	if stripeKey == "" {
		return fmt.Errorf("missing Stripe secret key")
	}

	StripeClient := stripe.NewClient(stripeKey)
	if StripeClient == nil {
		return fmt.Errorf("failed to create Stripe client")
	}

	LogPages["Admin"].Println("Stripe client initialized successfully")
	return nil
}

// SubscriptionRequest defines the request for creating a subscription
type SubscriptionRequest struct {
	TierName string `json:"tier_name"`
	UserID   string `json:"user_id"`
	Email    string `json:"email"`
}

// SubscriptionResponse defines the response for subscription operations
type SubscriptionResponse struct {
	Success     bool   `json:"success"`
	Message     string `json:"message"`
	RedirectURL string `json:"redirect_url,omitempty"`
}
