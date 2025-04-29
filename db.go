package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/stripe/stripe-go/v82"
	stripeclient "github.com/stripe/stripe-go/v82/client"
	supabase "github.com/the-muppet/supabase-go"
)

type DBConfig struct {
	URL     string `json:"url"`
	AnonKey string `json:"anon_key"`
	RoleKey string `json:"role_key"`
	Secret  string `json:"jwt_secret"`
}

// Services contains all external service clients
type Services struct {
	supabase *supabase.Client
	config   *DBConfig
}

var (
	instance *Services
	once     sync.Once
)

// GetServices returns the singleton instance of Services
func GetServices() *Services {
	once.Do(func() {
		instance = &Services{}
	})
	return instance
}

// Initialize sets up the service connections
func (s *Services) Initialize(config *DBConfig) {
	s.config = config
	s.supabase = supabase.CreateClient(config.URL, config.RoleKey)
	s.supabase.DB.AddHeader("x-postgres-role", string(MTGBAN_ROLE))

}

// GetSupabaseClient returns the supabase client
func (s *Services) GetSupabaseClient() *supabase.Client {
	return s.supabase
}

// WithRole returns a new supabase client with the specified role
func (s *Services) WithRole(roleName string) (*supabase.Client, error) {
	client := supabase.CreateClient(s.config.URL, s.config.RoleKey)
	client.DB.AddHeader("x-postgres-role", roleName)
	return client, nil
}

// Update getCustomerIDFromSupabase to use the singleton
func getCustomerIDFromSupabase(userID string) (string, error) {
	client := GetServices().GetSupabaseClient()

	type Customer struct {
		ID               string `json:"id"`
		StripeCustomerID string `json:"stripe_customer_id"`
	}

	var result []Customer
	err := client.DB.From("customers").Select("*").Eq("id", userID).Execute(&result)
	if err != nil {
		return "", fmt.Errorf("error querying customer: %w", err)
	}

	if len(result) == 0 {
		return "", nil
	}

	return result[0].StripeCustomerID, nil
}

// Update customer in Supabase
func updateCustomerInSupabase(userID, customerID string) error {
	client := GetServices().GetSupabaseClient()

	customer := map[string]any{
		"id":                 userID,
		"stripe_customer_id": customerID,
	}

	var result any
	err := client.DB.From("customers").Upsert(customer).Execute(&result)
	if err != nil {
		return fmt.Errorf("error upserting customer: %w", err)
	}

	return nil
}

// Upsert product record in Supabase
func upsertProductRecord(product *stripe.Product) error {
	client := GetServices().GetSupabaseClient()

	// Convert Stripe product to Supabase format
	productData := map[string]any{
		"id":          product.ID,
		"active":      product.Active,
		"name":        product.Name,
		"description": product.Description,
		"metadata":    product.Metadata,
	}

	// Add image if available
	if len(product.Images) > 0 {
		productData["image"] = product.Images[0]
	}

	var result any
	err := client.DB.From("products").Upsert(productData).Execute(&result)
	if err != nil {
		return fmt.Errorf("product insert/update failed: %w", err)
	}

	fmt.Printf("Product inserted/updated: %s\n", product.ID)
	return nil
}

// Delete product record from Supabase
func deleteProductRecord(product *stripe.Product) error {
	client := GetServices().GetSupabaseClient()

	var result any
	err := client.DB.From("products").Delete().Eq("id", product.ID).Execute(&result)
	if err != nil {
		return fmt.Errorf("product deletion failed: %w", err)
	}

	fmt.Printf("Product deleted: %s\n", product.ID)
	return nil
}

// Upsert price record in Supabase
func upsertPriceRecord(price *stripe.Price, retryCount ...int) error {
	client := GetServices().GetSupabaseClient()

	// Set trial period days default value
	const TRIAL_PERIOD_DAYS = 0

	// Convert Stripe price to Supabase format
	priceData := map[string]any{
		"id":          price.ID,
		"product_id":  price.Product.ID,
		"active":      price.Active,
		"currency":    price.Currency,
		"type":        string(price.Type),
		"unit_amount": price.UnitAmount,
		"description": nil,
		"metadata":    nil,
	}

	// Add recurring details if available
	if price.Recurring != nil {
		priceData["interval"] = string(price.Recurring.Interval)
		priceData["interval_count"] = price.Recurring.IntervalCount
		priceData["trial_period_days"] = price.Recurring.TrialPeriodDays
		if price.Recurring.TrialPeriodDays == 0 {
			priceData["trial_period_days"] = TRIAL_PERIOD_DAYS
		}
	}

	var result any
	err := client.DB.From("prices").Upsert(priceData).Execute(&result)

	// Handle foreign key constraint errors with retry
	if err != nil && len(retryCount) == 0 {
		// Wait and retry once
		time.Sleep(2 * time.Second)
		return upsertPriceRecord(price, 1)
	} else if err != nil {
		return fmt.Errorf("price insert/update failed: %w", err)
	}

	fmt.Printf("Price inserted/updated: %s\n", price.ID)
	return nil
}

// Delete price record from Supabase
func deletePriceRecord(price *stripe.Price) error {
	client := GetServices().GetSupabaseClient()

	var result any
	err := client.DB.From("prices").Delete().Eq("id", price.ID).Execute(&result)
	if err != nil {
		return fmt.Errorf("price deletion failed: %w", err)
	}

	fmt.Printf("Price deleted: %s\n", price.ID)
	return nil
}

// Manage subscription status change
func manageSubscriptionStatusChange(subscriptionID string, customerID string, createAction bool) error {
	client := GetServices().GetSupabaseClient()
	// Initialize Stripe client
	sc := stripeclient.New(stripe.Key, nil)

	// Get the subscription from Stripe
	sub, err := sc.Subscriptions.Get(subscriptionID, &stripe.SubscriptionParams{
		Params: stripe.Params{
			Expand: []*string{
				stripe.String("default_payment_method"),
			},
		},
	})

	if err != nil {
		return fmt.Errorf("error fetching subscription: %w", err)
	}

	// Get user's UUID from customers table
	type Customer struct {
		ID string `json:"id"`
	}

	var customers []Customer
	err = client.DB.From("customers").Select("id").Eq("stripe_customer_id", customerID).Execute(&customers)
	if err != nil {
		return fmt.Errorf("customer lookup failed: %w", err)
	}

	if len(customers) == 0 {
		return fmt.Errorf("no customer found for Stripe ID: %s", customerID)
	}

	uuid := customers[0].ID

	// Helper function to convert Unix timestamp to ISO time
	toISOTime := func(t int64) string {
		if t == 0 {
			return ""
		}
		return time.Unix(t, 0).UTC().Format(time.RFC3339)
	}

	// Prepare subscription data
	subData := map[string]any{
		"id":                   sub.ID,
		"user_id":              uuid,
		"status":               string(sub.Status),
		"price_id":             sub.Items.Data[0].Price.ID,
		"quantity":             sub.Items.Data[0].Quantity,
		"cancel_at_period_end": sub.CancelAtPeriodEnd,
		"current_period_start": toISOTime(sub.BillingCycleAnchor),
		"created":              toISOTime(sub.Created),
		"metadata":             sub.Metadata,
	}

	// Add optional fields if they exist
	if sub.CancelAt > 0 {
		subData["cancel_at"] = toISOTime(sub.CancelAt)
	}

	if sub.CanceledAt > 0 {
		subData["canceled_at"] = toISOTime(sub.CanceledAt)
	}

	if sub.EndedAt > 0 {
		subData["ended_at"] = toISOTime(sub.EndedAt)
	}

	if sub.TrialStart > 0 {
		subData["trial_start"] = toISOTime(sub.TrialStart)
	}

	if sub.TrialEnd > 0 {
		subData["trial_end"] = toISOTime(sub.TrialEnd)
	}

	// Upsert the subscription
	var result any
	err = client.DB.From("subscriptions").Upsert(subData).Execute(&result)
	if err != nil {
		return fmt.Errorf("subscription insert/update failed: %w", err)
	}

	fmt.Printf("Inserted/updated subscription [%s] for user [%s]\n", sub.ID, uuid)

	// For a new subscription, copy the billing details to the customer object
	if createAction && sub.DefaultPaymentMethod != nil {
		err = copyBillingDetailsToCustomer(client, uuid, sub.DefaultPaymentMethod)
		if err != nil {
			return fmt.Errorf("error copying billing details: %w", err)
		}
	}

	return nil
}

// Copy billing details from payment method to customer
func copyBillingDetailsToCustomer(client *supabase.Client, uuid string, pm *stripe.PaymentMethod) error {
	if pm.BillingDetails.Name == "" || pm.BillingDetails.Phone == "" || pm.BillingDetails.Address == nil {
		return nil // No billing details to copy
	}

	// Create update data
	userData := map[string]any{
		"billing_address": pm.BillingDetails.Address,
	}

	// Add payment method details based on the type
	if pm.Type == stripe.PaymentMethodTypeCard && pm.Card != nil {
		userData["payment_method"] = map[string]any{
			"brand":     pm.Card.Brand,
			"last4":     pm.Card.Last4,
			"exp_month": pm.Card.ExpMonth,
			"exp_year":  pm.Card.ExpYear,
		}
	}

	// Update the user
	var result any
	err := client.DB.From("users").Update(userData).Eq("id", uuid).Execute(&result)
	if err != nil {
		return fmt.Errorf("user update failed: %w", err)
	}

	return nil
}
