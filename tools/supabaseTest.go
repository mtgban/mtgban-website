package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	supabase "github.com/the-muppet/supabase-go"
)

type AuthResponse struct {
	AccessToken  string   `json:"access_token"`
	TokenType    string   `json:"token_type"`
	ExpiresIn    int64    `json:"expires_in"`
	ExpiresAt    int64    `json:"expires_at,omitempty"`
	RefreshToken string   `json:"refresh_token"`
	User         UserInfo `json:"user"`
}

type UserInfo struct {
	ID               string       `json:"id"`
	Aud              string       `json:"aud"`
	Role             string       `json:"role"`
	Email            string       `json:"email"`
	EmailConfirmedAt string       `json:"email_confirmed_at"`
	Phone            string       `json:"phone"`
	ConfirmedAt      string       `json:"confirmed_at"`
	LastSignInAt     string       `json:"last_sign_in_at"`
	AppMetadata      AppMetadata  `json:"app_metadata"`
	UserMetadata     UserMetadata `json:"user_metadata"`
	Identities       []Identity   `json:"identities,omitempty"`
	CreatedAt        string       `json:"created_at"`
	UpdatedAt        string       `json:"updated_at"`
	IsAnonymous      bool         `json:"is_anonymous,omitempty"`
}

type AppMetadata struct {
	Provider  string   `json:"provider,omitempty"`
	Providers []string `json:"providers,omitempty"`
	Sig       string   `json:"sig,omitempty"`
}

type UserMetadata struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	PhoneVerified bool   `json:"phone_verified"`
	Sub           string `json:"sub"`
}

type Identity struct {
	ID           string       `json:"id"`
	UserID       string       `json:"user_id"`
	IdentityData IdentityData `json:"identity_data"`
	Provider     string       `json:"provider"`
	CreatedAt    string       `json:"created_at"`
	UpdatedAt    string       `json:"updated_at"`
}

type IdentityData struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	PhoneVerified bool   `json:"phone_verified"`
	Sub           string `json:"sub"`
}

func main() {
	// Your Supabase credentials
	url := "https://hoghbridoggvmwmvszuy.supabase.co"
	key := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImhvZ2hicmlkb2dndm13bXZzenV5Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDYyMjE3MzksImV4cCI6MjA2MTc5NzczOX0.s63ANfmr6FkZ_6N-RcreVM5xuWpksJOT3WYOzjWNzp8"
	email := "elmo@bdwinc.org"
	password := "Password12!"

	// Initialize Supabase client
	client := supabase.CreateClient(url, key)

	// Create context
	ctx := context.Background()

	// Sign in with email and password
	fmt.Println("Authenticating with Supabase...")
	resp, err := client.Auth.SignIn(ctx, supabase.UserCredentials{
		Email:    email,
		Password: password,
	})
	if err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}

	// Convert full response to JSON string first
	jsonBytes, err := json.Marshal(resp)
	if err != nil {
		log.Fatalf("Failed to marshal response: %v", err)
	}

	// Print the raw JSON for debugging
	fmt.Println("Raw JSON response:")
	fmt.Println(string(jsonBytes))

	// Parse the JSON into a map to access fields dynamically
	var respMap map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &respMap); err != nil {
		log.Fatalf("Failed to unmarshal response: %v", err)
	}

	// Try to extract the signature from user.app_metadata.sig
	var signature string

	if user, ok := respMap["user"].(map[string]interface{}); ok {
		if appMetadata, ok := user["app_metadata"].(map[string]interface{}); ok {
			if sig, ok := appMetadata["sig"].(string); ok {
				signature = sig
				fmt.Println("\nSignature found:")
				fmt.Println(signature)
			} else {
				fmt.Println("\nNo 'sig' field in app_metadata")
				fmt.Println("app_metadata contents:", appMetadata)
			}
		} else {
			fmt.Println("\nNo 'app_metadata' field in user or it's not a map")
			fmt.Println("user fields:", user)
		}
	} else {
		fmt.Println("\nNo 'user' field in response or it's not a map")
	}

	if signature != "" {
		// Clean the signature by removing line breaks
		cleanSig := strings.ReplaceAll(strings.ReplaceAll(signature, "\n", ""), "\r", "")

		// Decode from base64
		decodedBytes, err := base64.StdEncoding.DecodeString(cleanSig)
		if err != nil {
			log.Fatalf("Failed to decode signature: %v", err)
		}

		fmt.Println("\nDecoded signature:")
		fmt.Println(string(decodedBytes))

		// Try to parse it as JSON if possible
		var permData interface{}
		if err := json.Unmarshal(decodedBytes, &permData); err == nil {
			fmt.Println("\nSignature contents (JSON):")
			prettyJSON, _ := json.MarshalIndent(permData, "", "  ")
			fmt.Println(string(prettyJSON))
		}
	}
}
