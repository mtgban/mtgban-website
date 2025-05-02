package main

import (
	"fmt"
	"os"

	"github.com/the-muppet/supabase-go"
)

type SupabaseConfig struct {
	URL        string `json:"url"`
	AnonKey    string `json:"anon_key"`
	ServiceKey string `json:"role_key"`
}

var SupabaseClient *supabase.Client

func InitSupabase() error {
	supabaseURL := os.Getenv("SUPABASE_URL")
	if supabaseURL == "" {
		supabaseURL = Config.Supabase.URL
	}

	supabaseKey := os.Getenv("SUPABASE_ANON_KEY")
	if supabaseKey == "" {
		supabaseKey = Config.Supabase.AnonKey
	}

	if supabaseURL == "" || supabaseKey == "" {
		return fmt.Errorf("missing Supabase configuration")
	}

	SupabaseClient := supabase.CreateClient(supabaseURL, supabaseKey)
	if SupabaseClient == nil {
		return fmt.Errorf("failed to create Supabase client")
	}

	LogPages["Admin"].Println("Supabase client initialized successfully")
	return nil
}

func CreateServiceClient() (*supabase.Client, error) {
	serviceRole := os.Getenv("SUPABASE_SERVICE_ROLE")
	if serviceRole == "" {
		serviceRole = Config.Supabase.ServiceKey
	}

	if serviceRole == "" {
		return nil, fmt.Errorf("missing Supabase service role key")
	}

	return supabase.CreateClient(Config.Supabase.URL, serviceRole), nil
}
