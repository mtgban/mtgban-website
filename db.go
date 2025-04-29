package main

import (
	supabase "github.com/the-muppet/supabase-go"
)

type DBConfig struct {
	URL     string `json:"url"`
	AnonKey string `json:"anon_key"`
	RoleKey string `json:"role_key"`
	Secret  string `json:"jwt_secret"`
}

// supabaseClient creates a new supabase client
func supabaseClient(url, key string) (*supabase.Client, error) {
	client := supabase.CreateClient(url, key)
	return client, nil
}
