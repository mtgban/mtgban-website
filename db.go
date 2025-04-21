package main

import (
	supabase "github.com/nedpals/supabase-go"
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

// RoleClient creates a new supabase client that uses the specified role
func roleClient(url, key, roleName string) (*supabase.Client, error) {
	client := supabase.CreateClient(url, key)
	client.DB.AddHeader("x-postgres-role", roleName)
	return client, nil
}
