package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// PreferencesNamespace is the key under which preferences are stored in UserMetadata
const PreferencesNamespace = "preferences"

func PreferencesAPI(w http.ResponseWriter, r *http.Request) {
	// Get permissions from context
	ctx := r.Context()
	userID, _ := ctx.Value("user_id").(string)

	// Only allow POST method
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse JSON request body
	var prefs struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&prefs); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Update preferences in Supabase
	err := updateUserPreferences(ctx, userID, map[string]string{
		prefs.Key: prefs.Value,
	})
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
	})
}

// getUserPreferences retrieves user preferences from UserMetadata
func getUserPreferences(ctx context.Context, userToken string) (map[string]string, error) {
	if userToken == "" {
		return nil, fmt.Errorf("no user token provided")
	}

	client := getSupabaseClient()
	if client == nil {
		return nil, fmt.Errorf("Supabase client not initialized")
	}

	user, err := client.Auth.User(ctx, userToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user data: %v", err)
	}

	preferences := make(map[string]string)
	if user.UserMetadata != nil {
		if prefsData, ok := user.UserMetadata[PreferencesNamespace]; ok {
			if prefsMap, ok := prefsData.(map[string]any); ok {
				for k, v := range prefsMap {
					if strVal, ok := v.(string); ok {
						preferences[k] = strVal
					}
				}
			}
		}
	}

	return preferences, nil
}

// updateUserPreferences saves or updates user preferences in UserMetadata
func updateUserPreferences(ctx context.Context, userToken string, newPreferences map[string]string) error {
	if userToken == "" {
		return fmt.Errorf("no user token provided")
	}

	client := getSupabaseClient()
	if client == nil {
		return fmt.Errorf("Supabase client not initialized")
	}

	user, err := client.Auth.User(ctx, userToken)
	if err != nil {
		return fmt.Errorf("failed to get user data: %v", err)
	}

	existingPrefs := make(map[string]any)
	if user.UserMetadata != nil {
		if prefs, ok := user.UserMetadata[PreferencesNamespace]; ok {
			if prefsMap, ok := prefs.(map[string]any); ok {
				existingPrefs = prefsMap
			}
		}
	}

	for k, v := range newPreferences {
		existingPrefs[k] = v
	}

	updateData := map[string]any{
		"user_metadata": map[string]any{
			PreferencesNamespace: existingPrefs,
		},
	}

	_, err = client.Auth.UpdateUser(ctx, userToken, updateData)
	if err != nil {
		return fmt.Errorf("failed to update user preferences: %v", err)
	}

	return nil
}

// updateSinglePreference updates just one preference key/value
func updateSinglePreference(ctx context.Context, userToken string, key, value string) error {
	return updateUserPreferences(ctx, userToken, map[string]string{
		key: value,
	})
}

// getPreferenceValue retrieves a single preference value
func getPreferenceValue(ctx context.Context, userToken string, key string) (string, bool, error) {
	prefs, err := getUserPreferences(ctx, userToken)
	if err != nil {
		return "", false, err
	}

	val, exists := prefs[key]
	return val, exists, nil
}

// deletePreference removes a preference
func deletePreference(ctx context.Context, userToken string, key string) error {
	prefs, err := getUserPreferences(ctx, userToken)
	if err != nil {
		return err
	}

	if _, exists := prefs[key]; !exists {
		return nil
	}

	delete(prefs, key)

	client := getSupabaseClient()
	if client == nil {
		return fmt.Errorf("Supabase client not initialized")
	}

	updateData := map[string]any{
		"user_metadata": map[string]any{
			PreferencesNamespace: prefs,
		},
	}

	_, err = client.Auth.UpdateUser(ctx, userToken, updateData)
	if err != nil {
		return fmt.Errorf("failed to delete preference: %v", err)
	}

	return nil
}
