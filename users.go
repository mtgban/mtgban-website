package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/the-muppet/supabase-go"
)

// LoginRequest represents the login form data from the client
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// SignupRequest represents the signup form data from the client
type SignupRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FullName  string `json:"full_name,omitempty"`
}

// AuthResponse represents the authentication response from supabase
type AuthResponse struct {
	Message string `json:"message"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

func HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var loginReq LoginRequest
	err := json.NewDecoder(r.Body).Decode(&loginReq)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	// TODO: check if anon or admin client needed here, think anon works though
	client := getUserClient()
	if client == nil {
		http.Error(w, "Authentication service unavailable", http.StatusServiceUnavailable)
		return
	}

	authResult, err := client.Auth.SignIn(r.Context(), supabase.UserCredentials{
		Email:    loginReq.Email,
		Password: loginReq.Password,
	})
	
	if err != nil {
		if DevMode {
			log.Printf("[DEBUG] Login failed for %s: %v", loginReq.Email, err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(AuthResponse{
			Success: false,
			Error:   "Invalid credentials",
		})
		return
	}

	session, err := storeAuthenticatedDetails(authResult)
	if err != nil {
		if DevMode {
			log.Printf("[DEBUG] Failed to store session: %v", err)
		}
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	setAuthCookies(w, session.AccessToken, session.RefreshToken, session.ExpiresAt)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{
		Success: true,
		Message: "Login successful",
	})
}

func HandleSignup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var signupReq SignupRequest
	err := json.NewDecoder(r.Body).Decode(&signupReq)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	client := getUserClient()
	if client == nil {
		http.Error(w, "Authentication service unavailable", http.StatusServiceUnavailable)
		return
	}

	var userData map[string]any
	if signupReq.FullName != "" {
		userData = map[string]any{
			"full_name": signupReq.FullName,
		}
	}

	user, err := client.Auth.SignUp(r.Context(), supabase.UserCredentials{
		Email:    signupReq.Email,
		Password: signupReq.Password,
		Data:     userData,
	})
	
	if err != nil {
		if DevMode {
			log.Printf("[DEBUG] Signup failed for %s: %v", signupReq.Email, err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(AuthResponse{
			Success: false,
			Error:   fmt.Sprintf("Signup failed: %v", err),
		})
		return
	}

	if !user.ConfirmationSentAt.IsZero() {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(AuthResponse{
			Success: true,
			Message: "Signup successful. Please check your email to confirm your account.",
		})
		return
	}

	authResult, err := client.Auth.SignIn(r.Context(), supabase.UserCredentials{
		Email:    signupReq.Email,
		Password: signupReq.Password,
	})
	
	if err != nil {
		if DevMode {
			log.Printf("[DEBUG] Auto sign-in failed after signup: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(AuthResponse{
			Success: true,
			Message: "Signup successful. Please login to continue.",
		})
		return
	}

	session, err := storeAuthenticatedDetails(authResult)
	if err != nil {
		if DevMode {
			log.Printf("[DEBUG] Failed to store session: %v", err)
		}
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	setAuthCookies(w, session.AccessToken, session.RefreshToken, session.ExpiresAt)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{
		Success: true,
		Message: "Signup successful",
	})
}

// Helper function to store AuthenticatedDetails in the session cache
func storeAuthenticatedDetails(authResult *supabase.AuthenticatedDetails) (*UserSession, error) {
	session := &UserSession{
		Id:           authResult.User.ID,
		Email:        authResult.User.Email,
		Role:         authResult.User.Role,
		AccessToken:  authResult.AccessToken,
		RefreshToken: authResult.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(authResult.ExpiresIn) * time.Second),
		CreatedAt:    time.Now(),
		LastActive:   time.Now(),
		Permissions:  make(UserPerms),
	}

	if authResult.User.AppMetadata != nil && authResult.User.AppMetadata.Sig != "" {
		session.Signature = authResult.User.AppMetadata.Sig
		
		if session.Signature != "" {
			permissions, err := decodeAndParseSignature(session.Signature)
			if err == nil {
				session.Permissions = permissions
			} else if DevMode {
				log.Printf("[DEBUG] Failed to parse signature: %v", err)
			}
		}
	}

	err := sessionCache.Set(session)
	if err != nil {
		return nil, err
	}

	return session, nil
}

func HandleOAuthSignIn(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Provider   string `json:"provider"`
		RedirectTo string `json:"redirect_to,omitempty"`
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Provider == "" {
		http.Error(w, "Provider is required", http.StatusBadRequest)
		return
	}

	client := getUserClient()
	if client == nil {
		http.Error(w, "Authentication service unavailable", http.StatusServiceUnavailable)
		return
	}

	redirectURL := req.RedirectTo
	if redirectURL == "" {
		redirectURL = getBaseURL(r) + "/auth/callback"
	}

	providerDetails, err := client.Auth.SignInWithProvider(supabase.ProviderSignInOptions{
		Provider:   req.Provider,
		RedirectTo: redirectURL,
		FlowType: supabase.PKCE,
		Scopes: []string{"email", "profile"},
	})

	if err != nil {
		if DevMode {
			log.Printf("[DEBUG] Failed to get OAuth URL for %s: %v", req.Provider, err)
		}
		http.Error(w, "Failed to create OAuth request", http.StatusInternalServerError)
		return
	}

	if providerDetails.CodeVerifier != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "code_verifier",
			Value:    providerDetails.CodeVerifier,
			Path:     "/auth/callback",
			HttpOnly: true,
			Secure:   !DevMode,
			MaxAge:   300,
			SameSite: http.SameSiteLaxMode,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"url": providerDetails.URL,
	})
}

func HandleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		handleAuthError(w, r, "No authorization code provided")
		return
	}

	cookie, err := r.Cookie("code_verifier")
	if err != nil {
		handleAuthError(w, r, "Session expired, please try again")
		return
	}
	codeVerifier := cookie.Value

	client := getUserClient()
	if client == nil {
		handleAuthError(w, r, "Authentication service unavailable")
		return
	}

	authResult, err := client.Auth.ExchangeCode(r.Context(), supabase.ExchangeCodeOpts{
		AuthCode:     code,
		CodeVerifier: codeVerifier,
	})

	if err != nil {
		if DevMode {
			log.Printf("[DEBUG] OAuth callback failed: %v", err)
		}
		handleAuthError(w, r, "Failed to authenticate with provider")
		return
	}

	session, err := storeAuthenticatedDetails(authResult)
	if err != nil {
		if DevMode {
			log.Printf("[DEBUG] Failed to store session: %v", err)
		}
		handleAuthError(w, r, "Failed to create session")
		return
	}

	setAuthCookies(w, session.AccessToken, session.RefreshToken, session.ExpiresAt)

	http.SetCookie(w, &http.Cookie{
		Name:     "code_verifier",
		Value:    "",
		Path:     "/auth/callback",
		HttpOnly: true,
		MaxAge:   -1,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func HandleLogout(w http.ResponseWriter, r *http.Request) {
	token, err := getTokenFromRequest(r)
	if err == nil {
		client := getUserClient()
		if client != nil {
			_ = client.Auth.SignOut(r.Context(), token)
		}

		claims, err := extractClaims(token)
		if err == nil {
			if userID, ok := claims["sub"].(string); ok && userID != "" {
				sessionCache.Delete(userID)
			}
		}
	}

	clearAuthCookies(w)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{
		Success: true,
		Message: "Logout successful",
	})
}

func setAuthCookies(w http.ResponseWriter, accessToken, refreshToken string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     "auth-token",
		Value:    accessToken,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   !DevMode,
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh-token",
		Value:    refreshToken,
		Path:     "/",
		Expires:  time.Now().Add(30 * 24 * time.Hour),
		HttpOnly: true,
		Secure:   !DevMode,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "auth-token",
		Value:    "",
		Path:     "/",
		Expires:  time.Now().Add(-1 * time.Hour),
		HttpOnly: true,
		Secure:   !DevMode,
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh-token",
		Value:    "",
		Path:     "/",
		Expires:  time.Now().Add(-1 * time.Hour),
		HttpOnly: true,
		Secure:   !DevMode,
		SameSite: http.SameSiteLaxMode,
	})
}