package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/NYTimes/gziphandler"
	"github.com/golang-jwt/jwt/v5"
	supabase "github.com/nedpals/supabase-go"
)

var DebugMode = true

var AuthHost = "localhost:19283"

const (
	DefaultHost              = "www.mtgban.com"
	DefaultSignatureDuration = 11 * 24 * time.Hour
)

const (
	SupabaseUrl     = "https://cnqdgapyhionjgvzpasv.supabase.co"
	SupabaseAnonKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNucWRnYXB5aGlvbmpndnpwYXN2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3MzgyNzc4MjcsImV4cCI6MjA1Mzg1MzgyN30.YvJogdMuXMPE4_VzhoX5u-nsBhI-ydkDyNAV2KFNjOE"
)

const (
	ErrMsg        = "Join the BAN Community and gain access to exclusive tools!"
	ErrMsgPlus    = "Increase your pledge to gain access to this feature!"
	ErrMsgDenied  = "Something went wrong while accessing this page"
	ErrMsgExpired = "You've been logged out"
	ErrMsgRestart = "Website is restarting, please try again in a few minutes"
	ErrMsgUseAPI  = "Slow down, you're making too many requests! For heavy data use consider the BAN API"
)

// AuthService handles all authentication related functionality
type AuthService struct {
	Logger      *log.Logger
	Supabase    *supabase.Client
	SupabaseURL string
	SupabaseKey string
	DebugMode   bool
	BaseAuthURL string
}

// Config holds the configuration for the authentication service
type AuthConfig struct {
	SupabaseURL     string `json:"supabase_url"`
	SupabaseAnonKey string `json:"supabase_anon_key"`
	SupabaseSecret  string `json:"supabase_jwt_secret"`
	DebugMode       bool   `json:"debug_mode"`
	LogPrefix       string `json:"log_prefix"`
}

// MtgbanUserData holds user data for MTGBAN users
type MtgbanUserData struct {
	UserId string
	Email  string
}

// Initialize auth service from configuration file
func InitAuth(configFile string) (*AuthService, error) {
	// Set default config
	config := AuthConfig{
		SupabaseURL:     SupabaseUrl,
		SupabaseAnonKey: SupabaseAnonKey,
		DebugMode:       DebugMode,
		LogPrefix:       "[AUTH] ",
	}

	// Try to load from config file if provided
	if configFile != "" {
		file, err := os.Open(configFile)
		if err == nil {
			defer file.Close()
			if err := json.NewDecoder(file).Decode(&config); err != nil {
				return nil, fmt.Errorf("failed to parse config file: %w", err)
			}
		} else if !os.IsNotExist(err) && !DevMode {
			return nil, fmt.Errorf("failed to open config file: %w", err)
		}
	}
	// Create a new Supabase client
	log.Printf("Creating Supabase client with URL: %s", config.SupabaseURL)
	supabase := supabase.CreateClient(config.SupabaseURL, config.SupabaseAnonKey)
	if supabase != nil {
		log.Printf("Supabase client created successfully")
	} else {
		return nil, fmt.Errorf("failed to create Supabase client")
	}
	// Create the service
	service := &AuthService{
		Logger:      log.New(os.Stdout, config.LogPrefix, log.Ldate|log.Ltime|log.Lshortfile),
		Supabase:    supabase,
		DebugMode:   config.DebugMode,
		BaseAuthURL: config.SupabaseURL + "/auth/v1",
	}

	// Initialize the service
	service.Logger.Printf("Initializing authentication service")
	service.Logger.Printf("Supabase URL: %s", config.SupabaseURL)

	// Run full authentication flow test in debug mode
	if service.DebugMode {
		service.Logger.Printf("Running comprehensive authentication flow test")

		// Run a complete authentication flow test
		if err := service.testFullAuthFlow(); err != nil {
			service.Logger.Printf("Authentication flow test failed: %v", err)
			return nil, fmt.Errorf("authentication flow test failed: %w", err)
		}
		service.Logger.Printf("Authentication flow test completed successfully")
	}

	service.registerRoutes()
	service.Logger.Printf("Authentication service initialized successfully")

	return service, nil
}

// Test full authentication flow: connection, account creation, and login
func (a *AuthService) testFullAuthFlow() error {
	// Step 1: Test basic connection
	a.Logger.Printf("Testing connection to Supabase...")

	// Test DB connection with a simple query
	var testName []interface{}
	err := a.Supabase.DB.From("testing").Select("name").Limit(1).Execute(&testName)
	if err != nil {
		a.Logger.Printf("DB connection test: %v", err)
		// Even if this fails (table might not exist), we continue to auth tests
	} else {
		a.Logger.Printf("DB connection successful")
	}

	// Step 2: Create a test user
	testEmail := fmt.Sprintf("test_%s@gmail.com", generateRandomString(8))
	testPassword := "Test" + generateRandomString(10) + "123!"

	a.Logger.Printf("Creating test user with email: %s", testEmail)
	user, err := a.Supabase.Auth.SignUp(context.Background(), supabase.UserCredentials{
		Email:    testEmail,
		Password: testPassword,
	})
	if err != nil {
		return fmt.Errorf("test user creation failed: %w", err)
	}
	a.Logger.Printf("Test user created successfully: %s", user.ID)

	// Step 3: Login with the created user
	a.Logger.Printf("Testing login with created user...")
	authDetails, err := a.Supabase.Auth.SignIn(context.Background(), supabase.UserCredentials{
		Email:    testEmail,
		Password: testPassword,
	})
	if err != nil {
		return fmt.Errorf("test user login failed: %w", err)
	}
	a.Logger.Printf("Test user login successful, received token: %s", authDetails.AccessToken[:10]+"...")

	// Step 4: Verify the token by getting user info
	a.Logger.Printf("Verifying authentication token...")
	userInfo, err := a.Supabase.Auth.User(context.Background(), authDetails.AccessToken)
	if err != nil {
		return fmt.Errorf("token verification failed: %w", err)
	}
	a.Logger.Printf("Token verified successfully, confirmed user email: %s", userInfo.Email)

	return nil
}

// Generate a random string for unique test emails
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)

	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}

	return string(result)
}

// registerRoutes registers all authentication-related routes with http
func (a *AuthService) registerRoutes() {
	a.Logger.Printf("Registering authentication routes")

	// Authentication pages
	http.HandleFunc("/login", a.HandleAuthPage)
	http.HandleFunc("/signup", a.HandleAuthPage)
	http.HandleFunc("/forgot-password", a.HandleForgotPassword)
	http.HandleFunc("/reset-password-sent", a.HandleResetPasswordSent)
	http.HandleFunc("/signup-success", a.HandleSignupSuccess)

	// Authentication form submissions
	http.HandleFunc("/login-submit", a.HandleLogin)
	http.HandleFunc("/signup-submit", a.HandleSignup)
	http.HandleFunc("/forgot-password-submit", a.HandleForgotPasswordSubmit)
	http.HandleFunc("/logout", a.HandleLogout)

	a.Logger.Printf("Authentication routes registered successfully")
}

// HandleAuthPage renders the authentication page
func (a *AuthService) HandleAuthPage(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	clientIP := getClientIP(r)

	a.Logger.Printf("Auth page request from %s: %s", clientIP, path)

	pageVars := genPageNav("Authentication", "")
	pageVars.ErrorMessage = r.FormValue("errmsg")

	// Check if the request is for login or signup
	if strings.HasSuffix(path, "/signup") {
		pageVars.Title = "Sign Up - MTGBAN"
		pageVars.PageType = "signup"

		// Process error messages for signup
		switch pageVars.ErrorMessage {
		case "email_taken":
			pageVars.ErrorMessage = "This email is already registered."
			a.Logger.Printf("Signup error shown to %s: email already taken", clientIP)
		case "weak_password":
			pageVars.ErrorMessage = "Password is too weak. Please use at least 8 characters with letters, numbers, and special characters."
			a.Logger.Printf("Signup error shown to %s: weak password", clientIP)
		case "empty_fields":
			pageVars.ErrorMessage = "Please fill in all required fields."
			a.Logger.Printf("Signup error shown to %s: empty fields", clientIP)
		case "passwords_mismatch":
			pageVars.ErrorMessage = "Passwords do not match."
			a.Logger.Printf("Signup error shown to %s: passwords mismatch", clientIP)
		case "terms_required":
			pageVars.ErrorMessage = "You must accept the Terms of Service to create an account."
			a.Logger.Printf("Signup error shown to %s: terms not accepted", clientIP)
		case "database_error":
			pageVars.ErrorMessage = "We're having trouble with our database. Please try again later or contact support."
			a.Logger.Printf("Signup error shown to %s: database error", clientIP)
		case "connection_error":
			pageVars.ErrorMessage = "We're having trouble connecting to our servers. Please check your internet connection and try again."
			a.Logger.Printf("Signup error shown to %s: connection error", clientIP)
		case "invalid_data":
			pageVars.ErrorMessage = "Some of the information you provided is invalid. Please check your details and try again."
			a.Logger.Printf("Signup error shown to %s: invalid data", clientIP)
		case "signup_failed":
			pageVars.ErrorMessage = "Sorry, we couldn't create your account. Please try again later or contact support."
			a.Logger.Printf("Signup error shown to %s: general failure", clientIP)
		}
	} else {
		pageVars.Title = "Login - MTGBAN"
		pageVars.PageType = "login"

		// Process error messages for login
		switch pageVars.ErrorMessage {
		case "invalid":
			pageVars.ErrorMessage = "Invalid email or password."
			a.Logger.Printf("Login error shown to %s: invalid credentials", clientIP)
		case "empty":
			pageVars.ErrorMessage = "Please enter both email and password."
			a.Logger.Printf("Login error shown to %s: empty fields", clientIP)
		}
	}

	render(w, "auth.html", pageVars)
}

// HandleLogin handles the login process
func (a *AuthService) HandleLogin(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	a.Logger.Printf("Login attempt from %s", clientIP)

	if r.Method != "POST" {
		a.Logger.Printf("Invalid method for login from %s: %s", clientIP, r.Method)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	remember := r.FormValue("remember") == "on"

	// Mask email for logging
	maskedEmail := maskEmail(email)
	a.Logger.Printf("Login attempt details: email=%s, remember=%v", maskedEmail, remember)

	if email == "" || password == "" {
		a.Logger.Printf("Login failed from %s: empty credentials", clientIP)
		http.Redirect(w, r, "/login?errmsg=empty", http.StatusSeeOther)
		return
	}

	// Connect to Supabase and authenticate the user
	a.Logger.Printf("Connecting to Supabase for authentication: %s", maskedEmail)
	supabaseClient := supabase.CreateClient(a.SupabaseURL, a.SupabaseKey)
	ctx := context.Background()

	// Use the Supabase client to authenticate with email/password
	startTime := time.Now()
	authResponse, err := supabaseClient.Auth.SignIn(ctx, supabase.UserCredentials{
		Email:    email,
		Password: password,
	})
	authDuration := time.Since(startTime)

	if err != nil {
		a.Logger.Printf("Login failed for %s from %s: %v (took %v)", maskedEmail, clientIP, err, authDuration)
		http.Redirect(w, r, "/login?errmsg=invalid", http.StatusSeeOther)
		return
	}

	// Extract the JWT token
	jwtToken := authResponse.AccessToken
	refreshToken := authResponse.RefreshToken
	tokenLength := len(jwtToken)
	refreshTokenLength := len(refreshToken)

	a.Logger.Printf("Login successful for %s from %s (took %v, token_length=%d, refresh_token_length=%d)",
		maskedEmail, clientIP, authDuration, tokenLength, refreshTokenLength)

	// Get user data from the token
	a.Logger.Printf("Getting user data from token for %s", maskedEmail)
	userData, err := getUserIds(jwtToken)
	if err != nil {
		a.Logger.Printf("Failed to get user data for %s: %v", maskedEmail, err)
		http.Redirect(w, r, "/login?errmsg=invalid", http.StatusSeeOther)
		return
	}

	// Get user tier from token or set default
	a.Logger.Printf("Getting user tier for %s", maskedEmail)
	tierTitle, err := getUserTier(jwtToken)
	if err != nil {
		// If tier not found in token, set a default tier
		tierTitle = "free"
		a.Logger.Printf("No tier found for %s, defaulting to 'free'", maskedEmail)
	} else {
		a.Logger.Printf("User tier for %s: %s", maskedEmail, tierTitle)
	}

	// Create a signed cookie using the sign function
	baseURL := getBaseURL(r)
	sig := sign(baseURL, tierTitle, userData)

	// Set the formatted cookie with appropriate expiration
	expiration := time.Hour * 24 // Default to 24 hours
	if remember {
		expiration = time.Hour * 24 * 30 // 30 days if "remember me" is checked
		a.Logger.Printf("Setting long-term cookie expiration (30 days) for %s", maskedEmail)
	} else {
		a.Logger.Printf("Setting standard cookie expiration (24 hours) for %s", maskedEmail)
	}

	a.Logger.Printf("Setting auth cookies for %s", maskedEmail)
	putSignatureInCookies(w, r, sig)

	// Store refresh token in HTTP-only cookie
	refreshCookie := http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil, // Set secure flag if using HTTPS
		MaxAge:   int(expiration.Seconds()),
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, &refreshCookie)

	// Redirect to home page or original destination
	redirectURL := "/home"
	if returnTo := r.FormValue("return_to"); returnTo != "" {
		redirectURL = returnTo
		a.Logger.Printf("Redirecting %s to originally requested URL: %s", maskedEmail, redirectURL)
	} else {
		a.Logger.Printf("Redirecting %s to home page", maskedEmail)
	}

	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// HandleSignup handles the signup process
func (a *AuthService) HandleSignup(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	a.Logger.Printf("Signup attempt from %s", clientIP)

	if r.Method != "POST" {
		a.Logger.Printf("Invalid method for signup from %s: %s", clientIP, r.Method)
		http.Redirect(w, r, "/signup", http.StatusSeeOther)
		return
	}

	// Get form values
	email := r.FormValue("email")
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm-password")
	fullName := r.FormValue("fullname")
	termsAccepted := r.FormValue("terms") == "on"

	// Mask email for logging
	maskedEmail := maskEmail(email)
	a.Logger.Printf("Signup attempt details: email=%s, name_provided=%v, terms_accepted=%v",
		maskedEmail, fullName != "", termsAccepted)

	// Validate inputs
	if email == "" || password == "" || fullName == "" {
		a.Logger.Printf("Signup validation failed for %s from %s: empty fields", maskedEmail, clientIP)
		http.Redirect(w, r, "/signup?errmsg=empty_fields", http.StatusSeeOther)
		return
	}

	if password != confirmPassword {
		a.Logger.Printf("Signup validation failed for %s from %s: passwords don't match", maskedEmail, clientIP)
		http.Redirect(w, r, "/signup?errmsg=passwords_mismatch", http.StatusSeeOther)
		return
	}

	if !termsAccepted {
		a.Logger.Printf("Signup validation failed for %s from %s: terms not accepted", maskedEmail, clientIP)
		http.Redirect(w, r, "/signup?errmsg=terms_required", http.StatusSeeOther)
		return
	}

	// Check password strength
	passwordStrength := checkPasswordStrength(password)
	a.Logger.Printf("Password strength for %s: %s", maskedEmail, passwordStrength)

	if len(password) < 8 {
		a.Logger.Printf("Signup validation failed for %s from %s: password too short", maskedEmail, clientIP)
		http.Redirect(w, r, "/signup?errmsg=weak_password", http.StatusSeeOther)
		return
	}

	// Connect to Supabase
	a.Logger.Printf("Connecting to Supabase for signup: %s", maskedEmail)
	a.Logger.Printf("Supabase URL being used: %s", maskURL(a.SupabaseURL))
	a.Logger.Printf("API key length: %d characters", len(a.SupabaseKey))

	// Create a raw HTTP request to test connectivity
	testReq, err := http.NewRequest("GET", a.SupabaseURL+"/auth/v1/health", nil)
	if err != nil {
		a.Logger.Printf("Failed to create test request: %v", err)
	} else {
		testReq.Header.Set("apikey", a.SupabaseKey)
		client := &http.Client{Timeout: 5 * time.Second}
		testResp, testErr := client.Do(testReq)
		if testErr != nil {
			a.Logger.Printf("Connection test failed: %v", testErr)
		} else {
			a.Logger.Printf("Connection test status: %d", testResp.StatusCode)
			testResp.Body.Close()
		}
	}

	// Create user metadata
	// IMPORTANT: Keep metadata structure simple to avoid JSONB parsing issues
	userMetadata := map[string]interface{}{
		"full_name": fullName,
	}

	// Log the exact structure being sent to Supabase
	a.Logger.Printf("Creating user with email: %s, password length: %d, metadata: %+v",
		maskedEmail, len(password), userMetadata)

	// Try first with the supabase-go library
	supabaseClient := supabase.CreateClient(a.SupabaseURL, a.SupabaseKey)
	ctx := context.Background()

	startTime := time.Now()
	user, err := supabaseClient.Auth.SignUp(ctx, supabase.UserCredentials{
		Email:    email,
		Password: password,
		Data:     userMetadata,
	})
	signupDuration := time.Since(startTime)

	if err != nil {
		a.Logger.Printf("Library signup failed for %s from %s: %v (took %v)",
			maskedEmail, clientIP, err, signupDuration)

		// Try a direct HTTP request to get more details about the error
		a.Logger.Printf("Attempting direct HTTP signup request for better diagnostics")

		// Construct manual request
		directSignupData := map[string]interface{}{
			"email":    email,
			"password": password,
			"data":     userMetadata,
		}

		jsonData, jsonErr := json.Marshal(directSignupData)
		if jsonErr != nil {
			a.Logger.Printf("JSON marshaling error: %v", jsonErr)
		} else {
			directReq, reqErr := http.NewRequest("POST", a.SupabaseURL+"/auth/v1/signup", bytes.NewBuffer(jsonData))
			if reqErr != nil {
				a.Logger.Printf("Failed to create direct request: %v", reqErr)
			} else {
				directReq.Header.Set("apikey", a.SupabaseKey)
				directReq.Header.Set("Content-Type", "application/json")

				directClient := &http.Client{Timeout: 10 * time.Second}
				directResp, directErr := directClient.Do(directReq)

				if directErr != nil {
					a.Logger.Printf("Direct request failed: %v", directErr)
				} else {
					body, _ := io.ReadAll(directResp.Body)
					a.Logger.Printf("Direct signup response status: %d, body: %s",
						directResp.StatusCode, string(body))
					directResp.Body.Close()
				}
			}
		}

		// Check for common errors and redirect appropriately
		errMsg := err.Error()
		a.Logger.Printf("Detailed error message: %s", errMsg)

		if strings.Contains(strings.ToLower(errMsg), "already") ||
			strings.Contains(strings.ToLower(errMsg), "taken") {
			a.Logger.Printf("Email already taken: %s", maskedEmail)
			http.Redirect(w, r, "/signup?errmsg=email_taken", http.StatusSeeOther)
		} else if strings.Contains(strings.ToLower(errMsg), "database") {
			a.Logger.Printf("Database error: %v", err)
			http.Redirect(w, r, "/signup?errmsg=database_error", http.StatusSeeOther)
		} else {
			a.Logger.Printf("General signup error: %v", err)
			http.Redirect(w, r, "/signup?errmsg=signup_failed", http.StatusSeeOther)
		}
		return
	}

	a.Logger.Printf("Signup successful for %s from %s (took %v)", maskedEmail, clientIP, signupDuration)
	a.Logger.Printf("User details: ID=%s, Email confirmed=%v", user.ID, !user.ConfirmedAt.IsZero())

	// If email confirmation is NOT required in Supabase settings (user is already confirmed)
	if !user.ConfirmedAt.IsZero() {
		a.Logger.Printf("Auto-login for new user %s", maskedEmail)

		// Auto-login the user after signup
		startLoginTime := time.Now()
		authResponse, err := supabaseClient.Auth.SignIn(ctx, supabase.UserCredentials{
			Email:    email,
			Password: password,
		})
		autoLoginDuration := time.Since(startLoginTime)

		if err == nil {
			a.Logger.Printf("Auto-login successful for %s (took %v)", maskedEmail, autoLoginDuration)

			// Extract the JWT token
			jwtToken := authResponse.AccessToken
			refreshToken := authResponse.RefreshToken

			// Get user data
			userData, err := getUserIds(jwtToken)
			if err != nil {
				a.Logger.Printf("Error getting user data during auto-login: %v", err)
			}

			tierTitle := "free" // Default tier for new users
			a.Logger.Printf("Setting new user %s to 'free' tier", maskedEmail)

			// Create and set cookies
			baseURL := getBaseURL(r)
			sig := sign(baseURL, tierTitle, userData)
			putSignatureInCookies(w, r, sig)

			// Set refresh token cookie
			refreshCookie := http.Cookie{
				Name:     "refresh_token",
				Value:    refreshToken,
				Path:     "/",
				HttpOnly: true,
				Secure:   r.TLS != nil,
				MaxAge:   int((time.Hour * 24).Seconds()),
				SameSite: http.SameSiteStrictMode,
			}
			http.SetCookie(w, &refreshCookie)

			a.Logger.Printf("Redirecting new user %s to home page", maskedEmail)
			http.Redirect(w, r, "/home", http.StatusSeeOther)
			return
		} else {
			a.Logger.Printf("Auto-login failed for new user %s: %v", maskedEmail, err)
		}
	}

	// Redirect to a confirmation page if email verification is required
	a.Logger.Printf("Redirecting %s to signup success page (email verification pending)", maskedEmail)
	http.Redirect(w, r, "/signup-success", http.StatusSeeOther)
}

// HandleForgotPassword renders the forgot password page
func (a *AuthService) HandleForgotPassword(w http.ResponseWriter, r *http.Request) {
	errmsg := r.FormValue("errmsg")
	message := ""

	switch errmsg {
	case "empty_email":
		message = "Please enter your email address."
	case "failed":
		message = "Failed to process your request. Please try again later."
	}

	pageVars := genPageNav("Forgot Password", "")
	pageVars.ErrorMessage = message

	render(w, "forgot-password.html", pageVars)
}

// HandleForgotPasswordSubmit initiates the password reset process
func (a *AuthService) HandleForgotPasswordSubmit(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	a.Logger.Printf("Password reset request from %s", clientIP)

	if r.Method != "POST" {
		a.Logger.Printf("Invalid method for password reset from %s: %s", clientIP, r.Method)
		http.Redirect(w, r, "/forgot-password", http.StatusSeeOther)
		return
	}

	email := r.FormValue("email")
	maskedEmail := maskEmail(email)

	if email == "" {
		a.Logger.Printf("Password reset validation failed from %s: empty email", clientIP)
		http.Redirect(w, r, "/forgot-password?errmsg=empty_email", http.StatusSeeOther)
		return
	}

	a.Logger.Printf("Processing password reset for %s from %s", maskedEmail, clientIP)

	// Connect to Supabase
	supabaseClient := supabase.CreateClient(a.SupabaseURL, a.SupabaseKey)
	ctx := context.Background()

	// Request password recovery
	startTime := time.Now()
	err := supabaseClient.Auth.ResetPasswordForEmail(ctx, email, "/reset-password-sent")
	resetDuration := time.Since(startTime)

	if err != nil {
		a.Logger.Printf("Password reset failed for %s from %s: %v (took %v)",
			maskedEmail, clientIP, err, resetDuration)
		http.Redirect(w, r, "/forgot-password?errmsg=failed", http.StatusSeeOther)
		return
	}

	a.Logger.Printf("Password reset request successful for %s from %s (took %v)",
		maskedEmail, clientIP, resetDuration)

	// Always redirect to success page, even if email doesn't exist
	// for security reasons (prevents email enumeration)
	a.Logger.Printf("Redirecting %s to reset confirmation page", maskedEmail)
	http.Redirect(w, r, "/reset-password-sent", http.StatusSeeOther)
}

// HandleResetPasswordSent renders the reset password confirmation page
func (a *AuthService) HandleResetPasswordSent(w http.ResponseWriter, r *http.Request) {
	pageVars := genPageNav("Reset Password", "")
	pageVars.PageMessage = "If an account exists with that email, we've sent password reset instructions."

	render(w, "reset-password-sent.html", pageVars)
}

// HandleSignupSuccess renders the signup success page
func (a *AuthService) HandleSignupSuccess(w http.ResponseWriter, r *http.Request) {
	pageVars := genPageNav("Registration Successful", "")
	pageVars.PageMessage = "Your account has been created. Please check your email to verify your account."

	render(w, "signup-success.html", pageVars)
}

// HandleLogout handles logging out by clearing cookies
func (a *AuthService) HandleLogout(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	a.Logger.Printf("Logout request from %s", clientIP)

	// Clear all auth cookies
	http.SetCookie(w, &http.Cookie{
		Name:     "signature",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	a.Logger.Printf("All auth cookies cleared for %s", clientIP)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// HandleRefreshToken attempts to get a new access token using the refresh token
func (a *AuthService) HandleRefreshToken(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	a.Logger.Printf("Token refresh attempt from %s", clientIP)

	// Get refresh token from cookie
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		a.Logger.Printf("Token refresh failed from %s: no refresh token cookie", clientIP)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	refreshToken := cookie.Value
	tokenLength := len(refreshToken)
	a.Logger.Printf("Found refresh token from %s (length=%d)", clientIP, tokenLength)

	// Prepare refresh token request
	data := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	}

	jsonData, _ := json.Marshal(data)
	req, err := http.NewRequest("POST", a.SupabaseURL+"/auth/v1/token", bytes.NewBuffer(jsonData))
	if err != nil {
		a.Logger.Printf("Failed to create refresh token request from %s: %v", clientIP, err)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", a.SupabaseKey)

	// Send request
	a.Logger.Printf("Sending refresh token request to Supabase from %s", clientIP)
	startTime := time.Now()
	client := &http.Client{}
	resp, err := client.Do(req)
	refreshDuration := time.Since(startTime)

	if err != nil {
		a.Logger.Printf("Token refresh network error from %s: %v (took %v)",
			clientIP, err, refreshDuration)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		a.Logger.Printf("Token refresh failed from %s with status %d (took %v)",
			clientIP, resp.StatusCode, refreshDuration)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Parse response
	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		a.Logger.Printf("Failed to parse refresh token response from %s: %v", clientIP, err)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	a.Logger.Printf("Token refresh successful from %s (took %v)", clientIP, refreshDuration)

	// Update tokens and user session
	accessToken, _ := result["access_token"].(string)
	newRefreshToken, _ := result["refresh_token"].(string)

	if accessToken == "" {
		a.Logger.Printf("No access token in refresh response from %s", clientIP)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	tokenLength = len(accessToken)
	newRefreshTokenLength := len(newRefreshToken)
	a.Logger.Printf("New tokens received from %s: token_length=%d, refresh_token_length=%d",
		clientIP, tokenLength, newRefreshTokenLength)

	// Update user session with new tokens
	userData, err := getUserIds(accessToken)
	if err != nil {
		a.Logger.Printf("Failed to extract user data from refreshed token for %s: %v", clientIP, err)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	a.Logger.Printf("User data extracted from refreshed token for %s", clientIP)

	tierTitle, err := getUserTier(accessToken)
	if err != nil || tierTitle == "" {
		tierTitle = "free"
		a.Logger.Printf("No tier found in refreshed token for %s, defaulting to 'free'", clientIP)
	} else {
		a.Logger.Printf("User tier from refreshed token for %s: %s", clientIP, tierTitle)
	}

	baseURL := getBaseURL(r)
	sig := sign(baseURL, tierTitle, userData)
	putSignatureInCookies(w, r, sig)
	a.Logger.Printf("Updated signature cookie for %s", clientIP)

	// Update refresh token cookie
	refreshCookie := http.Cookie{
		Name:     "refresh_token",
		Value:    newRefreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		MaxAge:   int((time.Hour * 24 * 30).Seconds()),
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, &refreshCookie)
	a.Logger.Printf("Updated refresh token cookie for %s", clientIP)

	// Redirect to the original request URL or home
	originalURL := r.URL.String()
	a.Logger.Printf("Redirecting %s to original URL after token refresh: %s", clientIP, originalURL)
	http.Redirect(w, r, originalURL, http.StatusSeeOther)
}

// WrapAuthMiddleware wraps a handler with authentication middleware
func (a *AuthService) WrapAuthMiddleware(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		path := r.URL.Path

		a.Logger.Printf("Auth check for %s accessing %s", clientIP, path)

		// Check if user is authenticated
		_, err := r.Cookie("signature")
		if err != nil {
			a.Logger.Printf("No signature cookie found for %s accessing %s", clientIP, path)

			// Try to refresh token if signature is missing but refresh token exists
			refreshCookie, refreshErr := r.Cookie("refresh_token")
			if refreshErr == nil {
				refreshTokenLength := len(refreshCookie.Value)
				a.Logger.Printf("Found refresh token for %s (length=%d), attempting refresh",
					clientIP, refreshTokenLength)
				a.HandleRefreshToken(w, r)
				return
			}

			a.Logger.Printf("No refresh token found for %s, redirecting to login", clientIP)

			// If we can't refresh, redirect to login
			redirectURL := "/login"
			if r.URL.Path != "/" && r.URL.Path != "/login" && r.URL.Path != "/signup" {
				redirectURL = "/login?return_to=" + r.URL.Path
				a.Logger.Printf("Setting return_to=%s for %s", r.URL.Path, clientIP)
			}

			a.Logger.Printf("Redirecting unauthenticated user %s to %s", clientIP, redirectURL)
			http.Redirect(w, r, redirectURL, http.StatusSeeOther)
			return
		}

		a.Logger.Printf("User %s authenticated, proceeding to %s", clientIP, path)
		// Continue to the protected handler
		handler(w, r)
	}
}

// getUseroken exchanges the authorization code for a JWT token
func getUserToken(code, baseURL, ref string) (string, error) {
	supabaseClient := supabase.CreateClient(SupabaseUrl, SupabaseAnonKey)

	ctx := context.Background()
	resp, err := supabaseClient.Auth.ExchangeCode(ctx, supabase.ExchangeCodeOpts{
		AuthCode: code,
	})
	if err != nil {
		return "", err
	}

	jwt := resp.AccessToken
	if jwt == "" {
		return "", errors.New("no jwt in response")
	}

	return jwt, nil
}

// getUserIds returns the user ID and email from the JWT token
func getUserIds(jwtToken string) (*MtgbanUserData, error) {
	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(SupabaseAnonKey), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid JWT token")
	}

	userData := &MtgbanUserData{
		UserId: claims["sub"].(string),
		Email:  strings.ToLower(claims["email"].(string)),
	}
	return userData, nil
}

// getUserTier returns the user tier from the JWT token
func getUserTier(jwtToken string) (string, error) {
	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(SupabaseAnonKey), nil
	})
	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", errors.New("invalid JWT token")
	}

	tierTitle, ok := claims["tier"].(string)
	if !ok {
		return "", errors.New("no tier in webtoken")
	}
	return tierTitle, nil
}

// getBaseURL returns the base URL of the request
func getBaseURL(r *http.Request) string {
	host := r.Host
	if host == "localhost:"+fmt.Sprint(Config.Port) && !DevMode {
		host = DefaultHost
	}
	baseURL := "http://" + host
	if r.TLS != nil {
		baseURL = strings.Replace(baseURL, "http", "https", 1)
	}
	return baseURL
}

// signHMACSHA1Base64 signs the data with the key using HMAC SHA1 and returns the base64 encoded string
func signHMACSHA1Base64(key []byte, data []byte) string {
	h := hmac.New(sha1.New, key)
	h.Write(data)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// getSignatureFromCookies returns the signature from the cookies
func getSignatureFromCookies(r *http.Request) string {
	var sig string
	for _, cookie := range r.Cookies() {
		if cookie.Name == "MTGBAN" {
			sig = cookie.Value
			break
		}
	}

	querySig := r.FormValue("sig")
	if sig == "" && querySig != "" {
		sig = querySig
	}

	exp := GetParamFromSig(sig, "Expires")
	if exp == "" {
		return ""
	}
	expires, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || expires < time.Now().Unix() {
		return ""
	}

	return sig
}

// putSignatureInCookies sets the signature in the cookies
func putSignatureInCookies(w http.ResponseWriter, r *http.Request, sig string) {
	baseURL := getBaseURL(r)

	year, month, _ := time.Now().Date()
	endOfThisMonth := time.Date(year, month+1, 1, 0, 0, 0, 0, time.Now().Location())
	domain := "mtgban.com"
	if strings.Contains(baseURL, "localhost") {
		domain = "localhost"
	}
	cookie := http.Cookie{
		Name:    "MTGBAN",
		Domain:  domain,
		Path:    "/",
		Expires: endOfThisMonth,
		Value:   sig,
	}

	http.SetCookie(w, &cookie)
}

// noSigning is a middleware that does not enforce any signing
func noSigning(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer recoverPanic(r, w)

		if AuthHost == "" {
			AuthHost = getBaseURL(r) + "/auth"
		}

		querySig := r.FormValue("sig")
		if querySig != "" {
			putSignatureInCookies(w, r, querySig)
		}

		next.ServeHTTP(w, r)
	})
}

// enforceAPISigning is a middleware that enforces API signing
func enforceAPISigning(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer recoverPanic(r, w)

		w.Header().Add("RateLimit-Limit", fmt.Sprint(APIRequestsPerSec))

		ip, err := IpAddress(r)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if !APIRateLimiter.allow(string(ip)) {
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}

		if !DatabaseLoaded {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}

		w.Header().Add("Content-Type", "application/json")

		sig := r.FormValue("sig")

		// If signature is empty let it pass through
		if sig == "" {
			gziphandler.GzipHandler(next).ServeHTTP(w, r)
			return
		}

		raw, err := base64.StdEncoding.DecodeString(sig)
		if SigCheck && err != nil {
			log.Println("API error, no sig", err)
			w.Write([]byte(`{"error": "invalid signature"}`))
			return
		}

		v, err := url.ParseQuery(string(raw))
		if SigCheck && err != nil {
			log.Println("API error, no b64", err)
			w.Write([]byte(`{"error": "invalid b64 signature"}`))
			return
		}

		q := url.Values{}
		q.Set("API", v.Get("API"))

		for _, optional := range OptionalFields {
			val := v.Get(optional)
			if val != "" {
				q.Set(optional, val)
			}
		}

		sig = v.Get("Signature")
		exp := v.Get("Expires")

		secret := os.Getenv("BAN_SECRET")
		apiUsersMutex.RLock()
		user_secret, found := Config.ApiUserSecrets[v.Get("UserEmail")]
		apiUsersMutex.RUnlock()
		if found {
			secret = user_secret
		}

		var expires int64
		if exp != "" {
			expires, err = strconv.ParseInt(exp, 10, 64)
			if err != nil {
				log.Println("API error", err.Error())
				w.Write([]byte(`{"error": "invalid or expired signature"}`))
				return
			}
			q.Set("Expires", exp)
		}

		data := fmt.Sprintf("%s%s%s%s", r.Method, exp, getBaseURL(r), q.Encode())
		valid := signHMACSHA1Base64([]byte(secret), []byte(data))

		if SigCheck && (valid != sig || (exp != "" && (expires < time.Now().Unix()))) {
			log.Println("API error, invalid", data)
			w.Write([]byte(`{"error": "invalid or expired signature"}`))
			return
		}

		gziphandler.GzipHandler(next).ServeHTTP(w, r)
	})
}

// enforceSigning is a middleware that enforces signing
func enforceSigning(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer recoverPanic(r, w)

		if AuthHost == "" {
			AuthHost = getBaseURL(r) + "/auth"
		}
		sig := getSignatureFromCookies(r)
		querySig := r.FormValue("sig")
		if querySig != "" {
			sig = querySig
			putSignatureInCookies(w, r, querySig)
		}

		switch r.Method {
		case "GET":
		case "POST":
			var ok bool
			for _, nav := range ExtraNavs {
				if nav.Link == r.URL.Path {
					ok = nav.CanPOST
				}
			}
			if !ok {
				http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
				return
			}
		default:
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		pageVars := genPageNav("Error", sig)

		if !UserRateLimiter.allow(GetParamFromSig(sig, "UserEmail")) && r.URL.Path != "/admin" {
			pageVars.Title = "Too Many Requests"
			pageVars.ErrorMessage = ErrMsgUseAPI

			render(w, "home.html", pageVars)
			return
		}

		raw, err := base64.StdEncoding.DecodeString(sig)
		if SigCheck && err != nil {
			pageVars.Title = "Unauthorized"
			pageVars.ErrorMessage = ErrMsg
			if DevMode {
				pageVars.ErrorMessage += " - " + err.Error()
			}

			render(w, "home.html", pageVars)
			return
		}

		v, err := url.ParseQuery(string(raw))
		if SigCheck && err != nil {
			pageVars.Title = "Unauthorized"
			pageVars.ErrorMessage = ErrMsg
			if DevMode {
				pageVars.ErrorMessage += " - " + err.Error()
			}

			render(w, "home.html", pageVars)
			return
		}

		q := url.Values{}
		for _, optional := range append(OrderNav, OptionalFields...) {
			val := v.Get(optional)
			if val != "" {
				q.Set(optional, val)
			}
		}

		expectedSig := v.Get("Signature")
		exp := v.Get("Expires")

		data := fmt.Sprintf("GET%s%s%s", exp, getBaseURL(r), q.Encode())
		valid := signHMACSHA1Base64([]byte(os.Getenv("BAN_SECRET")), []byte(data))
		expires, err := strconv.ParseInt(exp, 10, 64)
		if SigCheck && (err != nil || valid != expectedSig || expires < time.Now().Unix()) {
			if r.Method != "GET" {
				http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
				return
			}
			pageVars.Title = "Unauthorized"
			pageVars.ErrorMessage = ErrMsg
			if valid == expectedSig && expires < time.Now().Unix() {
				pageVars.ErrorMessage = ErrMsgExpired
				if DevMode {
					pageVars.ErrorMessage += " - sig expired"
				}
			}

			if DevMode {
				if err != nil {
					pageVars.ErrorMessage += " - " + err.Error()
				} else {
					pageVars.ErrorMessage += " - wrong host"
				}
			}
			// If sig is invalid, redirect to home
			render(w, "home.html", pageVars)
			return
		}

		if !DatabaseLoaded && r.URL.Path != "/admin" {
			page := "home.html"
			for _, navName := range OrderNav {
				nav := ExtraNavs[navName]
				if r.URL.Path == nav.Link {
					pageVars = genPageNav(nav.Name, sig)
					page = nav.Page
				}
			}
			pageVars.Title = "Great things are coming"
			pageVars.ErrorMessage = ErrMsgRestart

			render(w, page, pageVars)
			return
		}

		for _, navName := range OrderNav {
			nav := ExtraNavs[navName]
			if r.URL.Path == nav.Link {
				param := GetParamFromSig(sig, navName)
				canDo, _ := strconv.ParseBool(param)
				if DevMode && nav.AlwaysOnForDev {
					canDo = true
				}
				if SigCheck && !canDo {
					pageVars = genPageNav(nav.Name, sig)
					pageVars.Title = "This feature is BANned"
					pageVars.ErrorMessage = ErrMsgPlus

					render(w, nav.Page, pageVars)
					return
				}
				break
			}
		}

		gziphandler.GzipHandler(next).ServeHTTP(w, r)
	})
}

// recoverPanic recovers from a panic and sends an error response
func recoverPanic(r *http.Request, w http.ResponseWriter) {
	errPanic := recover()
	if errPanic != nil {
		log.Println("panic occurred:", errPanic)

		// Restrict stack size to fit into discord message
		buf := make([]byte, 1<<16)
		runtime.Stack(buf, true)
		if len(buf) > 1024 {
			buf = buf[:1024]
		}

		var msg string
		err, ok := errPanic.(error)
		if ok {
			msg = err.Error()
		} else {
			msg = "unknown error"
		}
		ServerNotify("panic", msg, true)
		ServerNotify("panic", string(buf))
		ServerNotify("panic", "source request: "+r.URL.String())

		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// getValuesForTier is used to generate the query parameters for signing
func getValuesForTier(tierTitle string) url.Values {
	v := url.Values{}
	tier, found := Config.ACL[tierTitle]
	if !found {
		return v
	}
	for _, page := range OrderNav {
		options, found := tier[page]
		if !found {
			continue
		}
		v.Set(page, "true")

		for _, key := range OptionalFields {
			val, found := options[key]
			if !found {
				continue
			}
			v.Set(key, val)
		}
	}
	return v
}

// sign signs the link with the given tier and user data
func sign(link string, tierTitle string, userData *MtgbanUserData) string {
	v := getValuesForTier(tierTitle)
	if userData != nil {
		v.Set("UserEmail", userData.Email)
		v.Set("UserTier", tierTitle)
	}

	expires := time.Now().Add(DefaultSignatureDuration)
	data := fmt.Sprintf("GET%d%s%s", expires.Unix(), link, v.Encode())
	key := os.Getenv("BAN_SECRET")
	sig := signHMACSHA1Base64([]byte(key), []byte(data))

	v.Set("Expires", fmt.Sprintf("%d", expires.Unix()))
	v.Set("Signature", sig)
	str := base64.StdEncoding.EncodeToString([]byte(v.Encode()))

	return str
}

// GetParamFromSig returns the value of a parameter from the signature
func GetParamFromSig(sig, param string) string {
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return ""
	}
	v, err := url.ParseQuery(string(raw))
	if err != nil {
		return ""
	}
	return v.Get(param)
}

// Auth handles the authentication process
func Auth(w http.ResponseWriter, r *http.Request) {
	baseURL := getBaseURL(r)
	code := r.FormValue("code")
	if code == "" {
		http.Redirect(w, r, baseURL, http.StatusFound)
		return
	}

	jwt, err := getUserToken(code, baseURL, r.FormValue("state"))
	if err != nil {
		LogPages["Admin"].Println("getUserToken", err.Error())
		http.Redirect(w, r, baseURL+"?errmsg=TokenNotFound", http.StatusFound)
		return
	}

	userData, err := getUserIds(jwt)
	if err != nil {
		LogPages["Admin"].Println("getUserId", err.Error())
		http.Redirect(w, r, baseURL+"?errmsg=UserNotFound", http.StatusFound)
		return
	}

	tierTitle, err := getUserTier(jwt)
	if err != nil {
		LogPages["Admin"].Println("getUserTier", err.Error())
		http.Redirect(w, r, baseURL+"?errmsg=TierNotFound", http.StatusFound)
		return
	}

	LogPages["Admin"].Println(userData)
	LogPages["Admin"].Println(tierTitle)

	// Sign our base URL with our tier and other data
	sig := sign(baseURL, tierTitle, userData)

	// Keep it secret. Keep it safe.
	putSignatureInCookies(w, r, sig)

	// Redirect to the URL indicated in this query param, or go to homepage
	redir := r.FormValue("state")
	if redir == "" {
		redir = getBaseURL(r)
	}

	// Redirect, we're done here
	http.Redirect(w, r, redir, http.StatusFound)
}
