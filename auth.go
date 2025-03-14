package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
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
	"unicode"

	"github.com/NYTimes/gziphandler"
	"github.com/golang-jwt/jwt/v5"
	supabase "github.com/nedpals/supabase-go"
)

var (
	DebugMode       = false // Default to false for security
	Host            = "localhost"
	AuthPort        = 19283
	AuthHost        = Host + ":" + fmt.Sprint(AuthPort)
	SupabaseUrl     = os.Getenv("SUPABASE_URL")
	SupabaseAnonKey = os.Getenv("SUPABASE_ANON_KEY")
)

const (
	DefaultHost              = "www.mtgban.com"
	DefaultSignatureDuration = 11 * 24 * time.Hour
)

const (
	ErrMsg        = "Join the BAN Community and gain access to exclusive tools!"
	ErrMsgPlus    = "Increase your pledge to gain access to this feature!"
	ErrMsgDenied  = "Something went wrong while accessing this page"
	ErrMsgExpired = "You've been logged out"
	ErrMsgRestart = "Website is restarting, please try again in a few minutes"
	ErrMsgUseAPI  = "Slow down, you're making too many requests! For heavy data use consider the BAN API"
)

// Route defines a single route with its handler and middleware
type Route struct {
	Handler    http.HandlerFunc
	Middleware func(http.Handler) http.Handler
}

// JWT handles all token-related operations
type JWT struct {
	SupabaseSecret string
	Logger         *log.Logger
}

// NewJWT creates a new JWT handler
func NewJWT(secret string, logger *log.Logger) *JWT {
	return &JWT{
		SupabaseSecret: secret,
		Logger:         logger,
	}
}

// GetUserData extracts user data from a JWT token
func (j *JWT) GetUserData(jwtToken string) (*MtgbanUserData, error) {
	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		// Validate the alg is what you expect
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(j.SupabaseSecret), nil
	})
	if err != nil {
		j.Logger.Printf("JWT parsing error: %v", err)
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		j.Logger.Printf("Invalid JWT token")
		return nil, errors.New("invalid JWT token")
	}

	userId, ok := claims["sub"].(string)
	if !ok {
		j.Logger.Printf("JWT missing 'sub' claim")
		return nil, errors.New("jwt missing user id")
	}

	email, ok := claims["email"].(string)
	if !ok {
		j.Logger.Printf("JWT missing 'email' claim")
		return nil, errors.New("jwt missing email")
	}

	userData := &MtgbanUserData{
		UserId: userId,
		Email:  strings.ToLower(email),
	}
	return userData, nil
}

// GetUserTier extracts the user tier from the JWT token
func (j *JWT) GetUserTier(jwtToken string) (string, error) {
	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(j.SupabaseSecret), nil
	})
	if err != nil {
		j.Logger.Printf("JWT parsing error when getting tier: %v", err)
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		j.Logger.Printf("Invalid JWT token when getting tier")
		return "", errors.New("invalid JWT token")
	}

	tierTitle, ok := claims["tier"].(string)
	if !ok {
		j.Logger.Printf("JWT missing 'tier' claim")
		return "", errors.New("no tier in webtoken")
	}
	return tierTitle, nil
}

// AuthService handles all authentication related functionality
type AuthService struct {
	Logger         *log.Logger
	Supabase       *supabase.Client
	SupabaseURL    string
	SupabaseKey    string
	SupabaseSecret string
	DebugMode      bool
	BaseAuthURL    string
	JWT            *JWT
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

// loadAuthConfig loads the authentication configuration from a file
func loadAuthConfig(configFile string) *AuthConfig {
	config := AuthConfig{
		SupabaseURL:     SupabaseUrl,
		SupabaseAnonKey: SupabaseAnonKey,
		DebugMode:       DebugMode,
		LogPrefix:       "[AUTH] ",
	}
	if configFile != "" {
		file, err := os.Open(configFile)
		if err == nil {
			defer file.Close()
			if err := json.NewDecoder(file).Decode(&config); err != nil {
				log.Printf("failed to parse config file: %v", err)
				return &config
			}
		} else if !os.IsNotExist(err) && !DevMode {
			log.Printf("failed to open config file: %v", err)
			return &config
		}
	}
	return &config
}

// NewAuth creates a new authentication service
func NewAuth(configFile string) (*AuthService, error) {
	if configFile == "" {
		configFile = "auth_config.json"
	}
	config := loadAuthConfig(configFile)

	// Create logger
	logger := log.New(os.Stdout, config.LogPrefix, log.Ldate|log.Ltime|log.Lshortfile)
	logger.Printf("Creating Supabase client with URL: %s", config.SupabaseURL)

	// Create Supabase client
	supabase := supabase.CreateClient(config.SupabaseURL, config.SupabaseAnonKey)
	if supabase == nil {
		return nil, fmt.Errorf("failed to create Supabase client")
	}

	logger.Printf("Supabase client created successfully")

	// Create JWT handler
	jwtHandler := NewJWT(config.SupabaseSecret, logger)

	// Create the service
	service := &AuthService{
		Logger:         logger,
		Supabase:       supabase,
		SupabaseURL:    config.SupabaseURL,
		SupabaseKey:    config.SupabaseAnonKey,
		SupabaseSecret: config.SupabaseSecret,
		DebugMode:      config.DebugMode,
		BaseAuthURL:    config.SupabaseURL + "/auth/v1",
		JWT:            jwtHandler,
	}
	service.Logger.Printf("Auth service initialized")
	return service, nil
}

// routeLogger logs a message asynchronously
func routeLogger(message string) {
	go func() {
		logger := log.New(os.Stdout, "", log.LstdFlags)
		logger.Println(message)
	}()
}

func requiresAuth(path string) bool {
	// First check ExtraNavs for NoAuth flag
	for _, navName := range OrderNav {
		nav := ExtraNavs[navName]
		if nav.Link == path && nav.NoAuth {
			return false
		}

		for _, subPage := range nav.SubPages {
			if subPage == path && nav.NoAuth {
				return false
			}
		}
	}

	// Then check against protected paths
	authPaths := []string{
		"/account",
		"/profile",
		"/settings",
		"/admin",
	}

	for _, authPath := range authPaths {
		if strings.HasPrefix(path, authPath) {
			return true
		}
	}

	// Check if the path is in ExtraNavs and not marked as NoAuth
	for _, navName := range OrderNav {
		nav := ExtraNavs[navName]
		if (nav.Link == path || contains(nav.SubPages, path)) && !nav.NoAuth {
			return true
		}
	}

	return false
}

// Test full authentication flow: connection, account creation, and login
func (a *AuthService) testFullAuthFlow() error {
	// Step 1: Test basic connection
	a.Logger.Printf("Testing connection to Supabase...")

	// Test DB connection with a simple query
	var testName []interface{}
	err := a.Supabase.DB.From("active_products").Select("product_name").Limit(1).Execute(&testName)
	if err != nil {
		a.Logger.Printf("DB connection test: %v", err)
	} else {
		a.Logger.Printf("DB connection successful")
	}

	// Step 2: Create a test user
	testEmail := fmt.Sprintf("test_%s@gmail.com", generateRandomString(8))
	testPassword := "Test" + generateRandomString(10) + "123!"
	a.Logger.Printf("Creating test user with email: %s", maskEmail(testEmail))

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
		Data: map[string]interface{}{
			"RedirectTo": a.BaseAuthURL + "/auth/v1/callback",
		},
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

// HandleAuthPage renders the authentication page
func (a *AuthService) HandleAuthPage(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	clientIP := getClientIP(r)

	a.Logger.Printf("Auth page request from %s: %s", clientIP, path)

	// Initialize base page variables
	pageVars := genPageNav("Authentication", "")
	pageVars.ShowForm = true // Both login and signup show forms
	pageVars.ErrorMessage = r.FormValue("errmsg")

	// Check if the request is for login or signup
	if strings.HasSuffix(path, "/signup") {
		pageVars.Title = "Sign Up - MTGBAN"
		pageVars.PageType = "signup"
		pageVars.FormTitle = "Create Your Account"
		pageVars.FormInstructions = "Fill in the form below to create your account."
		pageVars.FormAction = "/signup-submit"
		pageVars.FormContent = `
            <div class="form-group">
                <label for="email">Email:</label>
                <input type="email" id="email" name="email" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <div class="form-group">
                <label for="confirm-password">Confirm Password:</label>
                <input type="password" id="confirm-password" name="confirm-password" required>
            </div>
            <div class="form-group">
                <label for="fullname">Full Name:</label>
                <input type="text" id="fullname" name="fullname" required>
            </div>
            <div class="form-group">
                <input type="checkbox" id="terms" name="terms">
                <label for="terms">I accept the Terms of Service</label>
            </div>
        `
		pageVars.SubmitButtonText = "Sign Up"
		pageVars.FormLinks = `<a href="/login">Already have an account? Log in</a>`

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
		// Login page configuration
		pageVars.Title = "Login - MTGBAN"
		pageVars.PageType = "login"
		pageVars.FormTitle = "Log In to Your Account"
		pageVars.FormInstructions = "Enter your credentials to access your account."
		pageVars.FormAction = "/login-submit"
		pageVars.FormContent = `
            <div class="form-group">
                <label for="email">Email:</label>
                <input type="email" id="email" name="email" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <div class="form-group remember-me">
                <input type="checkbox" id="remember" name="remember">
                <label for="remember">Remember me</label>
            </div>
        `
		pageVars.SubmitButtonText = "Log In"
		pageVars.FormLinks = `
            <a href="/forgot-password">Forgot password?</a>
            <a href="/signup">Don't have an account? Sign up</a>
        `

		switch pageVars.ErrorMessage {
		case "invalid":
			pageVars.ErrorMessage = "Invalid email or password."
			a.Logger.Printf("Login error shown to %s: invalid credentials", clientIP)
		case "empty":
			pageVars.ErrorMessage = "Please enter both email and password."
			a.Logger.Printf("Login error shown to %s: empty fields", clientIP)
		}
	}

	// Pass return_to parameter if present
	if returnTo := r.FormValue("return_to"); returnTo != "" {
		if pageVars.FormAction == "/login-submit" {
			pageVars.FormContent += `<input type="hidden" name="return_to" value="` + returnTo + `">`
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
	ctx := context.Background()

	// Use the Supabase client to authenticate with email/password
	startTime := time.Now()
	authResponse, err := a.Supabase.Auth.SignIn(ctx, supabase.UserCredentials{
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
	userData, err := a.JWT.GetUserData(jwtToken)
	if err != nil {
		a.Logger.Printf("Failed to get user data for %s: %v", maskedEmail, err)
		http.Redirect(w, r, "/login?errmsg=invalid", http.StatusSeeOther)
		return
	}

	// Get user tier from token or set default
	tierTitle, err := a.JWT.GetUserTier(jwtToken)
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
	if !isPasswordStrong(password) {
		a.Logger.Printf("Signup validation failed for %s from %s: password not strong enough", maskedEmail, clientIP)
		http.Redirect(w, r, "/signup?errmsg=weak_password", http.StatusSeeOther)
		return
	}

	// Create user metadata
	userMetadata := map[string]interface{}{
		"full_name": fullName,
	}

	a.Logger.Printf("Creating user with email: %s, password length: %d, metadata: %+v",
		maskedEmail, len(password), userMetadata)

	// Create user with Supabase
	ctx := context.Background()
	startTime := time.Now()
	user, err := a.Supabase.Auth.SignUp(ctx, supabase.UserCredentials{
		Email:    email,
		Password: password,
		Data:     userMetadata,
	})
	signupDuration := time.Since(startTime)

	if err != nil {
		a.Logger.Printf("Signup failed for %s from %s: %v (took %v)",
			maskedEmail, clientIP, err, signupDuration)

		// Handle common errors
		errMsg := err.Error()
		if strings.Contains(strings.ToLower(errMsg), "already") ||
			strings.Contains(strings.ToLower(errMsg), "taken") {
			http.Redirect(w, r, "/signup?errmsg=email_taken", http.StatusSeeOther)
		} else if strings.Contains(strings.ToLower(errMsg), "database") {
			http.Redirect(w, r, "/signup?errmsg=database_error", http.StatusSeeOther)
		} else {
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
		authResponse, err := a.Supabase.Auth.SignIn(ctx, supabase.UserCredentials{
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
			userData, err := a.JWT.GetUserData(jwtToken)
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
	clientIP := getClientIP(r)
	a.Logger.Printf("Forgot password page request from %s", clientIP)

	pageVars := genPageNav("Forgot Password - MTGBAN", "")
	pageVars.ShowForm = true
	pageVars.FormTitle = "Reset Your Password"
	pageVars.FormInstructions = "Enter your email address and we'll send you instructions to reset your password."
	pageVars.FormAction = "/forgot-password-submit"
	pageVars.FormContent = `
		<div class="form-group">
			<label for="email">Email:</label>
			<input type="email" id="email" name="email" required>
		</div>
	`
	pageVars.SubmitButtonText = "Send Reset Instructions"
	pageVars.FormLinks = `<a href="/login">Back to login</a>`

	// Process error messages
	errmsg := r.FormValue("errmsg")
	switch errmsg {
	case "empty_email":
		pageVars.ErrorMessage = "Please enter your email address."
		a.Logger.Printf("Forgot password error shown to %s: empty email", clientIP)
	case "failed":
		pageVars.ErrorMessage = "Failed to process your request. Please try again later."
		a.Logger.Printf("Forgot password error shown to %s: request failed", clientIP)
	}

	a.Logger.Printf("Rendering forgot password page for %s with error: %s", clientIP, errmsg)
	render(w, "auth.html", pageVars)
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

	// Request password recovery
	ctx := context.Background()
	startTime := time.Now()
	err := a.Supabase.Auth.ResetPasswordForEmail(ctx, email, "/reset-password-sent")
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
	clientIP := getClientIP(r)
	a.Logger.Printf("Reset password confirmation page request from %s", clientIP)

	pageVars := genPageNav("Reset Password - MTGBAN", "")
	pageVars.ShowForm = false
	pageVars.MessageTitle = "Check Your Email"
	pageVars.MessageIconClass = "success"
	pageVars.PrimaryMessage = "If an account exists with that email, we've sent password reset instructions."
	pageVars.SecondaryMessage = "Please check your inbox and follow the instructions to reset your password. The link will expire in 24 hours."
	pageVars.SmallMessage = "Didn't receive an email? Check your spam folder or <a href=\"/forgot-password\">try again</a>."
	pageVars.ActionLink = "/login"
	pageVars.ActionText = "Return to Login"

	a.Logger.Printf("Rendering reset password sent page for %s", clientIP)
	render(w, "auth.html", pageVars)
}

// HandleSignupSuccess renders the signup success page
func (a *AuthService) HandleSignupSuccess(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	a.Logger.Printf("Signup success page request from %s", clientIP)

	pageVars := genPageNav("Registration Successful - MTGBAN", "")
	pageVars.ShowForm = false
	pageVars.MessageTitle = "Registration Successful!"
	pageVars.MessageIconClass = "success"
	pageVars.PrimaryMessage = "Your account has been created. Please check your email to verify your account."
	pageVars.SecondaryMessage = "We've sent a confirmation link to your email address. Please click the link to activate your account and gain full access to MTGBAN."
	pageVars.SmallMessage = "Didn't receive an email? Check your spam folder or contact our support team."
	pageVars.ActionLink = "/login"
	pageVars.ActionText = "Go to Login"

	a.Logger.Printf("Rendering signup success page for %s", clientIP)
	render(w, "auth.html", pageVars)
}

// HandleLogout handles logging out by clearing cookies
func (a *AuthService) HandleLogout(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	a.Logger.Printf("Logout request from %s", clientIP)

	// Clear all auth cookies
	http.SetCookie(w, &http.Cookie{
		Name:     "MTGBAN",
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
	client := &http.Client{Timeout: 10 * time.Second}
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
		body, _ := io.ReadAll(resp.Body)
		a.Logger.Printf("Token refresh failed from %s with status %d: %s (took %v)",
			clientIP, resp.StatusCode, string(body), refreshDuration)
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
	userData, err := a.JWT.GetUserData(accessToken)
	if err != nil {
		a.Logger.Printf("Failed to extract user data from refreshed token for %s: %v", clientIP, err)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	a.Logger.Printf("User data extracted from refreshed token for %s", clientIP)

	tierTitle, err := a.JWT.GetUserTier(accessToken)
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
	originalURL := r.URL.Query().Get("redirect_to")
	if originalURL == "" {
		originalURL = "/home"
	}
	a.Logger.Printf("Redirecting %s to %s after token refresh", clientIP, originalURL)
	http.Redirect(w, r, originalURL, http.StatusSeeOther)
}

// HandleCallback handles the OAuth callback after user authenticates with Supabase
func (a *AuthService) HandleCallback(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	a.Logger.Printf("Auth callback request from %s", clientIP)

	baseURL := getBaseURL(r)
	code := r.FormValue("code")
	if code == "" {
		a.Logger.Printf("No auth code found in callback from %s", clientIP)
		http.Redirect(w, r, baseURL, http.StatusFound)
		return
	}

	// Exchange code for token
	a.Logger.Printf("Exchanging auth code for token from %s", clientIP)
	startTime := time.Now()
	jwt, err := getUserToken(code, baseURL, r.FormValue("state"))
	tokenDuration := time.Since(startTime)

	if err != nil {
		a.Logger.Printf("Failed to get user token from %s: %v (took %v)",
			clientIP, err, tokenDuration)
		http.Redirect(w, r, baseURL+"?errmsg=TokenNotFound", http.StatusFound)
		return
	}
	a.Logger.Printf("Successfully exchanged auth code for token from %s (took %v)",
		clientIP, tokenDuration)

	// Get user data from token
	userData, err := a.JWT.GetUserData(jwt)
	if err != nil {
		a.Logger.Printf("Failed to get user data from token for %s: %v", clientIP, err)
		http.Redirect(w, r, baseURL+"?errmsg=UserNotFound", http.StatusFound)
		return
	}

	maskedEmail := maskEmail(userData.Email)
	a.Logger.Printf("Got user data for %s: %s", clientIP, maskedEmail)

	// Get user tier from token
	tierTitle, err := a.JWT.GetUserTier(jwt)
	if err != nil {
		a.Logger.Printf("Failed to get user tier from token for %s: %v", clientIP, err)
		tierTitle = "free" // Default to free tier
	}
	a.Logger.Printf("User tier for %s: %s", maskedEmail, tierTitle)

	// Sign our base URL with our tier and other data
	sig := sign(baseURL, tierTitle, userData)

	// Set cookies
	putSignatureInCookies(w, r, sig)
	a.Logger.Printf("Set signature cookie for %s", maskedEmail)

	// Redirect to the URL indicated in this query param, or go to homepage
	redir := r.FormValue("state")
	if redir == "" {
		redir = getBaseURL(r)
	}

	a.Logger.Printf("Redirecting %s to %s after successful authentication", maskedEmail, redir)
	http.Redirect(w, r, redir, http.StatusFound)
}

// WrapAuthMiddleware wraps a handler with authentication middleware
func (a *AuthService) WrapAuthMiddleware(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		path := r.URL.Path

		a.Logger.Printf("Auth check for %s accessing %s", clientIP, path)

		// Check if user is authenticated
		_, err := r.Cookie("MTGBAN")
		if err != nil {
			a.Logger.Printf("No signature cookie found for %s accessing %s", clientIP, path)

			// Try to refresh token if signature is missing but refresh token exists
			refreshCookie, refreshErr := r.Cookie("refresh_token")
			if refreshErr == nil {
				refreshTokenLength := len(refreshCookie.Value)
				a.Logger.Printf("Found refresh token for %s (length=%d), attempting refresh",
					clientIP, refreshTokenLength)

				// Add the current URL as a redirect target after refresh
				q := r.URL.Query()
				q.Set("redirect_to", r.URL.Path)
				refreshURL := "/refresh-token?" + q.Encode()

				http.Redirect(w, r, refreshURL, http.StatusSeeOther)
				return
			}

			a.Logger.Printf("No refresh token found for %s, redirecting to login", clientIP)

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

// NoSigning is a middleware that does not enforce any signing
func NoSigning(next http.Handler) http.Handler {
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

// EnforceAPISigning is a middleware that enforces API signing
func (a *AuthService) EnforceAPISigning(next http.Handler) http.Handler {
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
			a.Logger.Printf("API error, invalid signature: %v", err)
			w.Write([]byte(`{"error": "invalid signature"}`))
			return
		}

		v, err := url.ParseQuery(string(raw))
		if SigCheck && err != nil {
			a.Logger.Printf("API error, invalid base64: %v", err)
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
				a.Logger.Printf("API error, invalid expires: %v", err)
				w.Write([]byte(`{"error": "invalid or expired signature"}`))
				return
			}
			q.Set("Expires", exp)
		}

		data := fmt.Sprintf("%s%s%s%s", r.Method, exp, getBaseURL(r), q.Encode())
		valid := signHMACSHA256Base64([]byte(secret), []byte(data))

		if SigCheck && (valid != sig || (exp != "" && (expires < time.Now().Unix()))) {
			a.Logger.Printf("API error, invalid signature or expired")
			w.Write([]byte(`{"error": "invalid or expired signature"}`))
			return
		}

		gziphandler.GzipHandler(next).ServeHTTP(w, r)
	})
}

// EnforceSigning is a middleware that enforces signing
func EnforceSigning(next http.Handler) http.Handler {
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
		valid := signHMACSHA256Base64([]byte(os.Getenv("BAN_SECRET")), []byte(data))
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

// Generate a random string for unique test emails
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := range result {
		result[i] = charset[r.Intn(len(charset))]
	}

	return string(result)
}

// getUserToken exchanges the authorization code for a JWT token
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

// signHMACSHA256Base64 signs the data with the key using HMAC SHA256 and returns the base64 encoded string
func signHMACSHA256Base64(key []byte, data []byte) string {
	h := hmac.New(sha256.New, key)
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
		Name:     "MTGBAN",
		Domain:   domain,
		Path:     "/",
		Expires:  endOfThisMonth,
		Value:    sig,
		HttpOnly: true,                    // Added for security
		Secure:   r.TLS != nil,            // Secure if using HTTPS
		SameSite: http.SameSiteStrictMode, // Added for security
	}

	http.SetCookie(w, &cookie)
}

// getValuesForTier is used to generate the query parameters for signing
func getValuesForTier(tierTitle string) url.Values {
	v := url.Values{}

	featuresForTier, found := Config.ACL.Tiers[tierTitle]
	if !found {
		return v
	}

	for _, page := range OrderNav {
		pageEnabled := contains(featuresForTier, page)
		if !pageEnabled {
			continue
		}

		v.Set(page, "true")

		if featureOptions, ok := Config.ACL.Features[page]; ok {
			options, ok := featureOptions.(map[string]interface{})
			if !ok {
				continue
			}

			for _, key := range OptionalFields {
				if val, found := options[key]; found {
					strVal := fmt.Sprint(val)
					v.Set(key, strVal)
				}
			}
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
	sig := signHMACSHA256Base64([]byte(key), []byte(data))

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

// isPasswordStrong checks if a password is strong enough
func isPasswordStrong(password string) bool {
	if len(password) < 8 {
		return false
	}

	hasLetter := false
	hasDigit := false
	hasSpecial := false

	for _, c := range password {
		switch {
		case unicode.IsLetter(c):
			hasLetter = true
		case unicode.IsDigit(c):
			hasDigit = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			hasSpecial = true
		}
	}

	return (hasLetter && hasDigit) || (hasLetter && hasSpecial) || (hasDigit && hasSpecial)
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

		// Log the error
		log.Printf("PANIC: %s\nStack trace: %s\nRequest: %s",
			msg, string(buf), r.URL.String())

		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// contains checks if a string slice contains a specific string
func contains(slice []string, str string) bool {
	for _, item := range slice {
		if item == str {
			return true
		}
	}
	return false
}
