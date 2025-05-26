package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"

	"slices"

	"github.com/NYTimes/gziphandler"
)

var AuthHost string

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

type UserData struct {
	ID       string
	Email    string
	FullName string
}

type AuthResult struct {
	UserID      string
	Permissions map[string]map[string]any
	Signature   string
	Token       string
	APIKey      string
	Error       error
}

func extractClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Decode JWT payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	// Parse JSON payload
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}

	return claims, nil
}

func getTokenFromRequest(r *http.Request) (string, error) {
	// Try Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			return parts[1], nil
		}
	}

	// Try cookie
	cookie, err := r.Cookie("auth-token")
	if err == nil {
		return cookie.Value, nil
	}

	return "", fmt.Errorf("no auth token found")
}

func getRefreshTokenFromRequest(r *http.Request) (string, error) {
	cookie, err := r.Cookie("refresh-token")
	if err == nil {
		return cookie.Value, nil
	}

	return "", fmt.Errorf("no refresh token found")
}

func refreshAuthToken(ctx context.Context, token, refreshToken string) (string, error) {
	client := getSupabaseClient()
	if client == nil {
		return "", fmt.Errorf("Supabase client not initialized")
	}

	result, err := client.Auth.RefreshUser(ctx, token, refreshToken)
	if err != nil {
		return "", err
	}

	return result.AccessToken, nil
}

func Authenticate(ctx context.Context, r *http.Request) AuthResult {
	result := AuthResult{}

	if DevMode {
		log.Printf("[DEBUG] Starting authentication for request to %s", r.URL.Path)
	}

	if AuthHost == "" {
		AuthHost = getBaseURL(r)
		if DevMode {
			log.Printf("[DEBUG] Setting AuthHost to %s", AuthHost)
		}
	}

	token, err := getTokenFromRequest(r)
	if err != nil {
		if DevMode {
			log.Printf("[DEBUG] Token extraction failed: %v", err)
		}
		result.Error = fmt.Errorf("authentication required: %v", err)
		return result
	}

	if DevMode {
		log.Printf("[DEBUG] Successfully extracted token (first 10 chars): %s...", token[:min(10, len(token))])
	}

	claims, err := extractClaims(token)
	if err != nil {
		if DevMode {
			log.Printf("[DEBUG] Failed to extract claims: %v", err)
		}
		result.Error = fmt.Errorf("invalid token format: %v", err)
		return result
	}

	if DevMode {
		log.Printf("[DEBUG] Successfully extracted claims for subject: %v", claims["sub"])
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		if DevMode {
			log.Printf("[DEBUG] No expiration claim found in token")
		}
		result.Error = fmt.Errorf("invalid token format: no expiration")
		return result
	}

	expTime := time.Unix(int64(exp), 0)
	if time.Now().After(expTime) {
		if DevMode {
			log.Printf("[DEBUG] Token expired at %v, attempting refresh", expTime)
		}

		refreshToken, _ := getRefreshTokenFromRequest(r)
		if refreshToken != "" {
			if DevMode {
				log.Printf("[DEBUG] Found refresh token, attempting to refresh")
			}

			newToken, err := refreshAuthToken(ctx, token, refreshToken)
			if err == nil {
				if DevMode {
					log.Printf("[DEBUG] Successfully refreshed token")
				}
				token = newToken
				claims, err = extractClaims(token)
				if err != nil {
					if DevMode {
						log.Printf("[DEBUG] Failed to extract claims from refreshed token: %v", err)
					}
					result.Error = fmt.Errorf("token expired: %v", err)
					return result
				}
			} else {
				if DevMode {
					log.Printf("[DEBUG] Failed to refresh token: %v", err)
				}
				result.Error = fmt.Errorf("token expired: %v", err)
				return result
			}
		} else {
			if DevMode {
				log.Printf("[DEBUG] No refresh token found, authentication failed")
			}
			result.Error = fmt.Errorf("token expired")
			return result
		}
	}

	userID, ok := claims["sub"].(string)
	if !ok || userID == "" {
		if DevMode {
			log.Printf("[DEBUG] No user ID found in claims")
		}
		result.Error = fmt.Errorf("invalid user information")
		return result
	}

	if DevMode {
		log.Printf("[DEBUG] User ID extracted: %s", userID)
	}

	sig := extractSignature(ctx, userID, claims)
	if SigCheck && sig == "" {
		if DevMode {
			log.Printf("[DEBUG] No signature found for user %s", userID)
		}
		result.Error = fmt.Errorf("no access signature found")
		return result
	}

	if DevMode && sig != "" {
		log.Printf("[DEBUG] Found signature for user %s (first 10 chars): %s...", userID, sig[:min(10, len(sig))])
	}

	permissions, err := decodeAndParseSignature(sig)
	if SigCheck && err != nil {
		if DevMode {
			log.Printf("[DEBUG] Failed to decode signature: %v", err)
		}
		result.Error = fmt.Errorf("invalid signature format: %v", err)
		return result
	}

	if DevMode {
		log.Printf("[DEBUG] Successfully decoded permissions with %d categories", len(permissions))
	}

	result.UserID = userID
	result.Permissions = permissions
	result.Signature = sig
	result.Token = token

	if DevMode {
		log.Printf("[DEBUG] Authentication successful for user %s", userID)
	}

	return result
}

func AuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer recoverPanic(r, w)

			if AuthHost == "" {
				AuthHost = getBaseURL(r) + "/auth"
			}

			emptyPermissions := map[string]map[string]any{}
			var userToken string = ""
			var userPreferences map[string]any = nil

			var activeNavItem *NavElem
			var activeNavKey string

			for key, nav := range ExtraNavs {
				if r.URL.Path == nav.Link || isSubPage(r.URL.Path, nav.SubPages) {
					activeNavItem = nav
					activeNavKey = key
					break
				}
			}

			staticPaths := []string{
				"/css/", "/img/", "/js/", "/favicon.ico",
			}
			for _, prefix := range staticPaths {
				if strings.HasPrefix(r.URL.Path, prefix) {
					next.ServeHTTP(w, r)
					return
				}
			}

			if r.URL.Path == "/auth" {
				next.ServeHTTP(w, r)
				return
			}

			isNoAuth := activeNavItem != nil && activeNavItem.NoAuth
			isDevModeRoute := DevMode && activeNavItem != nil && activeNavItem.AlwaysOnForDev

			if isNoAuth || isDevModeRoute {
				if isNoAuth {
					if DevMode {
						log.Printf("[DEBUG] NoAuth route accessed: %s (%s)", activeNavItem.Name, r.URL.Path)
					}
				} else {
					if DevMode {
						log.Printf("[DEBUG] DevMode route accessed: %s (%s)", activeNavItem.Name, r.URL.Path)
					}
				}

				ctx := r.Context()
				ctx = context.WithValue(ctx, "permissions", emptyPermissions)
				ctx = context.WithValue(ctx, "token", "")
				ctx = context.WithValue(ctx, "signature", "")
				ctx = context.WithValue(ctx, "expiry_time", int64(0))
				ctx = context.WithValue(ctx, "user_email", "")
				ctx = context.WithValue(ctx, "user_preferences", userPreferences)

				gziphandler.GzipHandler(next).ServeHTTP(w, r.WithContext(ctx))
				return
			}

			publicPaths := []string{
				"/", "/go/", "/random", "/randomsealed", "/discord",
				"/search/oembed",
			}

			for _, path := range publicPaths {
				if strings.HasPrefix(r.URL.Path, path) {
					ctx := r.Context()
					ctx = context.WithValue(ctx, "permissions", emptyPermissions)
					ctx = context.WithValue(ctx, "token", "")
					ctx = context.WithValue(ctx, "signature", "")
					ctx = context.WithValue(ctx, "expiry_time", int64(0))
					ctx = context.WithValue(ctx, "user_email", "")
					ctx = context.WithValue(ctx, "user_preferences", userPreferences)

					gziphandler.GzipHandler(next).ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			publicAPIPaths := []string{
				"/api/search/", "/api/suggest", "/api/opensearch.xml",
				"/api/cardkingdom/pricelist.json",
			}

			for _, path := range publicAPIPaths {
				if strings.HasPrefix(r.URL.Path, path) {
					w.Header().Add("Content-Type", "application/json")

					ctx := r.Context()
					ctx = context.WithValue(ctx, "permissions", emptyPermissions)
					ctx = context.WithValue(ctx, "token", "")
					ctx = context.WithValue(ctx, "signature", "")
					ctx = context.WithValue(ctx, "expiry_time", int64(0))
					ctx = context.WithValue(ctx, "user_email", "anonymous@mtgban.com")
					ctx = context.WithValue(ctx, "user_preferences", userPreferences)

					gziphandler.GzipHandler(next).ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			isAPIRequest := strings.HasPrefix(r.URL.Path, "/api/")
			if isAPIRequest {
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
			}

			authResult := Authenticate(r.Context(), r)

			if authResult.Error != nil {
				if DevMode {
					log.Printf("[DEBUG] Authentication failed: %v", authResult.Error)
				}

				if isAPIRequest {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte(fmt.Sprintf(`{"error": "%s"}`, authResult.Error.Error())))
					return
				} else {
					pageVars := genPageNavWithPermissions("Login Required", emptyPermissions, 0)
					pageVars.Title = "Authentication Required"
					pageVars.ErrorMessage = ErrMsg
					pageVars.PatreonLogin = true
					render(w, "home.html", pageVars)
					return
				}
			}

			userToken = authResult.Token
			permissions := authResult.Permissions
			signature := authResult.Signature

			var expiryTime int64 = 0
			if signature != "" {
				exp := GetParamFromSig(signature, "Expires")
				expiryTime, _ = strconv.ParseInt(exp, 10, 64)
			}

			if userToken != "" {
				prefs, err := getUserPreferences(r.Context(), userToken)
				if err == nil {
					userPreferences = prefs
				}
			}

			if r.Method != "GET" {
				var ok bool
				if activeNavItem != nil {
					ok = activeNavItem.CanPOST
				}
				if !ok {
					http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
					return
				}
			}

			if !UserRateLimiter.allow(authResult.UserID) && r.URL.Path != "/admin" {
				pageVars := genPageNavWithPermissions("Error", emptyPermissions, 0)
				pageVars.Title = "Too Many Requests"
				pageVars.ErrorMessage = ErrMsgUseAPI
				render(w, "home.html", pageVars)
				return
			}

			if activeNavItem != nil && activeNavKey != "" {
				hasAccess := checkFeatureAccess(permissions, activeNavKey)

				if DevMode && activeNavItem.AlwaysOnForDev {
					hasAccess = true
				}

				if SigCheck && !hasAccess {
					pageVars := genPageNavWithPermissions(activeNavItem.Name, emptyPermissions, 0)
					pageVars.Title = "This feature is BANned"
					pageVars.ErrorMessage = ErrMsgPlus
					render(w, activeNavItem.Page, pageVars)
					return
				}
			}

			if isAPIRequest && !checkAPIAccess(permissions) && SigCheck {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error": "API access not authorized"}`))
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, "permissions", permissions)
			ctx = context.WithValue(ctx, "token", authResult.Token)
			ctx = context.WithValue(ctx, "signature", signature)
			ctx = context.WithValue(ctx, "expiry_time", expiryTime)
			ctx = context.WithValue(ctx, "user_preferences", userPreferences)

			if claims, err := extractClaims(authResult.Token); err == nil {
				if email, ok := claims["email"].(string); ok && email != "" {
					ctx = context.WithValue(ctx, "user_email", email)
				}
			} else {
				ctx = context.WithValue(ctx, "user_email", "")
			}

			gziphandler.GzipHandler(next).ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func isSubPage(path string, subPages []string) bool {
	return slices.Contains(subPages, path)
}

func checkFeatureAccess(permissions map[string]map[string]any, featureName string) bool {
	hasAccess := false

	if navPerms, ok := permissions[featureName]; ok {
		if enabled, ok := navPerms[featureName+"Enabled"]; ok {
			if enabledStr, ok := enabled.(string); ok && (enabledStr == "true" || enabledStr == "ALL") {
				hasAccess = true
			}
		}

		if !hasAccess {
			if enabled, ok := navPerms["Enabled"]; ok {
				if enabledStr, ok := enabled.(string); ok && (enabledStr == "true" || enabledStr == "ALL") {
					hasAccess = true
				}
			}
		}
	}

	if !hasAccess && featureName != "Global" {
		if globalPerms, ok := permissions["Global"]; ok {
			if enabled, ok := globalPerms["AnyEnabled"]; ok {
				if enabledStr, ok := enabled.(string); ok && enabledStr == "true" {
					hasAccess = true
				}
			}
		}
	}
	return hasAccess
}

func checkAPIAccess(permissions map[string]map[string]any) bool {
	apiEnabled := false

	if apiPerms, ok := permissions["API"]; ok {
		if enabled, ok := apiPerms["Enabled"]; ok {
			if enabledStr, ok := enabled.(string); ok && enabledStr == "true" {
				apiEnabled = true
			}
		}
	}

	if !apiEnabled {
		if globalPerms, ok := permissions["Global"]; ok {
			if enabled, ok := globalPerms["APIEnabled"]; ok {
				if enabledStr, ok := enabled.(string); ok && enabledStr == "true" {
					apiEnabled = true
				}
			} else if enabled, ok := globalPerms["AnyEnabled"]; ok {
				if enabledStr, ok := enabled.(string); ok && enabledStr == "true" {
					apiEnabled = true
				}
			}
		}
	}

	return apiEnabled
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type PermissionChecker struct {
	permissions map[string]map[string]any
	userID      string
}

func NewPermissionChecker(perms map[string]map[string]any, userID string) *PermissionChecker {
	if DevMode {
		log.Printf("[DEBUG] Creating permission checker for user %s with %d permission categories",
			userID, len(perms))
	}

	return &PermissionChecker{
		permissions: perms,
		userID:      userID,
	}
}

func (pc *PermissionChecker) HasPermission(feature, permission string) bool {
	if DevMode {
		log.Printf("[DEBUG] Checking permission %s.%s for user %s", feature, permission, pc.userID)
	}

	if featurePerms, ok := pc.permissions[feature]; ok {
		if permVal, ok := featurePerms[permission]; ok {
			if permStr, ok := permVal.(string); ok && (permStr == "true" || permStr == "ALL") {
				if DevMode {
					log.Printf("[DEBUG] Permission %s.%s granted directly for user %s",
						feature, permission, pc.userID)
				}
				return true
			}
		}
	}

	if featurePerms, ok := pc.permissions[feature]; ok {
		if enabled, ok := featurePerms["Enabled"]; ok {
			if enabledStr, ok := enabled.(string); ok && (enabledStr == "true" || enabledStr == "ALL") {
				if DevMode {
					log.Printf("[DEBUG] Permission %s.%s granted via %s.Enabled for user %s",
						feature, permission, feature, pc.userID)
				}
				return true
			}
		}
	}

	if globalPerms, ok := pc.permissions["Global"]; ok {
		if enabled, ok := globalPerms[feature+"Enabled"]; ok {
			if enabledStr, ok := enabled.(string); ok && enabledStr == "true" {
				if DevMode {
					log.Printf("[DEBUG] Permission %s.%s granted via Global.%sEnabled for user %s",
						feature, permission, feature, pc.userID)
				}
				return true
			}
		}

		if enabled, ok := globalPerms["AnyEnabled"]; ok {
			if enabledStr, ok := enabled.(string); ok && enabledStr == "true" {
				if DevMode {
					log.Printf("[DEBUG] Permission %s.%s granted via Global.AnyEnabled for user %s",
						feature, permission, pc.userID)
				}
				return true
			}
		}
	}

	if DevMode && ExtraNavs[feature].AlwaysOnForDev {
		log.Printf("[DEBUG] Permission %s.%s granted via DevMode.AlwaysOnForDev for user %s",
			feature, permission, pc.userID)
		return true
	}

	if DevMode {
		log.Printf("[DEBUG] Permission %s.%s DENIED for user %s", feature, permission, pc.userID)
	}

	return false
}

func (pc *PermissionChecker) HasAPIAccess() bool {
	if DevMode {
		log.Printf("[DEBUG] Checking API access permission for user %s", pc.userID)
	}

	result := pc.HasPermission("API", "Enabled") ||
		pc.HasPermission("Global", "APIEnabled")

	if DevMode {
		log.Printf("[DEBUG] API access %s for user %s",
			map[bool]string{true: "GRANTED", false: "DENIED"}[result], pc.userID)
	}

	return result
}

func extractSignature(ctx context.Context, userID string, claims map[string]any) string {
	sig := ""

	if DevMode {
		log.Printf("[DEBUG] Extracting signature for user %s", userID)
	}

	if sessionCache != nil {
		if session, found := sessionCache.Get(userID); found && session.Signature != "" {
			if DevMode {
				log.Printf("[DEBUG] Found signature in session cache for user %s", userID)
			}
			return session.Signature
		}
	}

	if appMeta, ok := claims["app_metadata"].(map[string]any); ok {
		if sigValue, ok := appMeta["sig"].(string); ok && sigValue != "" {
			if DevMode {
				log.Printf("[DEBUG] Found signature in token claims for user %s", userID)
			}
			return sigValue
		}
	}

	if DevMode {
		log.Printf("[DEBUG] Signature not found in cache or claims, fetching from Supabase for user %s", userID)
	}

	client := getSupabaseClient()
	if client == nil {
		if DevMode {
			log.Printf("[DEBUG] Supabase client not initialized, cannot fetch user data for user %s", userID)
		}
		sig = ""
		return sig
	}

	userData, err := client.Auth.User(ctx, userID)
	if err != nil {
		if DevMode {
			log.Printf("[DEBUG] Failed to fetch user data from Supabase: %v", err)
		}
		if userData == nil {
			sig = ""
		}
		return sig
	}

	if DevMode {
		log.Printf("[DEBUG] No signature found for user %s", userID)
	}

	return sig
}

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

func recoverPanic(r *http.Request, w http.ResponseWriter) {
	errPanic := recover()
	if errPanic != nil {
		log.Println("panic occurred:", errPanic)

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

func handleAuthError(w http.ResponseWriter, r *http.Request, message string) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf(`{"error": "%s"}`, message)))
		return
	}

	pageVars := genPageNav("Authentication Error", "")
	pageVars.Title = "Authentication Error"
	pageVars.ErrorMessage = message
	pageVars.PatreonLogin = true
	render(w, "home.html", pageVars)
}

func Auth(w http.ResponseWriter, r *http.Request) {
	authResult := Authenticate(r.Context(), r)

	if authResult.Error != nil {
		handleAuthError(w, r, authResult.Error.Error())
		return
	}

	if DevMode {
		log.Printf("[DEBUG] Authentication successful for user %s", authResult.UserID)
	}

	ctx := r.Context()
	ctx = context.WithValue(ctx, "permissions", authResult.Permissions)
	ctx = context.WithValue(ctx, "token", authResult.Token)

	if claims, err := extractClaims(authResult.Token); err == nil {
		if email, ok := claims["email"].(string); ok && email != "" {
			ctx = context.WithValue(ctx, "user_email", email)
		}
	}

	gziphandler.GzipHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "Authentication successful"}`))
	})).ServeHTTP(w, r.WithContext(ctx))
}

func AuthPage(w http.ResponseWriter, r *http.Request) {
	pageVars := genPageNav("Authentication", "")
	pageVars.Title = "Login / Sign Up"
	render(w, "auth.html", pageVars)
}