package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ErrSecretNotFound is an error type for when the CSRF secret is not found.
var ErrSecretNotFound = errors.New("CSRF secret not found")

// CSRF manages CSRF secrets stored in a file.
type CSRF struct {
	filePath string
	secret   string // Holds the FULL secret string (base64:timestamp)
	logger   *log.Logger
}

// NewCSRF initializes a new CSRF.
func NewCSRF(filePath string, logger *log.Logger) (*CSRF, error) {
	if logger == nil {
		log.Println("WARNING: Logger received by NewCSRF is nil! Using default logger.")
		logger = log.Default()
	}

	if filePath == "" {
		defaultPath := "csrf_secret.txt"
		logger.Printf("[INFO] CSRF SecretPath was empty in config, defaulting to '%s'.", defaultPath)
		filePath = defaultPath
	}

	csrf := &CSRF{
		filePath: filePath,
		logger:   logger,
	}

	err := csrf.loadSecret(filePath)
	if err == nil {
		csrf.logger.Printf("[DEBUG] CSRF secret loaded successfully from file '%s'.", csrf.filePath)
		return csrf, nil
	}

	if errors.Is(err, ErrSecretNotFound) || strings.Contains(err.Error(), "is empty") {
		csrf.logger.Printf("[DEBUG] CSRF secret file '%s' not found or empty, creating new.", csrf.filePath)
	} else {
		csrf.logger.Printf("[WARNING] Failed to load CSRF secret file '%s', will generate and overwrite: %v", csrf.filePath, err)
	}

	dir := filepath.Dir(csrf.filePath)
	if dir != "." && dir != "" {
		if errMkdir := os.MkdirAll(dir, 0700); errMkdir != nil {
			return nil, fmt.Errorf("failed to create directory '%s' for CSRF secret file '%s': %w", dir, csrf.filePath, errMkdir)
		}
		csrf.logger.Printf("[DEBUG] Directory '%s' ensured for CSRF secret file.", dir)
	}

	// Generate the new secret string
	newSecret, errGen := generateNewSecretString(32)
	if errGen != nil {
		return nil, fmt.Errorf("failed to generate new CSRF secret for file '%s': %w", csrf.filePath, errGen)
	}
	// Assign the generated secret to the instance
	csrf.secret = newSecret

	if errSave := csrf.saveSecret(csrf.filePath, csrf.secret); errSave != nil {
		return nil, fmt.Errorf("failed to save newly generated CSRF secret to file '%s': %w", csrf.filePath, errSave)
	}
	csrf.logger.Printf("[DEBUG] New CSRF secret generated and saved to file '%s'.", csrf.filePath)

	return csrf, nil
}

// GenerateSecret generates a new CSRF secret.
func generateNewSecretString(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("secret length must be greater than 0")
	}
	// Generate a new secret
	secretBytes := make([]byte, length)
	_, err := rand.Read(secretBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes for secret: %w", err)
	}

	timestamp := time.Now().Unix()
	encodedSecret := base64.StdEncoding.EncodeToString(secretBytes)
	combinedSecret := fmt.Sprintf("%s:%d", encodedSecret, timestamp)
	return combinedSecret, nil
}

// LoadSecret loads the CSRF secret from the file.
func (f *CSRF) loadSecret(filePath string) error {
	secretBytes, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrSecretNotFound
		}
		return fmt.Errorf("failed to read CSRF secret file '%s': %w", f.filePath, err)
	}

	secret := strings.TrimSpace(string(secretBytes))
	if secret == "" {
		return fmt.Errorf("CSRF secret file '%s' is empty", f.filePath)
	}
	f.secret = secret // Store the full secret (base64:timestamp)

	return nil
}

// saveSecret saves the CSRF secret to the file.
func (f *CSRF) saveSecret(filepath string, secret string) error {
	err := os.WriteFile(filepath, []byte(secret), 0600)
	if err != nil {
		// Added filepath to the error for clarity on write failure
		return fmt.Errorf("failed to write CSRF secret to file '%s': %w", filepath, err)
	}
	f.logger.Printf("[DEBUG] CSRF secret saved to file '%s'.", f.filePath)
	return nil
}

// RotateSecret rotates the CSRF secret periodically
func (f *CSRF) RotateSecret(interval time.Duration) {
	if f.filePath == "" {
		f.logger.Println("[ERROR] RotateSecret called but filePath is unexpectedly empty. Rotation disabled.")
		return
	}

	go func() {
		time.Sleep(5 * time.Second) // Initial delay

		f.logger.Printf("[INFO] CSRF rotation check loop started. Interval: %v", interval)

		for { // Main rotation check loop
			f.logger.Printf("[DEBUG] Rotation loop iteration starting.") // Log loop start

			fullSecret := f.secret
			if fullSecret == "" {
				f.logger.Printf("[ERROR] Instance secret (f.secret) is empty in rotation loop. Skipping check.")
				time.Sleep(interval)
				continue
			}

			parts := strings.SplitN(fullSecret, ":", 2)
			var ts int64
			var parseErr error // Renamed from err for clarity
			validFormat := len(parts) == 2
			timestampStr := "" // Store timestamp string for logging

			if validFormat {
				timestampStr = parts[1] // Get the string part
				ts, parseErr = strconv.ParseInt(timestampStr, 10, 64)
				if parseErr != nil {
					f.logger.Printf("[ERROR] Failed to parse timestamp '%s' from secret string '%s' in rotation check: %v", timestampStr, fullSecret, parseErr)
					validFormat = false
				}
			} else {
				f.logger.Printf("[ERROR] Invalid secret format (expected 'base64:timestamp') found in rotation check: '%s'", fullSecret)
			}

			rotateNow := false
			var waitTime time.Duration

			if !validFormat {
				f.logger.Printf("[WARNING] Invalid CSRF secret format or unparseable timestamp detected, rotating immediately to fix.")
				rotateNow = true
			} else {
				// Check secret age only if format and timestamp are valid
				secretTime := time.Unix(ts, 0)
				elapsed := time.Since(secretTime)
				f.logger.Printf("[DEBUG] Checking secret age: %v (Timestamp: %s, Parsed Unix: %d)", elapsed, timestampStr, ts)

				if elapsed >= interval {
					f.logger.Printf("[INFO] CSRF secret age: %v (>= interval %v), rotating now.", elapsed, interval)
					rotateNow = true
				} else {
					waitTime = interval - elapsed
					if waitTime > 1*time.Minute {
						f.logger.Printf("[INFO] CSRF secret age: %v, still fresh. Next check in approx %v.", elapsed, waitTime)
					} else {
						f.logger.Printf("[DEBUG] CSRF secret age: %v, still fresh. Next check in %v.", elapsed, waitTime)
					}
				}
			}

			if !rotateNow {
				f.logger.Printf("[DEBUG] Not rotating now, sleeping for %v.", waitTime)
				time.Sleep(waitTime)
				continue
			}

			f.logger.Printf("[INFO] Performing CSRF secret rotation...")
			newSecretString, errGen := generateNewSecretString(32)
			if errGen != nil {
				f.logger.Printf("[ERROR] Failed to generate new CSRF secret during rotation: %v", errGen)
				f.logger.Printf("[INFO] Retrying rotation after 1 hour due to generation error.")
				time.Sleep(1 * time.Hour) // Retry after a delay on generation error
				continue
			}

			// Update the instance's secret *before* saving
			f.secret = newSecretString
			f.logger.Printf("[DEBUG] Generated new secret string: %s...", newSecretString[:10])

			// Save the new secret using the instance's method
			if errSave := f.saveSecret(f.filePath, f.secret); errSave != nil {
				f.logger.Printf("[ERROR] Failed to save new CSRF secret during rotation to '%s': %v", f.filePath, errSave)
				time.Sleep(1 * time.Hour)
				continue
			}
			f.logger.Printf("[DEBUG] Successfully saved new secret to '%s'.", f.filePath)

			f.logger.Printf("[INFO] CSRF secret rotated successfully.")

			// Wait for the full interval after a successful rotation before checking again
			f.logger.Printf("[DEBUG] Rotation complete, sleeping for interval %v.", interval)
			time.Sleep(interval)
		} // End of for loop
	}()
}

// getCSRFSecretKey extracts the secret key for use in HMAC calculations.
func (c *CSRF) getCSRFSecretKey() ([]byte, error) {
	if c.secret == "" {
		// This shouldn't happen if NewCSRF succeeded, but defensive check
		c.logger.Println("[ERROR] Attempted to get CSRF secret key but secret is empty.")
		return nil, ErrCSRFSecretNotFound
	}

	parts := strings.SplitN(c.secret, ":", 2)
	if len(parts) != 2 {
		c.logger.Printf("[ERROR] Invalid internal CSRF secret format: %s", c.secret)
		return nil, fmt.Errorf("invalid internal CSRF secret format")
	}

	decodedSecret, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		c.logger.Printf("[ERROR] Failed to decode base64 secret from '%s...': %v", parts[0][:5], err) // Log partial secret
		return nil, fmt.Errorf("failed to decode base64 secret: %w", err)
	}
	return decodedSecret, nil
}

// generateCSRFToken generates a CSRF token for a user session.
func (a *AuthService) generateCSRFToken(sessionID string) (string, error) {
	key, err := a.CSRF.getCSRFSecretKey() // Call method on the CSRF instance
	if err != nil {
		return "", err
	}

	h := hmac.New(sha256.New, key)
	h.Write([]byte(sessionID))
	h.Write([]byte(time.Now().Format("2006-01-02")))
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

// validateCSRFToken validates a submitted CSRF token against the expected token.
func (a *AuthService) validateCSRFToken(submittedToken, sessionID string) (bool, error) {
	key, err := a.CSRF.getCSRFSecretKey() // Call method on the CSRF instance
	if err != nil {
		return false, err
	}

	h := hmac.New(sha256.New, key)
	h.Write([]byte(sessionID))
	h.Write([]byte(time.Now().Format("2006-01-02")))
	expectedToken := base64.StdEncoding.EncodeToString(h.Sum(nil))

	return hmac.Equal([]byte(submittedToken), []byte(expectedToken)), nil
}

// CSRFProtection middleware checks for valid CSRF tokens on non-exempt, non-GET/HEAD/OPTIONS requests
func (a *AuthService) CSRFProtection(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Fast path: skip check for exempt methods or paths
		if isExemptMethod(r.Method) || a.isExemptPath(r.URL.Path) {
			next(w, r)
			return
		}

		// Get user session from context
		userSession := getUserSessionFromContext(r)
		if userSession == nil || userSession.User == nil {
			a.logWithContext(r, "CSRFProtection: No valid user session found for non-exempt path %s %s, cannot validate CSRF.", r.Method, r.URL.Path)
			a.handleError(w, r, ErrInvalidToken)
			return
		}

		// Get CSRF token from request
		submittedToken := getCSRFToken(r)
		if submittedToken == "" {
			a.logWithContext(r, "CSRFProtection: Missing CSRF token in request for user %s on %s %s.", maskID(userSession.UserId), r.Method, r.URL.Path)
			a.handleError(w, r, ErrCSRFValidation)
			return
		}

		// Validate the token
		valid, err := a.validateCSRFToken(submittedToken, userSession.UserId)
		if err != nil {
			a.logWithContext(r, "CSRFProtection: Error validating CSRF token for user %s on %s %s: %v", maskID(userSession.UserId), r.Method, r.URL.Path, err)
			a.handleError(w, r, ErrCSRFValidation)
			return
		}
		if !valid {
			if DebugMode {
				a.logWithContext(r, "[DEBUG] CSRF Token Validation Failed for user %s on %s %s. Token mismatch.", maskID(userSession.UserId), r.Method, r.URL.Path)
			} else {
				a.logWithContext(r, "CSRF Token Validation Failed for user %s on %s %s.", maskID(userSession.UserId), r.Method, r.URL.Path)
			}
			a.handleError(w, r, ErrCSRFValidation)
			return
		}
		// Token is valid, continue
		a.logWithContext(r, "[DEBUG] CSRF token validated successfully for user %s on %s %s.", maskID(userSession.UserId), r.Method, r.URL.Path)
		next(w, r)
	}
}

// getCSRFToken extracts the CSRF token from a request
func getCSRFToken(r *http.Request) string {
	// Try header first
	token := r.Header.Get("X-CSRF-Token")
	if token != "" {
		return token
	}

	// Then try cookie
	if cookie, err := r.Cookie("csrf_token"); err == nil {
		return cookie.Value
	}

	// Fallback to form value
	return r.PostFormValue("csrf_token")
}
