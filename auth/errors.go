package auth

import "fmt"

// ConfigError represents configuration validation errors
type ConfigError struct {
	Code    int
	Message string
	Err     error
}

func (e *ConfigError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// NewConfigError creates a new ConfigError
func NewConfigError(message string, err error) *ConfigError {
	return &ConfigError{
		Code:    400,
		Message: message,
		Err:     err,
	}
}

// CacheError represents general cache operation errors
type CacheError struct {
	Code    int    // HTTP status code
	Message string // Human readable error message
	Err     error  // Underlying error if any
	Op      string // Operation that failed
	Details string // Additional error context
}

// Error returns a formatted error message with operation and details
func (e *CacheError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("cache %s failed: %s - %v [%s]", e.Op, e.Message, e.Err, e.Details)
	}
	return fmt.Sprintf("cache %s failed: %s [%s]", e.Op, e.Message, e.Details)
}

// NewCacheError creates a new CacheError with operation context
func NewCacheError(code int, op string, message string, details string, err error) *CacheError {
	return &CacheError{
		Code:    code,
		Message: message,
		Err:     err,
		Op:      op,
		Details: details,
	}
}

// CacheNotFoundError represents when a cache lookup fails
type CacheNotFoundError struct {
	Key     string // Cache key that was not found
	CacheID string // Identifier for which cache was queried
}

func (e *CacheNotFoundError) Error() string {
	return fmt.Sprintf("key '%s' not found in cache '%s'", e.Key, e.CacheID)
}

// KeyNotFoundError represents when a specific key lookup fails
type KeyNotFoundError struct {
	Key      string // The key that was not found
	Resource string // The resource type being looked up
	Err      error  // Original error if any
}

func (e *KeyNotFoundError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s with key '%s' not found: %v", e.Resource, e.Key, e.Err)
	}
	return fmt.Sprintf("%s with key '%s' not found", e.Resource, e.Key)
}

// NewKeyNotFoundError creates a new KeyNotFoundError
func NewKeyNotFoundError(resource string, key string, err error) *KeyNotFoundError {
	return &KeyNotFoundError{
		Key:      key,
		Resource: resource,
		Err:      err,
	}
}

// AuthError represents authentication-related errors with detailed context
type AuthError struct {
	Code      int    // HTTP status code
	Message   string // Human readable error message
	Operation string // Operation that failed (e.g. "token validation", "role check")
	RequestID string // Request ID for tracing
	UserID    string // User ID if available
	Err       error  // Underlying error
}

// Error returns a detailed error message with context
func (e *AuthError) Error() string {
	base := fmt.Sprintf("[%d] %s failed: %s", e.Code, e.Operation, e.Message)
	if e.UserID != "" {
		base += fmt.Sprintf(" (UserID: %s)", e.UserID)
	}
	if e.RequestID != "" {
		base += fmt.Sprintf(" [RequestID: %s]", e.RequestID)
	}
	if e.Err != nil {
		base += fmt.Sprintf(" - caused by: %v", e.Err)
	}
	return base
}

// NewAuthError creates a new AuthError with full context
func NewAuthError(code int, op string, message string, reqID string, userID string, err error) *AuthError {
	return &AuthError{
		Code:      code,
		Operation: op,
		Message:   message,
		RequestID: reqID,
		UserID:    userID,
		Err:       err,
	}
}

// UnauthorizedError represents a 401 Unauthorized error with token details
type UnauthorizedError struct {
	Message   string
	TokenType string // e.g. "Bearer", "API Key"
	TokenHint string // First few chars of token for debugging
	RequestID string
	Err       error
}

// Error returns detailed token error information
func (e *UnauthorizedError) Error() string {
	msg := fmt.Sprintf("Unauthorized - %s", e.Message)
	if e.TokenType != "" {
		msg += fmt.Sprintf(" (TokenType: %s", e.TokenType)
		if e.TokenHint != "" {
			msg += fmt.Sprintf(", Hint: %s...)", e.TokenHint)
		} else {
			msg += ")"
		}
	}
	if e.RequestID != "" {
		msg += fmt.Sprintf(" [RequestID: %s]", e.RequestID)
	}
	if e.Err != nil {
		msg += fmt.Sprintf(" - %v", e.Err)
	}
	return msg
}

// NewUnauthorizedError creates a new UnauthorizedError
func NewUnauthorizedError(message string, tokenType string, tokenHint string, reqID string, err error) *UnauthorizedError {
	return &UnauthorizedError{
		Message:   message,
		TokenType: tokenType,
		TokenHint: tokenHint,
		RequestID: reqID,
		Err:       err,
	}
}

// ForbiddenError represents a 403 Forbidden error with role context
type ForbiddenError struct {
	Message      string
	UserID       string
	CurrentRole  string
	RequiredRole string
	Resource     string
	RequestID    string
	Err          error
}

// Error returns detailed access denied information
func (e *ForbiddenError) Error() string {
	msg := fmt.Sprintf("Forbidden - %s", e.Message)
	if e.UserID != "" {
		msg += fmt.Sprintf(" (UserID: %s", e.UserID)
		if e.CurrentRole != "" && e.RequiredRole != "" {
			msg += fmt.Sprintf(", Current Role: %s, Required: %s)", e.CurrentRole, e.RequiredRole)
		} else {
			msg += ")"
		}
	}
	if e.Resource != "" {
		msg += fmt.Sprintf(" - Attempted access to: %s", e.Resource)
	}
	if e.RequestID != "" {
		msg += fmt.Sprintf(" [RequestID: %s]", e.RequestID)
	}
	if e.Err != nil {
		msg += fmt.Sprintf(" - %v", e.Err)
	}
	return msg
}

// NewForbiddenError creates a ForbiddenError with role context
func NewForbiddenError(message string, userID string, currentRole string, requiredRole string, resource string, reqID string, err error) *ForbiddenError {
	return &ForbiddenError{
		Message:      message,
		UserID:       userID,
		CurrentRole:  currentRole,
		RequiredRole: requiredRole,
		Resource:     resource,
		RequestID:    reqID,
		Err:          err,
	}
}

// MissingRequiredRoleError represents a missing required role error
type MissingRequiredRoleError struct {
	Message      string
	UserID       string
	CurrentRole  string
	RequiredRole string
	RequestID    string
	Err          error
}

// Error returns detailed missing role information
func (e *MissingRequiredRoleError) Error() string {
	msg := fmt.Sprintf("Access Denied - %s", e.Message)
	if e.UserID != "" {
		msg += fmt.Sprintf(" (UserID: %s, Current Role: %s, Required: %s)",
			e.UserID, e.CurrentRole, e.RequiredRole)
	}
	if e.RequestID != "" {
		msg += fmt.Sprintf(" [RequestID: %s]", e.RequestID)
	}
	if e.Err != nil {
		msg += fmt.Sprintf(" - %v", e.Err)
	}
	return msg
}

// NewMissingRequiredRoleError creates a new MissingRequiredRoleError
func NewMissingRequiredRoleError(message string, userID string, currentRole string, requiredRole string, reqID string, err error) *MissingRequiredRoleError {
	return &MissingRequiredRoleError{
		Message:      message,
		UserID:       userID,
		CurrentRole:  currentRole,
		RequiredRole: requiredRole,
		RequestID:    reqID,
		Err:          err,
	}
}
