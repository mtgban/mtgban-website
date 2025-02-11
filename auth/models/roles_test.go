package models

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUserData_JSON(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	tests := []struct {
		name     string
		userData UserData
		want     string
	}{
		{
			name: "Complete user data",
			userData: UserData{
				ID:         "user123",
				Role:       RoleAdmin,
				Status:     "active",
				CreatedAt:  now,
				LastSignIn: now,
			},
			want: `{"id":"user123","role":"admin","status":"active","created_at":"` + now.Format(time.RFC3339) + `","last_sign_in":"` + now.Format(time.RFC3339) + `"}`,
		},
		{
			name: "Minimal user data",
			userData: UserData{
				ID: "user456",
			},
			want: `{"id":"user456","role":"","status":"","created_at":"","last_sign_in":""}`,
		},

		{
			name: "With different role",
			userData: UserData{
				ID:   "user789",
				Role: RoleModern,
			},
			want: `{"id":"user789","role":"modern","status":"","created_at":"","last_sign_in":""}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test marshaling
			data, err := json.Marshal(tt.userData)
			assert.NoError(t, err)

			// Test unmarshaling
			var decoded UserData
			err = json.Unmarshal(data, &decoded)
			assert.NoError(t, err)

			// Verify all fields match
			assert.Equal(t, tt.userData.ID, decoded.ID)
			assert.Equal(t, tt.userData.Role, decoded.Role)
			assert.Equal(t, tt.userData.Status, decoded.Status)
			assert.Equal(t, tt.userData.CreatedAt.Unix(), decoded.CreatedAt.Unix())
			assert.Equal(t, tt.userData.LastSignIn.Unix(), decoded.LastSignIn.Unix())
		})
	}
}

func TestWebhookPayload_JSON(t *testing.T) {
	tests := []struct {
		name    string
		payload WebhookPayload
	}{
		{
			name: "Complete payload",
			payload: WebhookPayload{
				Type:  "INSERT",
				Table: "users",
				Record: map[string]interface{}{
					"id":     "user123",
					"role":   "admin",
					"status": "active",
				},
				OldRecord: map[string]interface{}{
					"id":     "user123",
					"role":   "modern",
					"status": "active",
				},
			},
		},
		{
			name: "Without old record",
			payload: WebhookPayload{
				Type:  "DELETE",
				Table: "users",
				Record: map[string]interface{}{
					"id":     "user456",
					"role":   "admin",
					"status": "active",
				},
			},
		},
		{
			name:    "Empty payload",
			payload: WebhookPayload{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test marshaling
			data, err := json.Marshal(tt.payload)
			assert.NoError(t, err)

			// Test unmarshaling
			var decoded WebhookPayload
			err = json.Unmarshal(data, &decoded)
			assert.NoError(t, err)

			// Verify fields match
			assert.Equal(t, tt.payload.Type, decoded.Type)
			assert.Equal(t, tt.payload.Table, decoded.Table)
			assert.Equal(t, tt.payload.Record, decoded.Record)
			assert.Equal(t, tt.payload.OldRecord, decoded.OldRecord)
		})
	}
}

func TestDefaultAuthConfig(t *testing.T) {
	config := DefaultAuthConfig()

	// Verify default values
	assert.Equal(t, 5*time.Second, config.ContextTimeout)
	assert.Equal(t, 5*time.Minute, config.RefreshInterval)
	assert.Empty(t, config.JWTSecret)
	assert.Empty(t, config.WebhookSecretKey)

	// Test custom values
	config.JWTSecret = []byte("secret")
	config.WebhookSecretKey = "webhook-secret"

	assert.Equal(t, []byte("secret"), config.JWTSecret)
	assert.Equal(t, "webhook-secret", config.WebhookSecretKey)
}

func TestAuthError(t *testing.T) {
	tests := []struct {
		name        string
		err         *AuthError
		expectedMsg string
	}{
		{
			name: "Error with underlying error",
			err: &AuthError{
				Code:    401,
				Message: "Unauthorized",
				Err:     fmt.Errorf("invalid token"),
			},
			expectedMsg: "Unauthorized: invalid token",
		},
		{
			name: "Error without underlying error",
			err: &AuthError{
				Code:    403,
				Message: "Forbidden",
			},
			expectedMsg: "Forbidden",
		},
		{
			name:        "Empty error",
			err:         &AuthError{},
			expectedMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedMsg, tt.err.Error())
		})
	}
}

func TestUserContextKey(t *testing.T) {
	// Test context key type safety
	key := UserContextKey
	assert.Equal(t, UserContextKey, key)

	// Test context value storage and retrieval
	ctx := context.Background()
	userData := &UserData{ID: "test-user"}

	// Store value in context
	ctx = context.WithValue(ctx, key, userData)

	// Retrieve value from context
	retrieved := ctx.Value(key)
	assert.Equal(t, userData, retrieved)

	// Test wrong key type
	wrongKey := "user"
	assert.NotEqual(t, retrieved, ctx.Value(wrongKey))
}

func TestUserData_Timestamps(t *testing.T) {
	now := time.Now().UTC()

	userData := UserData{
		ID:         "test-user",
		CreatedAt:  now,
		LastSignIn: now.Add(time.Hour),
	}

	// Verify time handling
	assert.True(t, userData.LastSignIn.After(userData.CreatedAt))

	// Test JSON roundtrip with timestamps
	data, err := json.Marshal(userData)
	assert.NoError(t, err)

	var decoded UserData
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)

	assert.Equal(t, userData.CreatedAt.Unix(), decoded.CreatedAt.Unix())
	assert.Equal(t, userData.LastSignIn.Unix(), decoded.LastSignIn.Unix())
}

func TestUserRole_String(t *testing.T) {
	tests := []struct {
		name string
		role UserRole
		want string
	}{
		{"API role", RoleApi, "api"},
		{"Test role", RoleTest, "test"},
		{"Free role", RoleFree, "free"},
		{"Pioneer role", RolePioneer, "pioneer"},
		{"Modern role", RoleModern, "modern"},
		{"Legacy role", RoleLegacy, "legacy"},
		{"Vintage role", RoleVintage, "vintage"},
		{"Admin role", RoleAdmin, "admin"},
		{"Empty role", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.role.String()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestUserRole_MarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		role    UserRole
		want    string
		wantErr bool
	}{
		{"Marshal API role", RoleApi, `"api"`, false},
		{"Marshal Test role", RoleTest, `"test"`, false},
		{"Marshal Free role", RoleFree, `"free"`, false},
		{"Marshal Pioneer role", RolePioneer, `"pioneer"`, false},
		{"Marshal Modern role", RoleModern, `"modern"`, false},
		{"Marshal Legacy role", RoleLegacy, `"legacy"`, false},
		{"Marshal Vintage role", RoleVintage, `"vintage"`, false},
		{"Marshal Admin role", RoleAdmin, `"admin"`, false},
		{"Marshal empty role", "", `""`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.role)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestUserRole_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    UserRole
		wantErr bool
	}{
		{"Unmarshal API role", `"api"`, RoleApi, false},
		{"Unmarshal Test role", `"test"`, RoleTest, false},
		{"Unmarshal Free role", `"free"`, RoleFree, false},
		{"Unmarshal Pioneer role", `"pioneer"`, RolePioneer, false},
		{"Unmarshal Modern role", `"modern"`, RoleModern, false},
		{"Unmarshal Legacy role", `"legacy"`, RoleLegacy, false},
		{"Unmarshal Vintage role", `"vintage"`, RoleVintage, false},
		{"Unmarshal Admin role", `"admin"`, RoleAdmin, false},
		{"Unmarshal empty role", `""`, "", false},
		{"Invalid JSON", `invalid`, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got UserRole
			err := json.Unmarshal([]byte(tt.json), &got)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestUserRole_IsValid(t *testing.T) {
	tests := []struct {
		name string
		role UserRole
		want bool
	}{
		{"API role valid", RoleApi, true},
		{"Test role valid", RoleTest, true},
		{"Free role valid", RoleFree, true},
		{"Pioneer role valid", RolePioneer, true},
		{"Modern role valid", RoleModern, true},
		{"Legacy role valid", RoleLegacy, true},
		{"Vintage role valid", RoleVintage, true},
		{"Admin role valid", RoleAdmin, true},
		{"Empty role invalid", "", false},
		{"Unknown role invalid", "unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.role.IsValid()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRoleHierarchy(t *testing.T) {
	tests := []struct {
		name           string
		role           UserRole
		expectedAccess []UserRole
	}{
		{
			name:           "Free role hierarchy",
			role:           RoleFree,
			expectedAccess: []UserRole{},
		},
		{
			name:           "Pioneer role hierarchy",
			role:           RolePioneer,
			expectedAccess: []UserRole{RoleFree},
		},
		{
			name:           "Modern role hierarchy",
			role:           RoleModern,
			expectedAccess: []UserRole{RoleFree, RolePioneer},
		},
		{
			name:           "Legacy role hierarchy",
			role:           RoleLegacy,
			expectedAccess: []UserRole{RoleFree, RolePioneer, RoleModern},
		},
		{
			name:           "Vintage role hierarchy",
			role:           RoleVintage,
			expectedAccess: []UserRole{RoleFree, RolePioneer, RoleModern, RoleLegacy},
		},
		{
			name:           "Admin role hierarchy",
			role:           RoleAdmin,
			expectedAccess: []UserRole{RoleFree, RolePioneer, RoleModern, RoleLegacy, RoleVintage},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			access, exists := RoleHierarchy[tt.role]
			assert.True(t, exists, "Role should exist in hierarchy")
			assert.ElementsMatch(t, tt.expectedAccess, access)

			// Verify all roles in hierarchy are valid
			for _, role := range access {
				assert.True(t, role.IsValid(), "Role in hierarchy should be valid")
			}
		})
	}

	// Test missing roles in hierarchy
	t.Run("API role not in hierarchy", func(t *testing.T) {
		_, exists := RoleHierarchy[RoleApi]
		assert.False(t, exists)
	})

	t.Run("Test role not in hierarchy", func(t *testing.T) {
		_, exists := RoleHierarchy[RoleTest]
		assert.False(t, exists)
	})
}

// Helper function to test if a role has access to another role through the hierarchy
func hasAccess(role UserRole, targetRole UserRole) bool {
	if role == targetRole {
		return true
	}

	allowedRoles, exists := RoleHierarchy[role]
	if !exists {
		return false
	}

	for _, allowed := range allowedRoles {
		if allowed == targetRole {
			return true
		}
	}
	return false
}

func TestRoleAccess(t *testing.T) {
	tests := []struct {
		name       string
		role       UserRole
		targetRole UserRole
		hasAccess  bool
	}{
		{"Admin can access Vintage", RoleAdmin, RoleVintage, true},
		{"Admin can access Legacy", RoleAdmin, RoleLegacy, true},
		{"Admin can access Modern", RoleAdmin, RoleModern, true},
		{"Admin can access Pioneer", RoleAdmin, RolePioneer, true},
		{"Admin can access Free", RoleAdmin, RoleFree, true},

		{"Vintage can access Legacy", RoleVintage, RoleLegacy, true},
		{"Vintage can access Modern", RoleVintage, RoleModern, true},
		{"Vintage can't access Admin", RoleVintage, RoleAdmin, false},

		{"Modern can access Pioneer", RoleModern, RolePioneer, true},
		{"Modern can't access Legacy", RoleModern, RoleLegacy, false},

		{"Free can't access Pioneer", RoleFree, RolePioneer, false},
		{"Free can't access Modern", RoleFree, RoleModern, false},

		{"API role has no access", RoleApi, RoleFree, false},
		{"Test role has no access", RoleTest, RoleFree, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasAccess(tt.role, tt.targetRole)
			assert.Equal(t, tt.hasAccess, got)
		})
	}
}
