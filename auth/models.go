package auth

import (
	"reflect"
	"slices"
	"strings"
	"time"
)

// Context Keys
type ContextKey string

func (k ContextKey) String() string {
	return "cache key:" + string(k)
}

const (
	UserContextKey ContextKey = "user"   // User ID
	RoleContextKey ContextKey = "role"   // Administrative Role
	TierContextKey ContextKey = "tier"   // Subscription Tier
	PageAccessKey  ContextKey = "access" // Page Access
)

type AccessType string

const (
	RoleAccess    AccessType = "role"
	TierAccess    AccessType = "tier"
	FeatureAccess AccessType = "feature"
	API           AccessType = "api"
)

//
// Role System - Administrative Permissions
//

type Role string

// Roles grant permissions without the need for a subscription.
const (
	RoleRoot      Role = "root"
	RoleAdmin     Role = "admin"
	RoleModerator Role = "moderator"
	RoleDeveloper Role = "developer"
	RoleLostBoy   Role = "lostboy"
)

// AllRoles returns a slice of all valid roles
func AllRoles() []Role {
	return []Role{
		RoleRoot,
		RoleAdmin,
		RoleModerator,
		RoleDeveloper,
		RoleLostBoy,
	}
}

// IsValid verifies the role is legit
func (r Role) IsValid() bool {
	validRoles := []Role{
		RoleRoot,
		RoleAdmin,
		RoleModerator,
		RoleDeveloper,
		RoleLostBoy,
	}
	return slices.Contains(validRoles, r)
}

// String returns string representation
func (r Role) String() string {
	return string(r)
}

// Tier System - Subscription-based Features
type Tier string

// Tiers grant permissions at the subscription level.
// A user may only have one tier at a time.
const (
	TierFree    Tier = "free"
	TierPioneer Tier = "pioneer"
	TierModern  Tier = "modern"
	TierLegacy  Tier = "legacy"
	TierVintage Tier = "vintage"
	TierAPI     Tier = "api"
)

func AllTiers() []Tier {
	tiers := make([]Tier, 0, len(TierConfig))
	for tier := range TierConfig {
		tiers = append(tiers, tier)
	}
	return tiers
}

// TierProperties defines properties for each tier
type TierProperties struct {
	Subscribed bool   // Whether this tier requires a subscription
	Hierarchy  []Tier // Lower tiers this tier has access to
}

// TierConfig defines the configuration for all tiers
var TierConfig = map[Tier]TierProperties{
	TierFree:    {Subscribed: false, Hierarchy: []Tier{}},
	TierAPI:     {Subscribed: true, Hierarchy: []Tier{}},
	TierPioneer: {Subscribed: true, Hierarchy: []Tier{TierFree}},
	TierModern:  {Subscribed: true, Hierarchy: []Tier{TierFree, TierPioneer}},
	TierLegacy:  {Subscribed: true, Hierarchy: []Tier{TierFree, TierPioneer, TierModern}},
	TierVintage: {Subscribed: true, Hierarchy: []Tier{TierFree, TierPioneer, TierModern, TierLegacy}},
}

// Mapping from product names to tiers
var productTierMap = map[string]Tier{
	"pioneer": TierPioneer,
	"modern":  TierModern,
	"legacy":  TierLegacy,
	"vintage": TierVintage,
	"api":     TierAPI,
}

// String returns the string representation of the tier
func (t Tier) String() string {
	return string(t)
}

// FromProductName converts a product name to a tier
func FromProductName(productName string) Tier {
	normalized := strings.ToLower(strings.TrimSpace(productName))
	if tier, exists := productTierMap[normalized]; exists {
		return tier
	}
	return TierFree
}

// IsValid checks if this is a valid tier
func (t Tier) IsValid() bool {
	_, exists := TierConfig[t]
	return exists || t == ""
}

//
// Features - Application Pages/Functionality
//

// Feature represents a high-level application feature (typically a page)
type Feature string

// Application features (pages/sections)
const (
	Search    Feature = "Search"
	Newspaper Feature = "Newspaper"
	Sleepers  Feature = "Sleepers"
	Upload    Feature = "Upload"
	Global    Feature = "Global"
	Arbit     Feature = "Arbit"
	Reverse   Feature = "Reverse"
	Admin     Feature = "Admin"
)

// AllFeatures returns a list of all features
func AllFeatures() []Feature {
	return []Feature{
		Search,
		Newspaper,
		Sleepers,
		Upload,
		Global,
		Arbit,
		Reverse,
		Admin,
	}
}

// IsValid checks if this is a valid feature
func (f Feature) IsValid() bool {
	return slices.Contains(AllFeatures(), f) || f == ""
}

//
// Subscription Status
//

type Status string

const (
	StatusActive    Status = "active"
	StatusInactive  Status = "inactive"
	StatusCancelled Status = "cancelled"
)

//
// Feature Flags
//

// FeatureFlags is a type alias for feature flags map
type FeatureFlags map[string]string

// Typealias for All or None
type AllOrNone string

const (
	All  AllOrNone = "ALL"
	None AllOrNone = "NONE"
)

// Typealias for News Version
type NewsVersion string

const (
	Day0 NewsVersion = "0day"
	Day1 NewsVersion = "1day"
	Day3 NewsVersion = "3day"
)

// Features represents the application features that can be enabled or disabled
type Features struct {
	// Search Features
	SearchDisabled        AllOrNone `json:"search_disabled"`         // "ALL", "NONE"
	SearchBuylistDisabled AllOrNone `json:"search_buylist_disabled"` // "ALL", "NONE"
	CanDownloadCSV        bool      `json:"can_download_csv"`
	CanFilterByPrice      bool      `json:"can_filter_by_price"`
	ShowSealedYP          bool      `json:"show_sealed_yp"`

	// Arbitrage Features
	ArbitEnabled         AllOrNone `json:"arbit_enabled"`          // "ALL", "NONE"
	ArbitDisabledVendors AllOrNone `json:"arbit_disabled_vendors"` // "ALL", "NONE"
	GlobalArbitrage      bool      `json:"global_arbitrage"`

	// Upload Features
	CanBuylist      bool `json:"can_buylist"`
	CanChangeStores bool `json:"can_change_stores"`
	HasOptimizer    bool `json:"has_optimizer"`
	NoUploadLimit   bool `json:"no_upload_limit"`

	// News Features
	NewsAccess   NewsVersion `json:"news_access"` // "0day", "1day", "3day"
	CanSwitchDay bool        `json:"can_switch_day"`

	// Premium Features
	CanFilterByPercentage bool `json:"can_filter_by_percentage"`
	HasSleepers           bool `json:"has_sleepers"`
	ExperimentsEnabled    bool `json:"experiments_enabled"`
	AnyEnabled            bool `json:"any_enabled"`
}

// UserData represents a complete user record with roles, tier, and features
type UserData struct {
	ID       string                                  `json:"id"`
	Email    string                                  `json:"email"`
	Role     *Role                                   `json:"role"`     // Administrative role (pointer to allow nil)
	Tier     Tier                                    `json:"tier"`     // Subscription tier
	Status   Status                                  `json:"status"`   // Subscription status
	Features map[string]map[string]map[string]string `json:"features"` // Feature flags
}

// hasRoleAccess checks if the user's role grants access to page/resource
func (u *UserData) hasRoleAccess(requiredRole Role) bool {
	// no role, no access
	if u.Role == nil {
		return false
	}

	// Direct match
	if *u.Role == requiredRole {
		return true
	}

	// Admin role has access to everything
	if *u.Role == RoleAdmin {
		return true
	}

	return false
}

// hasTierAccess checks if the user's tier has access to the required tier
func (u *UserData) hasTierAccess(requiredTier Tier) bool {
	// no tier, no access
	if u.Tier == "" {
		return false
	}

	// Direct match
	if u.Tier == requiredTier {
		return true
	}

	// Check tier hierarchy
	props, exists := TierConfig[u.Tier]
	if !exists {
		return false
	}
	return slices.Contains(props.Hierarchy, requiredTier)
}

// hasFeatureAccess checks if the user has access to a specific feature
func (u *UserData) hasFeatureAccess(requiredFeature Feature) (bool, map[string]map[string]string) {
	if u.Features == nil {
		return false, nil
	}
	for feature, value := range u.Features {
		if feature == string(requiredFeature) {
			return true, value
		}
	}
	return false, nil
}

// HasAccess checks if the user has access via either role, tier, or feature flags
func (u *UserData) HasAccess(accessType AccessType, required interface{}) bool {
	switch accessType {
	case RoleAccess:
		if role, ok := required.(Role); ok && role != "" {
			return u.hasRoleAccess(role)
		}
	case TierAccess:
		if tier, ok := required.(Tier); ok && tier != "" {
			return u.hasTierAccess(tier)
		}
	case FeatureAccess:
		if feature, ok := required.(Feature); ok && feature != "" {
			hasFeature, _ := u.hasFeatureAccess(feature)
			return hasFeature
		}
	}
	return false
}

// GetFeature gets a feature flag value from the user's features
func (u *UserData) GetFeature(category, feature, setting string) string {
	if u.Features == nil {
		return ""
	}

	if categoryMap, ok := u.Features[category]; ok {
		if featureMap, ok := categoryMap[feature]; ok {
			if value, ok := featureMap[setting]; ok {
				return value
			}
		}
	}

	return ""
}

//
// Configuration Types
//

// AuthConfig holds the complete authorization configuration
type AuthConfig struct {
	RoleACL      map[string][]Role                 `json:"role_acl"`
	TierACL      map[string][]Tier                 `json:"tier_acl"`
	FeatureFlags map[string]map[string]interface{} `json:"feature_flags"`
	SBase        AuthSettings                      `json:"supabase"`
}

// AuthSettings contains authentication configuration
type AuthSettings struct {
	RefreshInterval time.Duration `json:"refresh_interval"`
	SupabaseURL     string        `json:"supabase_url"`
	SupabaseKey     string        `json:"supabase_key"`
	SupabaseSecret  string        `json:"supabase_secret"`
}

// Webhook Types
type WebhookPayload struct {
	Type      string                 `json:"type"`
	Table     string                 `json:"table"`
	Record    map[string]interface{} `json:"record"`
	OldRecord map[string]interface{} `json:"old_record,omitempty"`
}

// CopyMatchingFields copies all matching fields from source to destination using reflection
func CopyMatchingFields(source, destination interface{}) {
	sourceVal := reflect.ValueOf(source)
	destVal := reflect.ValueOf(destination)

	// Ensure we're working with pointers to structs
	if sourceVal.Kind() != reflect.Ptr || destVal.Kind() != reflect.Ptr {
		return // Both must be pointers
	}

	sourceVal = sourceVal.Elem()
	destVal = destVal.Elem()

	if sourceVal.Kind() != reflect.Struct || destVal.Kind() != reflect.Struct {
		return // Both must be structs
	}

	// Iterate over the fields in the source struct
	sourceType := sourceVal.Type()
	for i := 0; i < sourceVal.NumField(); i++ {
		sourceField := sourceType.Field(i)

		// Skip unexported fields
		if sourceField.PkgPath != "" {
			continue
		}

		sourceFieldName := sourceField.Name
		sourceFieldValue := sourceVal.Field(i)

		// Look for matching field in destination struct
		destFieldValue := destVal.FieldByName(sourceFieldName)

		// Check if the field exists and can be set
		if destFieldValue.IsValid() && destFieldValue.CanSet() {
			// Handle direct type matches
			if sourceFieldValue.Type().AssignableTo(destFieldValue.Type()) {
				destFieldValue.Set(sourceFieldValue)
				continue
			}

			// Handle pointer-to-non-pointer conversions
			if destFieldValue.Kind() != reflect.Ptr &&
				sourceFieldValue.Kind() == reflect.Ptr &&
				!sourceFieldValue.IsNil() {
				sourceElem := sourceFieldValue.Elem()
				if sourceElem.Type().AssignableTo(destFieldValue.Type()) {
					destFieldValue.Set(sourceElem)
				}
				continue
			}

			// Handle non-pointer-to-pointer conversions
			if destFieldValue.Kind() == reflect.Ptr &&
				sourceFieldValue.Kind() != reflect.Ptr {
				if sourceFieldValue.Type().AssignableTo(destFieldValue.Type().Elem()) {
					// Create a new pointer of the right type
					newPtr := reflect.New(destFieldValue.Type().Elem())
					// Set its value
					newPtr.Elem().Set(sourceFieldValue)
					// Set the pointer field
					destFieldValue.Set(newPtr)
				}
				continue
			}
		}
	}
}
