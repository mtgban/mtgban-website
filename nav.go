package main

import (
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
)

type NavIdx struct {
	i        map[string]int
	j        map[string]int
	k        map[string]int
	NavArray [][]NavElem
	Lookup   func(role string, tier string, dev bool) int
}

var navIdx NavIdx
var navBuildMutex sync.RWMutex

func buildNavbars() {
	// Check if ACL is properly initialized
	if Config.ACL.Roles == nil || Config.ACL.Tiers == nil {
		log.Println("[ERROR] Config.ACL or its Role/Tier maps are nil. Cannot perform navigation precomputation.")
		return
	}

	// Initialize the role and tier indices with the empty string at index 0
	navIdx.i = map[string]int{"": 0}
	navIdx.j = map[string]int{"": 0}

	// Add all other roles and tiers with incrementing indices
	roleIdx := 1
	for role := range Config.ACL.Roles {
		navIdx.i[role] = roleIdx
		roleIdx++
		if DebugMode {
			log.Printf("[DEBUG] Indexed Role: %s -> %d", role, roleIdx-1)
		}
	}

	tierIdx := 1
	for tier := range Config.ACL.Tiers {
		navIdx.j[tier] = tierIdx
		tierIdx++
		if DebugMode {
			log.Printf("[DEBUG] Indexed Tier: %s -> %d", tier, tierIdx-1)
		}
	}

	// Define the lookup function for converting role, tier, and dev state to an array index
	navIdx.Lookup = func(role string, tier string, dev bool) int {
		roleIdx, exists := navIdx.i[role]
		if !exists {
			log.Printf("[ERROR] Role '%s' not found in ACL roles", role)
			roleIdx = 0
		}

		tierIdx, exists := navIdx.j[tier]
		if !exists {
			log.Printf("[ERROR] Tier '%s' not found in ACL tiers", tier)
			tierIdx = 0
		}

		devIdx := 0
		if dev {
			devIdx = 1
		}

		tierCount := len(navIdx.j)
		devStates := 2

		return roleIdx*(tierCount*devStates) + tierIdx*devStates + devIdx
	}

	// Create the array to hold all possible navbars
	navIdx.NavArray = make([][]NavElem, len(navIdx.i)*len(navIdx.j)*2)

	if DebugMode {
		log.Printf("[DEBUG] Precomputing all possible navigation states...")
		log.Printf("[DEBUG] Combinations: Roles (%d) * Tiers (%d) * DevMode (2) = %d",
			len(navIdx.i), len(navIdx.j), len(navIdx.i)*len(navIdx.j)*2)
	}

	// Acquire write lock
	navBuildMutex.Lock()
	defer navBuildMutex.Unlock()

	// Precompute all combinations
	for role, _ := range navIdx.i {
		for tier, _ := range navIdx.j {
			for _, devState := range []bool{false, true} {
				idx := navIdx.Lookup(role, tier, devState)

				permissions := make(map[string]any)

				err := setPermissions(role, tier, &permissions)
				if err != nil {
					log.Printf("[ERROR] Error setting permissions for role '%s', tier '%s': %v", role, tier, err)
					continue
				}

				// Build dummy session
				userId := fmt.Sprintf("%s_%s", role, tier)
				email := fmt.Sprintf("nav_%s@mtgban.com", userId)
				dummySession := &UserSession{
					UserId:      userId,
					Tokens:      nil,
					User:        &UserData{UserId: userId, Email: email, Role: role, Tier: tier},
					Permissions: permissions,
					Metadata:    nil,
					CreatedAt:   time.Now(),
				}

				// Build nav for that state
				builtNav := buildNav(dummySession, devState)

				// Store directly in the indexed array
				navIdx.NavArray[idx] = builtNav

				if DebugMode {
					cacheKey := fmt.Sprintf("role:%s|tier:%s|dev:%t", role, tier, devState)
					log.Printf("[DEBUG] Precomputed key: '%s' -> %d nav items", cacheKey, len(builtNav))
				}
			}
		}
	}
	log.Printf("[INFO] Navigation states precomputed")
}

// buildNav constructs the base navigation list based on user session permissions
func buildNav(userSession *UserSession, isDevMode bool) []NavElem {
	var baseNav []NavElem

	// Initialize navigation with defaults
	if DefaultNav != nil {
		baseNav = make([]NavElem, len(DefaultNav))
		copy(baseNav, DefaultNav)
	} else {
		baseNav = []NavElem{}
	}

	// Add navigation items based on ACL permissions and configuration
	if OrderNav != nil && ExtraNavs != nil {
		for _, feat := range OrderNav {
			navItem, exists := ExtraNavs[feat]
			// Skip if the feature isn't defined in ExtraNavs
			if !exists || navItem == nil {
				continue
			}
			showNavItem := false

			// Reason 1: No authentication required
			if navItem.NoAuth {
				showNavItem = true
			} else if userSession != nil {
				// Reason 2: User has a session and permissions allow it
				if userSession.Permissions != nil {
					// Check if the top-level feature key exists in the permissions map
					_, hasPerm := userSession.Permissions[feat]
					if hasPerm {
						showNavItem = true
					} else if isDevMode && (navItem.AlwaysOnForDev || !SigCheck) {
						// Reason 3: DevMode override applies
						showNavItem = true
					}
				} else if isDevMode && (navItem.AlwaysOnForDev || !SigCheck) {
					// Reason 4: permissions are nil, but DevMode override applies
					showNavItem = true
				}
			} else if isDevMode && navItem.AlwaysOnForDev && navItem.NoAuth == false {
				// Handle edge case: No session, but DevMode override applies for an auth-required item
				showNavItem = true
			}
			// Add the item to the final list if it should be shown
			if showNavItem {
				// Copy the NavElem to avoid modifying the original ExtraNavs entry later
				displayNavItem := *navItem
				baseNav = append(baseNav, displayNavItem)
			}
		}
	} else {
		// Log if essential configs are missing only if DebugMode is true
		if DebugMode {
			if OrderNav == nil {
				log.Printf("[DEBUG] buildNav: OrderNav is nil, skipping ACL-based navigation additions.")
			}
			if ExtraNavs == nil {
				log.Printf("[DEBUG] buildNav: ExtraNavs is nil, skipping ACL-based navigation additions.")
			}
		}
	}
	if DebugMode {
		log.Printf("[DEBUG] buildNav: %v", baseNav)
	}
	return baseNav
}

func genPageNav(activeTab string, r *http.Request) PageVars {
	if DebugMode {
		log.Printf("[DEBUG] genPageNav called for activeTab: '%s', URL: '%s'", activeTab, r.URL.Path)
	}

	// Initialize page variables
	pageVars := PageVars{
		Title:        "BAN " + activeTab,
		LastUpdate:   LastUpdate,
		Hash:         BuildCommit,
		ShowLogin:    true,
		IsLoggedIn:   false,
		ErrorMessage: "",
	}

	// Set game-specific properties
	if Config.Game != "" {
		pageVars.Title += " - " + Config.Game
		pageVars.DisableChart = true
	}
	switch Config.Game {
	case mtgban.GameMagic:
		pageVars.CardBackURL = "https://cards.scryfall.io/back.png"
	case mtgban.GameLorcana:
		pageVars.CardBackURL = "img/backs/lorcana.webp"
	default:
		pageVars.CardBackURL = "img/backs/default.png"
	}

	// Default user values
	userTier := "free"
	userRole := "user"
	userEmail := ""

	// Get user info from session if available
	var session *UserSession
	sessionData := r.Context().Value(userContextKey)
	if sessionData != nil {
		var ok bool
		session, ok = sessionData.(*UserSession)
		if ok && session != nil {
			pageVars.IsLoggedIn = true
			if session.User != nil {
				userEmail = session.User.Email
				userTier = session.User.Tier
				userRole = session.User.Role
			} else {
				log.Printf("[WARNING] User session found but User is nil")
			}
			pageVars.ShowLogin = false
			if DebugMode {
				log.Printf("[DEBUG] genPageNav: User session loaded from context: Email: %s, Role: %s, Tier: %s", maskEmail(userEmail), userRole, userTier)
			}
		} else if DebugMode {
			log.Printf("[DEBUG] genPageNav: No user session found in context. Assuming anonymous (Role: '%s', Tier: '%s').", userRole, userTier)
		}
	}

	// Update PageVars with user info
	pageVars.UserEmail = userEmail
	pageVars.UserTier = userTier
	pageVars.UserRole = userRole

	if DebugMode {
		log.Printf("[DEBUG] genPageNav: Looking up nav for role: %s, tier: %s, dev: %t", userRole, userTier, DevMode)
	}

	// Get the nav from index, JS will handle active state
	pageVars.Nav = getNav(userRole, userTier, DevMode)

	if DebugMode {
		log.Printf("[DEBUG] genPageNav finished. Returning PageVars with %d nav items.", len(pageVars.Nav))
	}
	return pageVars
}

func getNav(role string, tier string, dev bool) []NavElem {
	idx := navIdx.Lookup(role, tier, dev)
	// check if index is out of bounds
	if idx < 0 || idx >= len(navIdx.NavArray) {
		if DebugMode {
			log.Printf("[ERROR] getNav: Calculated index %d out of bounds for NavArray (size %d) for role='%s', tier='%s', dev=%t", idx, len(navIdx.NavArray), role, tier, dev)
		}
		// Return a default/empty nav
		defaultIdx := navIdx.Lookup("", "", false)
		if defaultIdx >= 0 && defaultIdx < len(navIdx.NavArray) && navIdx.NavArray[defaultIdx] != nil {
			return navIdx.NavArray[defaultIdx]
		}
		if DebugMode {
			log.Printf("[ERROR] getNav: No default nav found, returning empty nav.")
		}
		return []NavElem{} // Absolute fallback
	}

	nav := navIdx.NavArray[idx]
	if nav == nil {
		if DebugMode {
			log.Printf("[ERROR] getNav: Precomputed nav is nil for index %d (role='%s', tier='%s', dev=%t). Returning empty nav.", idx, role, tier, dev)
		}
		return []NavElem{}
	}
	return nav
}
