package main

import (
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
)

var navCache = make(map[string][]NavElem)
var navCacheMutex sync.RWMutex

// precomputeNavigation precomputes and caches all possible navigation states based on user roles and tier combinations
func precomputeNavigation() {
	// Check if ACL is properly initialized
	if Config.ACL.Roles == nil || Config.ACL.Tiers == nil {
		log.Println("[ERROR] Config.ACL or its Role/Tier maps are nil. Cannot perform navigation precomputation.")
		return
	}
	// get all roles from ACL
	allRoles := []string{""}
	for role := range Config.ACL.Roles {
		if DebugMode {
			log.Printf("[DEBUG] Role: %s", role)
		}
		allRoles = append(allRoles, role)
	}
	// get all tiers from ACL
	allTiers := []string{""}
	for tier := range Config.ACL.Tiers {
		if DebugMode {
			log.Printf("[DEBUG] Tier: %s", tier)
		}
		allTiers = append(allTiers, tier)
	}
	// consider DevMode states due to `IsAlwaysOnForDev`
	isDevMode := []bool{false, true}

	if DebugMode {
		log.Printf("[DEBUG] Precomputing all possible navigation states...")
		log.Printf("[DEBUG] Combinations: Roles (%d) * Tiers (%d) * DevMode (%d) = %d",
			len(allRoles), len(allTiers), len(isDevMode),
			len(allRoles)*len(allTiers)*len(isDevMode))
	}

	// aquire write lock
	navCacheMutex.Lock()
	defer navCacheMutex.Unlock()

	// precompute all combinations
	for _, role := range allRoles {
		for _, tier := range allTiers {
			for _, devState := range isDevMode {
				// create permissions map for this combination
				permissions := make(map[string]interface{})
				// set permissions based on role and tier
				err := setPermissions(role, tier, &permissions)
				if err != nil {
					log.Printf("[ERROR] computeNavs: Error setting permissions for role '%s', tier '%s': %v", role, tier, err)
					continue
				}
				// build dummy session using derived permissions and UserData (needed for buildNav)
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
				// cache key captures the profile + DevMode state
				cacheKey := fmt.Sprintf("role:%s|tier:%s|dev:%t", role, tier, devState)
				// build nav for that state
				builtNav := buildNav(dummySession, devState)

				// Store a copy in the cache
				navToCache := make([]NavElem, len(builtNav))
				copy(navToCache, builtNav)

				navCache[cacheKey] = navToCache

				if DebugMode {
					log.Printf("[DEBUG] Precomputed key: '%s' -> %d nav items", cacheKey, len(navToCache))
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

	pageVars := PageVars{
		Title:        "BAN " + activeTab,
		LastUpdate:   LastUpdate,
		Hash:         BuildCommit,
		ShowLogin:    true,
		IsLoggedIn:   false,
		ErrorMessage: "",
	}
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

	// Declare variables with default values
	userTier := "free"
	userRole := "user"
	userEmail := ""

	// Get UserSession from context
	var session *UserSession
	sessionData := r.Context().Value(userContextKey)
	if sessionData != nil {
		var ok bool
		session, ok = sessionData.(*UserSession)
		if ok && session != nil {
			// Populate pageVars based on UserSession
			pageVars.IsLoggedIn = true
			if session.User != nil {
				// get values from session
				userEmail = session.User.Email
				userTier = session.User.Tier
				userRole = session.User.Role
			} else {
				log.Printf("[WARNING] User session found but User is nil")
			}
			// dont show login button if user is logged in
			pageVars.ShowLogin = false
			if DebugMode {
				log.Printf("[DEBUG] genPageNav: User session loaded from context: Email: %s, Role: %s, Tier: %s", maskEmail(userEmail), userRole, userTier)
			}
		} else if DebugMode {
			log.Printf("[DEBUG] genPageNav: No user session found in context. Assuming anonymous (Role: '%s', Tier: '%s').", userRole, userTier)
		}
	}

	// Update PageVars with final determined values
	pageVars.UserEmail = userEmail
	pageVars.UserTier = userTier
	pageVars.UserRole = userRole

	cacheKey := fmt.Sprintf("role:%s|tier:%s|dev:%t", userRole, userTier, DevMode)
	if DebugMode {
		log.Printf("[DEBUG] genPageNav: Cache key: %s", cacheKey)
	}
	var finalNav []NavElem

	// lookup in precomputed cache
	navCacheMutex.RLock()
	cachedNav, found := navCache[cacheKey]
	navCacheMutex.RUnlock()

	if !found {
		log.Printf("[WARNING] genPageNav: Precomputed navigation state NOT FOUND for key: '%s'. Falling back to dynamic build.", cacheKey)
		finalNav = buildNav(session, DevMode)
	} else {
		if DebugMode {
			log.Printf("[DEBUG] genPageNav: Nav cache HIT for key: '%s'. Cache size: %d", cacheKey, len(navCache))
		}
		// copy is still needed due to 'Active' and 'Class' fields
		// TODO: javascript should be able to handle this
		finalNav = make([]NavElem, len(cachedNav))
		copy(finalNav, cachedNav)
		if DebugMode {
			log.Printf("[DEBUG] genPageNav: Copied %d items from cache for key: '%s'", len(finalNav), cacheKey)
		}
	}
	pageVars.Nav = finalNav

	mainNavIndex := -1
	if DebugMode {
		log.Printf("[DEBUG] genPageNav: Marking active nav tab for URL: '%s' (activeTab: '%s')", r.URL.Path, activeTab)
	}
	for i := range pageVars.Nav {
		// Reset any potential stale state from cache/copying
		pageVars.Nav[i].Active = false
		pageVars.Nav[i].Class = ""

		if pageVars.Nav[i].Name == activeTab {
			mainNavIndex = i
			if DebugMode {
				log.Printf("[DEBUG] genPageNav: Found active tab by Name match: '%s' at index %d", activeTab, i)
			}
			// Found main tab match, break outer loop
			break
		} else {
			// Check subpages for active tab based on the current request URL
			for _, subPage := range pageVars.Nav[i].SubPages {
				if r.URL.Path == subPage {
					mainNavIndex = i
					if DebugMode {
						log.Printf("[DEBUG] genPageNav: Found active tab by SubPage match: '%s' (parent '%s') at index %d", r.URL.Path, pageVars.Nav[i].Name, i)
					}
					// Found subpage match, break inner loop
					break
				}
			}
			if mainNavIndex != -1 {
				// Found match in subpages, break outer loop
				break
			}
		}
	}

	if mainNavIndex >= 0 && mainNavIndex < len(pageVars.Nav) {
		pageVars.Nav[mainNavIndex].Active = true
		pageVars.Nav[mainNavIndex].Class = "active"
		if DebugMode {
			log.Printf("[DEBUG] genPageNav: Set active nav tab: '%s'", pageVars.Nav[mainNavIndex].Name)
		}
	} else if DebugMode {
		log.Printf("[DEBUG] genPageNav: No nav item found matching activeTab '%s' or URL '%s' to mark active.", activeTab, r.URL.Path)
	}

	if DebugMode {
		log.Printf("[DEBUG] genPageNav finished. Returning PageVars with %d nav items.", len(pageVars.Nav))
	}
	return pageVars
}
