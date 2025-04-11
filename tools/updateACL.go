package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	supabase "github.com/nedpals/supabase-go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Version information
const (
	Version = "1.2.0"
)

// Permission represents a single permission with a value
type Permission string

// PermissionSection represents a group of related permissions
type PermissionSection map[string]Permission

// RolePermissions represents all permission sections for a role
type RolePermissions map[string]PermissionSection

// TierPermissions represents all permission sections for a tier
type TierPermissions map[string]PermissionSection

// ACLStructured represents the complete access control list with strongly typed structures
type ACLStructured struct {
	Version string                     `json:"version"`
	Updated time.Time                  `json:"updated"`
	Tier    map[string]TierPermissions `json:"tier"`
	Role    map[string]RolePermissions `json:"role"`
}

// AuthConfig represents the complete authentication configuration
type AuthConfig struct {
	Domain            string   `json:"domain"`
	Port              string   `json:"port"`
	SecureCookies     bool     `json:"secure_cookies"`
	CookieDomain      string   `json:"cookie_domain"`
	CSRFSecret        string   `json:"csrf_secret"`
	SignatureTTL      int      `json:"signature_ttl"`
	LoginRateLimit    int      `json:"login_rate_limit"`
	SignupRateLimit   int      `json:"signup_rate_limit"`
	APIRateLimit      int      `json:"api_rate_limit"`
	PublicRateLimit   int      `json:"public_rate_limit"`
	LogPrefix         string   `json:"log_prefix"`
	SupabaseURL       string   `json:"supabase_url"`
	SupabaseJWTSecret string   `json:"supabase_jwt_secret"`
	SupabaseAnonKey   string   `json:"supabase_anon_key"`
	SupabaseRoleKey   string   `json:"supabase_role_key"`
	AssetsPath        string   `json:"assets_path"`
	ExemptRoutes      []string `json:"exempt_routes"`
	ExemptPrefixes    []string `json:"exempt_prefixes"`
	ExemptSuffixes    []string `json:"exempt_suffixes"`
	ACL               ACL      `json:"acl"`
}

// HasPermission checks if a permission section has a specific permission set
func (ps PermissionSection) HasPermission(name string) bool {
	_, exists := ps[name]
	return exists
}

// GetPermissionValue retrieves a permission value, with a default if not found
func (ps PermissionSection) GetPermissionValue(name string, defaultValue string) string {
	if val, exists := ps[name]; exists {
		return string(val)
	}
	return defaultValue
}

// GetSection retrieves a permission section by name
func (tp TierPermissions) GetSection(name string) PermissionSection {
	if section, exists := tp[name]; exists {
		return section
	}
	return PermissionSection{}
}

// CheckPermission checks if a specific permission exists in a section
func (tp TierPermissions) CheckPermission(section, permission string) bool {
	if s := tp.GetSection(section); s != nil {
		return s.HasPermission(permission)
	}
	return false
}

// MergeWith merges this permission section with another, with the other taking precedence
func (ps PermissionSection) MergeWith(other PermissionSection) PermissionSection {
	result := make(PermissionSection)

	// Copy this section's permissions
	for k, v := range ps {
		result[k] = v
	}

	// Override with other section's permissions
	for k, v := range other {
		result[k] = v
	}

	return result
}

// ACL represents the complete access control list in the format expected by the database
// Note: Field names match JSON field names in the auth config
type ACL struct {
	Roles map[string]map[string]map[string]string `json:"role"` // "role" not "roles"
	Tiers map[string]map[string]map[string]string `json:"tier"` // "tier" not "tiers"
}

// Config represents the application configuration
type Config struct {
	// Database connection details
	DB struct {
		Url    string `json:"url"`
		Key    string `json:"key"`
		Secret string `json:"jwt_secret"`
		Host   string `json:"host"`
		Port   int    `json:"port"`
		Name   string `json:"name"`
		User   string `json:"user"`
		Pass   string `json:"pass"`
	} `json:"db"`

	// Auth configuration with ACL
	Auth AuthConfig `json:"auth"`
}

// Query represents a Supabase query with named parameters
type Query struct {
	Query  string                 `json:"query"`
	Params map[string]interface{} `json:"params"`
}

// ConvertToStructured converts the database-style ACL to a strongly typed structure
func (a ACL) ConvertToStructured() ACLStructured {
	structured := ACLStructured{
		Version: Version,
		Updated: time.Now().UTC(),
		Tier:    make(map[string]TierPermissions),
		Role:    make(map[string]RolePermissions),
	}

	// Convert tiers
	for tierName, tierSections := range a.Tiers {
		structured.Tier[tierName] = make(TierPermissions)
		for sectionName, perms := range tierSections {
			structured.Tier[tierName][sectionName] = make(PermissionSection)
			for permName, permValue := range perms {
				structured.Tier[tierName][sectionName][permName] = Permission(permValue)
			}
		}
	}

	// Convert roles
	for roleName, roleSections := range a.Roles {
		structured.Role[roleName] = make(RolePermissions)
		for sectionName, perms := range roleSections {
			structured.Role[roleName][sectionName] = make(PermissionSection)
			for permName, permValue := range perms {
				structured.Role[roleName][sectionName][permName] = Permission(permValue)
			}
		}
	}

	return structured
}

// ConvertToDatabase converts the strongly typed ACL structure back to the database format
func (a ACLStructured) ConvertToDatabase() ACL {
	dbStyle := ACL{
		Tiers: make(map[string]map[string]map[string]string),
		Roles: make(map[string]map[string]map[string]string),
	}

	// Convert tiers
	for tierName, tierSections := range a.Tier {
		dbStyle.Tiers[tierName] = make(map[string]map[string]string)
		for sectionName, perms := range tierSections {
			dbStyle.Tiers[tierName][sectionName] = make(map[string]string)
			for permName, permValue := range perms {
				dbStyle.Tiers[tierName][sectionName][permName] = string(permValue)
			}
		}
	}

	// Convert roles
	for roleName, roleSections := range a.Role {
		dbStyle.Roles[roleName] = make(map[string]map[string]string)
		for sectionName, perms := range roleSections {
			dbStyle.Roles[roleName][sectionName] = make(map[string]string)
			for permName, permValue := range perms {
				dbStyle.Roles[roleName][sectionName][permName] = string(permValue)
			}
		}
	}

	return dbStyle
}

// Command line flags
type Flags struct {
	ConfigPath  string
	OutputPath  string
	UpdateDB    bool
	DryRun      bool
	Verbose     bool
	JustRoles   bool
	JustTiers   bool
	BackupFirst bool
	Timeout     int
	AuthMode    bool   // New flag to handle auth config
	AuthPath    string // Path to auth config (if separate)
	Help        bool   // Help flag
}

// JSON buffer pool for optimized JSON operations
var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

func main() {
	// Set up structured logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.With().Caller().Logger()

	// Parse command line flags
	flags := parseFlags()

	// If no flags provided or help flag set, show help
	if flag.NFlag() == 0 || flags.Help {
		showHelp()
		return
	}

	if flags.Verbose {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Debug().Msg("Debug logging enabled")
	}

	// Load configuration
	log.Info().Str("config_path", flags.ConfigPath).Msg("Loading configuration")
	config, err := loadConfig(flags.ConfigPath, flags.AuthMode, flags.AuthPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// Create context with 30 second timeout
	_, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Print what we would update in dry run mode
	if flags.DryRun {
		displayDryRunInfo(config.Auth.ACL, flags.JustRoles, flags.JustTiers)
		return
	}

	// Create Supabase client
	supabaseClient := supabase.CreateClient(
		config.Auth.SupabaseURL,
		config.Auth.SupabaseRoleKey,
	)
	if supabaseClient == nil {
		log.Fatal().Msg("Failed to create Supabase client")
	}

	// Prepare the data to update
	var aclData map[string]interface{}
	if flags.JustRoles {
		aclData = map[string]interface{}{
			"acl": map[string]interface{}{
				"roles": config.Auth.ACL.Roles,
			},
		}
		log.Debug().Int("role_count", len(config.Auth.ACL.Roles)).Msg("Updating roles only")
	} else if flags.JustTiers {
		aclData = map[string]interface{}{
			"acl": map[string]interface{}{
				"tiers": config.Auth.ACL.Tiers,
			},
		}
		log.Debug().Int("tier_count", len(config.Auth.ACL.Tiers)).Msg("Updating tiers only")
	} else {
		aclData = map[string]interface{}{
			"acl": map[string]interface{}{
				"roles": config.Auth.ACL.Roles,
				"tiers": config.Auth.ACL.Tiers,
			},
		}
		log.Debug().
			Int("role_count", len(config.Auth.ACL.Roles)).
			Int("tier_count", len(config.Auth.ACL.Tiers)).
			Msg("Updating complete ACL")
	}

	// Convert to JSON
	aclJSON, err := json.Marshal(aclData)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to marshal ACL to JSON")
	}

	// Generate request ID
	requestID := fmt.Sprintf("acl-update-%d", time.Now().UnixNano())

	// Call direct RPC endpoint
	log.Info().Msg("Updating ACL in database")
	var result interface{}
	err = supabaseClient.DB.Rpc("load_acl", map[string]interface{}{
		"acl_data":   json.RawMessage(aclJSON),
		"request_id": requestID,
	}).Execute(&result)

	// If direct call fails, try using exec_sql wrapper
	if err != nil {
		log.Warn().Err(err).Msg("Direct RPC call failed, trying with exec_sql wrapper")

		execSQLQuery := map[string]interface{}{
			"query": "SELECT load_acl($1::jsonb, $2::text)",
			"params": map[string]interface{}{
				"param1": string(aclJSON),
				"param2": requestID,
			},
		}

		err = supabaseClient.DB.Rpc("exec_sql", execSQLQuery).Execute(&result)
		if err != nil {
			log.Fatal().Err(err).Msg("Database update failed")
		}
	}

	log.Info().Msg("ACL update completed successfully")
}

// noFlagsProvided checks if any command-line flags were provided
func noFlagsProvided() bool {
	// flag.NFlag() returns the number of flags that have been set
	return flag.NFlag() == 0
}

// showHelp displays detailed help information
func showHelp() {
	appName := filepath.Base(os.Args[0])

	fmt.Printf("\n%s - ACL Management Tool v%s\n", appName, Version)
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println("\nThis tool manages Access Control Lists (ACL) for applications using Supabase.")
	fmt.Println("\nUSAGE:")
	fmt.Printf("  %s [OPTIONS]\n\n", appName)

	fmt.Println("CONFIGURATION OPTIONS:")
	fmt.Println("  -config string      Path to the configuration file (default \"config.json\")")
	fmt.Println("  -auth               Use auth configuration format instead of standalone ACL")
	fmt.Println("  -auth-path string   Path to auth configuration (if separate from main config)")

	fmt.Println("\nOPERATION OPTIONS:")
	fmt.Println("  -update-db          Update the database with the ACL configuration")
	fmt.Println("  -dry-run            Show what would be updated without making changes")
	fmt.Println("  -roles              Update just roles (not tiers)")
	fmt.Println("  -tiers              Update just tiers (not roles)")
	fmt.Println("  -backup             Backup current ACL before updating")

	fmt.Println("\nOUTPUT OPTIONS:")
	fmt.Println("  -output string      Path to save the extracted ACL configuration")
	fmt.Println("  -verbose            Enable verbose logging")
	fmt.Println("  -timeout int        Timeout in seconds for database operations (default 30)")
	fmt.Println("  -version            Display version information")
	fmt.Println("  -help               Show this help message")

	fmt.Println("\nEXAMPLES:")
	fmt.Printf("  # Show this help\n  %s -help\n\n", appName)
	fmt.Printf("  # Update database with complete ACL (classic format)\n  %s -config config.json -update-db\n\n", appName)
	fmt.Printf("  # Update database with auth-style ACL\n  %s -config config.json -auth -update-db\n\n", appName)
	fmt.Printf("  # Update just roles in auth-style ACL\n  %s -config config.json -auth -roles -update-db\n\n", appName)
	fmt.Printf("  # Perform a dry run to see what would be updated\n  %s -config config.json -auth -dry-run\n\n", appName)
	fmt.Printf("  # Extract ACL to a file without updating database\n  %s -config config.json -auth -output acl.json\n\n", appName)

	fmt.Println("\nCONFIGURATION FORMAT:")
	fmt.Println("  The tool expects a configuration file with database connection details")
	fmt.Println("  and ACL structure. For auth mode, it expects the ACL in the auth configuration.")
	fmt.Println("  Database connection details are automatically taken from the Auth section")
	fmt.Println("  of the config file (supabase_url and supabase_role_key fields).")

	fmt.Println("\nFor more information, visit: https://github.com/mtgban/acl-manager")
	fmt.Println("")
}

// parseFlags parses command line flags and returns a Flags struct
func parseFlags() Flags {
	flags := Flags{}

	flag.StringVar(&flags.ConfigPath, "config", "config.json", "Path to the configuration file")
	flag.StringVar(&flags.OutputPath, "output", "", "Path to save the extracted ACL configuration (optional)")
	flag.BoolVar(&flags.UpdateDB, "update-db", false, "Update the database with the ACL configuration")
	flag.BoolVar(&flags.DryRun, "dry-run", false, "Show what would be updated without making changes")
	flag.BoolVar(&flags.Verbose, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&flags.JustRoles, "roles", false, "Update just roles")
	flag.BoolVar(&flags.JustTiers, "tiers", false, "Update just tiers")
	flag.BoolVar(&flags.BackupFirst, "backup", false, "Backup current ACL before updating")
	flag.IntVar(&flags.Timeout, "timeout", 30, "Timeout in seconds for database operations")

	// New flags for auth config
	flag.BoolVar(&flags.AuthMode, "auth", false, "Use auth configuration format")
	flag.StringVar(&flags.AuthPath, "auth-path", "", "Path to auth configuration (if separate from main config)")

	// Help flag
	flag.BoolVar(&flags.Help, "help", false, "Show help information")

	// Add version flag
	version := flag.Bool("version", false, "Display version information")
	flag.Parse()

	if *version {
		fmt.Printf("ACL Manager v%s\n", Version)
		os.Exit(0)
	}

	return flags
}

// loadConfig loads the configuration from file
func loadConfig(configPath string, authMode bool, authPath string) (*Config, error) {
	config := &Config{}

	// Expand the path if it contains ~
	if len(configPath) > 0 && configPath[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get user home directory: %w", err)
		}
		configPath = filepath.Join(home, configPath[1:])
	}

	// Try to load from config file if it exists
	if _, err := os.Stat(configPath); err == nil {
		// Open the file
		file, err := os.Open(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open config file: %w", err)
		}
		defer file.Close()

		// If using auth mode, load the full auth config
		if authMode {
			// If auth path is specified, load from that file
			if authPath != "" {
				authFile, err := os.Open(authPath)
				if err != nil {
					return nil, fmt.Errorf("failed to open auth config file: %w", err)
				}
				defer authFile.Close()

				// Parse auth file as a standalone auth config
				var authConfig AuthConfig
				if err := json.NewDecoder(authFile).Decode(&authConfig); err != nil {
					return nil, fmt.Errorf("failed to parse auth config file: %w", err)
				}
				config.Auth = authConfig
			} else {
				// Parse the main file as a full auth config
				var authWrapper struct {
					Auth AuthConfig `json:"auth"`
				}
				if err := json.NewDecoder(file).Decode(&authWrapper); err != nil {
					return nil, fmt.Errorf("failed to parse auth config: %w", err)
				}
				config.Auth = authWrapper.Auth
			}
		} else {
			// Parse the file as standard config
			if err := json.NewDecoder(file).Decode(config); err != nil {
				return nil, fmt.Errorf("failed to parse config file: %w", err)
			}
		}

		log.Debug().Str("config_path", configPath).Msg("Loaded configuration from file")

		// Copy Supabase DB connection details from Auth section to DB section if needed
		if config.DB.Url == "" && config.Auth.SupabaseURL != "" {
			config.DB.Url = config.Auth.SupabaseURL
		}

		if config.DB.Key == "" && config.Auth.SupabaseRoleKey != "" {
			config.DB.Key = config.Auth.SupabaseRoleKey
		}

		if config.DB.Secret == "" && config.Auth.SupabaseJWTSecret != "" {
			config.DB.Secret = config.Auth.SupabaseJWTSecret
		}
	} else if os.IsNotExist(err) {
		// If no config file, return error
		return nil, fmt.Errorf("config file not found: %s", configPath)
	}

	return config, nil
}

// validateConfig validates the configuration
func validateConfig(config *Config, authMode bool) error {
	// Check for missing required fields
	if config.DB.Url == "" {
		return errors.New("database URL is required")
	}
	if config.DB.Key == "" {
		return errors.New("database API key is required")
	}

	// Validate ACL
	if authMode {
		if config.Auth.ACL.Tiers == nil && config.Auth.ACL.Roles == nil {
			return errors.New("ACL must contain at least one tier or role")
		}
	} else {
		if config.Auth.ACL.Tiers == nil && config.Auth.ACL.Roles == nil {
			return errors.New("ACL must contain at least one tier or role")
		}
	}

	return nil
}

// prepareACLJSON prepares the ACL JSON based on update type
func prepareACLJSON(acl ACL, justRoles, justTiers, authMode bool) ([]byte, error) {
	var data interface{}

	if justRoles {
		// Update only roles
		if authMode {
			data = map[string]interface{}{
				"auth": map[string]interface{}{
					"acl": map[string]interface{}{
						"role": acl.Roles,
					},
				},
			}
		} else {
			data = map[string]interface{}{
				"acl": map[string]interface{}{
					"role": acl.Roles,
				},
			}
		}
		log.Debug().Int("role_count", len(acl.Roles)).Msg("Preparing roles only ACL")
	} else if justTiers {
		// Update only tiers
		if authMode {
			data = map[string]interface{}{
				"auth": map[string]interface{}{
					"acl": map[string]interface{}{
						"tier": acl.Tiers,
					},
				},
			}
		} else {
			data = map[string]interface{}{
				"acl": map[string]interface{}{
					"tier": acl.Tiers,
				},
			}
		}
		log.Debug().Int("tier_count", len(acl.Tiers)).Msg("Preparing tiers only ACL")
	} else {
		// Update both roles and tiers
		if authMode {
			data = map[string]interface{}{
				"auth": map[string]interface{}{
					"acl": map[string]interface{}{
						"tier": acl.Tiers,
						"role": acl.Roles,
					},
				},
			}
		} else {
			data = map[string]interface{}{
				"acl": map[string]interface{}{
					"tier": acl.Tiers,
					"role": acl.Roles,
				},
			}
		}
		log.Debug().
			Int("tier_count", len(acl.Tiers)).
			Int("role_count", len(acl.Roles)).
			Msg("Preparing complete ACL")
	}

	// Marshal to JSON with optimized buffer
	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufferPool.Put(buf)

	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false) // Improve performance
	if err := encoder.Encode(data); err != nil {
		return nil, fmt.Errorf("failed to marshal ACL to JSON: %w", err)
	}

	return buf.Bytes(), nil
}

// saveToFile saves data to a file with pretty formatting
func saveToFile(data []byte, filePath string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Format the JSON with indentation for better readability
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, data, "", "  "); err != nil {
		return fmt.Errorf("failed to format JSON: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filePath, prettyJSON.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}

	return nil
}

// displayDryRunInfo displays what would be updated without making changes
func displayDryRunInfo(acl ACL, justRoles, justTiers bool) {
	fmt.Println("DRY RUN - No changes will be made to the database")

	if justRoles {
		fmt.Printf("Would update ACL with %d roles\n", len(acl.Roles))
		fmt.Println("\nRoles:")
		for role := range acl.Roles {
			fmt.Printf("  - %s\n", role)
		}
	} else if justTiers {
		fmt.Printf("Would update ACL with %d tiers\n", len(acl.Tiers))
		fmt.Println("\nTiers:")
		for tier := range acl.Tiers {
			fmt.Printf("  - %s\n", tier)
		}
	} else {
		fmt.Printf("Would update ACL with %d tiers and %d roles\n",
			len(acl.Tiers), len(acl.Roles))
		fmt.Println("\nTiers:")
		for tier := range acl.Tiers {
			fmt.Printf("  - %s\n", tier)
		}
		fmt.Println("\nRoles:")
		for role := range acl.Roles {
			fmt.Printf("  - %s\n", role)
		}
	}
}

// updateDatabase updates the database with the ACL configuration
func updateDatabase(ctx context.Context, config *Config, aclJSON []byte, flags Flags, acl ACL) error {
	log.Info().Msg("Initializing database connection")

	// Create Supabase client
	supabaseClient := supabase.CreateClient(config.DB.Url, config.DB.Key)
	if supabaseClient == nil {
		return errors.New("failed to create Supabase client; check URL and key configuration")
	}

	// Backup current ACL if requested
	if flags.BackupFirst {
		if err := backupCurrentACL(ctx, supabaseClient, flags.AuthMode); err != nil {
			return fmt.Errorf("backup failed: %w", err)
		}
	}

	// Rate limit to prevent API abuse (simple implementation)
	time.Sleep(500 * time.Millisecond)

	// Update the ACL
	if err := updateACLWithRestAPI(ctx, supabaseClient, aclJSON, flags.Verbose, flags.AuthMode); err != nil {
		return fmt.Errorf("ACL update failed: %w", err)
	}

	// Log success message
	if flags.JustRoles {
		log.Info().Int("count", len(acl.Roles)).Msg("Successfully updated roles in database")
	} else if flags.JustTiers {
		log.Info().Int("count", len(acl.Tiers)).Msg("Successfully updated tiers in database")
	} else {
		log.Info().
			Int("tier_count", len(acl.Tiers)).
			Int("role_count", len(acl.Roles)).
			Msg("Successfully updated ACL in database")
	}

	return nil
}

// backupCurrentACL fetches and backs up the current ACL
func backupCurrentACL(ctx context.Context, client *supabase.Client, authMode bool) error {
	log.Info().Msg("Backing up current ACL")

	// Query to get current ACL
	var fetchQuery Query
	if authMode {
		fetchQuery = Query{
			Query:  "SELECT get_current_auth_acl()",
			Params: map[string]interface{}{},
		}
	} else {
		fetchQuery = Query{
			Query:  "SELECT get_current_acl()",
			Params: map[string]interface{}{},
		}
	}

	var result json.RawMessage
	if err := client.DB.Rpc("exec_sql", map[string]interface{}{"query": fetchQuery.Query, "params": fetchQuery.Params}); err != nil {
		return fmt.Errorf("failed to fetch current ACL: %w", err)
	}

	// Create backup filename with timestamp
	backupFile := fmt.Sprintf("acl_backup_%s.json", time.Now().Format("20060102_150405"))

	// Save to file
	if err := saveToFile(result, backupFile); err != nil {
		return fmt.Errorf("failed to save backup: %w", err)
	}

	log.Info().Str("file", backupFile).Msg("Current ACL backed up")
	return nil
}

// updateACLWithRestAPI updates the ACL using Supabase's REST API
func updateACLWithRestAPI(ctx context.Context, client *supabase.Client, aclJSON []byte, verbose bool, authMode bool) error {
	if verbose {
		log.Debug().Msg("Updating ACL using Supabase REST API")
	}

	// Add request ID for tracking
	requestID := fmt.Sprintf("acl-update-%d", time.Now().UnixNano())

	// Call the function to update the ACL
	var updateQuery Query
	if authMode {
		updateQuery = Query{
			Query: "SELECT load_auth_acl($1::jsonb, $2::text)",
			Params: map[string]interface{}{
				"param1": string(aclJSON),
				"param2": requestID,
			},
		}
	} else {
		updateQuery = Query{
			Query: "SELECT load_acl($1::jsonb, $2::text)",
			Params: map[string]interface{}{
				"param1": string(aclJSON),
				"param2": requestID,
			},
		}
	}

	var result interface{}
	if err := client.DB.Rpc("exec_sql", map[string]interface{}{"query": updateQuery.Query, "params": updateQuery.Params}); err != nil {
		return fmt.Errorf("database update failed: %w", err)
	}

	log.Info().Interface("result", result).Msg("Database update result")

	return nil
}

// fetchCurrentACL fetches the current ACL from the database
func fetchCurrentACL(ctx context.Context, client *supabase.Client, authMode bool) (ACL, error) {
	var acl ACL

	// Query to get current ACL
	var fetchQuery Query
	if authMode {
		fetchQuery = Query{
			Query:  "SELECT get_current_auth_acl()",
			Params: map[string]interface{}{},
		}
	} else {
		fetchQuery = Query{
			Query:  "SELECT get_current_acl()",
			Params: map[string]interface{}{},
		}
	}

	var result json.RawMessage
	if err := client.DB.Rpc("exec_sql", map[string]interface{}{"query": fetchQuery.Query, "params": fetchQuery.Params}); err != nil {
		return acl, fmt.Errorf("failed to fetch current ACL: %w", err)
	}

	// Parse result
	if err := json.Unmarshal(result, &acl); err != nil {
		return acl, fmt.Errorf("failed to parse ACL result: %w", err)
	}

	return acl, nil
}
