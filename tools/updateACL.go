package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	supabase "github.com/nedpals/supabase-go"
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
	Tier map[string]TierPermissions `json:"tier"`
	Role map[string]RolePermissions `json:"role"`
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
type ACL struct {
	Roles map[string]map[string]map[string]string `json:"roles"`
	Tiers map[string]map[string]map[string]string `json:"tiers"`
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

	// ACL configuration with explicit roles and tiers
	ACL ACL `json:"acl"`
}

// Query represents a Supabase query with named parameters
type Query struct {
	Query  string                 `json:"query"`
	Params map[string]interface{} `json:"params"`
}

// ConvertToStructured converts the database-style ACL to a strongly typed structure
func (a ACL) ConvertToStructured() ACLStructured {
	structured := ACLStructured{
		Tier: make(map[string]TierPermissions),
		Role: make(map[string]RolePermissions),
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

func main() {
	// Parse command-line flags
	configPath := flag.String("config", "config.json", "Path to the configuration file")
	outputPath := flag.String("output", "", "Path to save the extracted ACL configuration (optional)")
	updateDB := flag.Bool("update-db", false, "Update the database with the ACL configuration")
	dryRun := flag.Bool("dry-run", false, "Show what would be updated without making changes")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	justRoles := flag.Bool("roles", false, "Update just roles")
	justTiers := flag.Bool("tiers", false, "Update just tiers")
	flag.Parse()

	// Set up logging
	log.SetPrefix("[ACL-UPDATER] ")
	if *verbose {
		log.Println("Verbose logging enabled")
	}

	// Load configuration
	if *verbose {
		log.Printf("Loading configuration from %s", *configPath)
	}
	config, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Check if the ACL exists with tiers and roles
	if len(config.ACL.Tiers) == 0 && len(config.ACL.Roles) == 0 {
		log.Fatalf("No ACL configuration found in %s", *configPath)
	}

	// Convert to structured ACL to enable using the helper methods
	structuredACL := config.ACL.ConvertToStructured()

	// Example of using the structured ACL methods
	if *verbose {
		// Check if 'admin' role has 'SearchDownloadCSV' permission in 'Search' section
		adminRole := structuredACL.Role["admin"]
		if adminRole != nil {
			searchSection := adminRole.GetSection("Search")
			if searchSection != nil {
				hasDownloadCSV := searchSection.HasPermission("SearchDownloadCSV")
				log.Printf("Admin role has SearchDownloadCSV permission: %v", hasDownloadCSV)

				value := searchSection.GetPermissionValue("SearchDownloadCSV", "false")
				log.Printf("SearchDownloadCSV value: %s", value)
			}
		}
	}

	// Prepare aclJSON based on the update type
	var aclJSON []byte
	if *justRoles {
		// Update only roles
		aclJSON, err = json.Marshal(map[string]interface{}{
			"acl": map[string]interface{}{
				"roles": config.ACL.Roles,
			},
		})
		if err != nil {
			log.Fatalf("Failed to marshal roles ACL to JSON: %v", err)
		}

		if *verbose {
			log.Printf("Only updating %d roles in ACL configuration", len(config.ACL.Roles))
		}
	} else if *justTiers {
		// Update only tiers
		aclJSON, err = json.Marshal(map[string]interface{}{
			"acl": map[string]interface{}{
				"tiers": config.ACL.Tiers,
			},
		})
		if err != nil {
			log.Fatalf("Failed to marshal tiers ACL to JSON: %v", err)
		}

		if *verbose {
			log.Printf("Only updating %d tiers in ACL configuration", len(config.ACL.Tiers))
		}
	} else {
		// Update both roles and tiers
		aclJSON, err = json.Marshal(map[string]interface{}{
			"acl": map[string]interface{}{
				"tiers": config.ACL.Tiers,
				"roles": config.ACL.Roles,
			},
		})
		if err != nil {
			log.Fatalf("Failed to marshal ACL to JSON: %v", err)
		}

		if *verbose {
			log.Printf("Found %d tiers and %d roles in ACL configuration",
				len(config.ACL.Tiers), len(config.ACL.Roles))
		}
	}

	// If outputPath is specified, save the ACL configuration to file
	if *outputPath != "" {
		if *verbose {
			log.Printf("Saving ACL configuration to %s", *outputPath)
		}

		// Format the JSON with indentation for better readability
		prettyJSON, err := json.MarshalIndent(json.RawMessage(aclJSON), "", "  ")
		if err != nil {
			log.Fatalf("Failed to format ACL JSON: %v", err)
		}

		if err := os.WriteFile(*outputPath, prettyJSON, 0644); err != nil {
			log.Fatalf("Failed to write ACL configuration to file: %v", err)
		}

		log.Printf("ACL configuration saved to %s", *outputPath)
	}

	// In dry-run mode, just show what would be updated
	if *dryRun {
		fmt.Println("DRY RUN - No changes will be made to the database")

		if *justRoles {
			fmt.Printf("Would update ACL with %d roles\n", len(config.ACL.Roles))
			fmt.Println("\nRoles:")
			for role := range config.ACL.Roles {
				fmt.Printf("  - %s\n", role)
			}
		} else if *justTiers {
			fmt.Printf("Would update ACL with %d tiers\n", len(config.ACL.Tiers))
			fmt.Println("\nTiers:")
			for tier := range config.ACL.Tiers {
				fmt.Printf("  - %s\n", tier)
			}
		} else {
			fmt.Printf("Would update ACL with %d tiers and %d roles\n",
				len(config.ACL.Tiers), len(config.ACL.Roles))
			fmt.Println("\nTiers:")
			for tier := range config.ACL.Tiers {
				fmt.Printf("  - %s\n", tier)
			}
			fmt.Println("\nRoles:")
			for role := range config.ACL.Roles {
				fmt.Printf("  - %s\n", role)
			}
		}
		return
	}

	// If updateDB flag is set, update the database
	if *updateDB {
		if *verbose {
			log.Println("Initializing Supabase client for database update...")
		}

		// Check for required config values
		if config.DB.Url == "" || config.DB.Key == "" {
			log.Fatalf("Missing required Supabase URL or key in configuration")
		}

		// Create Supabase client
		supabaseClient := supabase.CreateClient(config.DB.Url, config.DB.Key)
		if supabaseClient == nil {
			log.Fatalf("Failed to create Supabase client")
		}

		// Update the ACL using Supabase REST API
		if err := updateACLWithRestAPI(context.Background(), supabaseClient, aclJSON, *verbose); err != nil {
			log.Fatalf("Failed to update ACL in database: %v", err)
		}

		if *justRoles {
			log.Printf("Successfully updated ACL with %d roles in database", len(config.ACL.Roles))
		} else if *justTiers {
			log.Printf("Successfully updated ACL with %d tiers in database", len(config.ACL.Tiers))
		} else {
			log.Printf("Successfully updated ACL with %d tiers and %d roles in database",
				len(config.ACL.Tiers), len(config.ACL.Roles))
		}
	}
}

// updateACLWithRestAPI updates the ACL using Supabase's REST API
func updateACLWithRestAPI(ctx context.Context, client *supabase.Client, aclJSON []byte, verbose bool) error {
	if verbose {
		log.Println("Updating ACL using Supabase REST API...")
	}

	// Call the function to update the ACL
	updateQuery := Query{
		Query: "SELECT load_acl($1::jsonb)",
		Params: map[string]interface{}{
			"param1": string(aclJSON),
		},
	}

	var result interface{}
	if err := client.DB.RPC(ctx, "exec_sql", updateQuery, &result); err != nil {
		return fmt.Errorf("failed to update ACL: %w", err)
	}

	return nil
}

func loadConfig(configPath string) (*Config, error) {
	// Expand the path if it contains ~
	if len(configPath) > 0 && configPath[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get user home directory: %w", err)
		}
		configPath = filepath.Join(home, configPath[1:])
	}

	// Open the file
	file, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	// Parse the file
	var config Config
	if err := json.NewDecoder(file).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// extractACL extracts just the ACL portion from the config file
func extractACL(config *Config) ([]byte, error) {
	aclJSON, err := json.MarshalIndent(map[string]interface{}{
		"acl": map[string]interface{}{
			"tiers": config.ACL.Tiers,
			"roles": config.ACL.Roles,
		},
	}, "", "  ")

	if err != nil {
		return nil, fmt.Errorf("failed to marshal ACL to JSON: %w", err)
	}

	return aclJSON, nil
}
