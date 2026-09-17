// Package catalog is the API price list: what is sold, at what amount, and
// under which entitlement. The website renders the pricing page from it and
// the gateway seeds Stripe from it, so both read this one embedded file.
package catalog

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

//go:embed catalog.json
var embedded []byte

// StoreScopeExplicit marks a package whose stores the customer picks.
const StoreScopeExplicit = "explicit"

var (
	keyPattern     = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	validScopes    = []string{StoreScopeExplicit, "BASE_ACCESS", "ALL_ACCESS"}
	validModes     = []string{"retail", "buylist", "sealed"}
	validIntervals = []string{"day", "week", "month", "year"}
)

// Package is one price-data tier.
type Package struct {
	Key            string   `json:"key"`
	Name           string   `json:"name"`
	Monthly        int64    `json:"monthly"`
	StoreScope     string   `json:"store_scope"`
	IncludedStores int      `json:"included_stores"`
	Modes          []string `json:"modes"`
}

// Addon is a per-unit extra a package can carry.
type Addon struct {
	Key       string   `json:"key"`
	Name      string   `json:"name"`
	Monthly   int64    `json:"monthly"`
	AppliesTo []string `json:"applies_to"`
}

// Interval is a billing cadence. A non-public one needs an invite.
type Interval struct {
	Key      string `json:"key"`
	Interval string `json:"interval"`
	Count    int64  `json:"count"`
	Public   bool   `json:"public"`
}

// Catalog is the whole price list.
type Catalog struct {
	Currency         string     `json:"currency"`
	Packages         []Package  `json:"packages"`
	Addons           []Addon    `json:"addons"`
	Intervals        []Interval `json:"intervals"`
	IncludedGames    []string   `json:"included_games"`
	SelectableStores []string   `json:"selectable_stores"`
}

// Load parses the embedded catalog.
func Load() (*Catalog, error) {
	return Parse(embedded)
}

// MustLoad is Load for package initializers; the embedded file is under test.
func MustLoad() *Catalog {
	c, err := Load()
	if err != nil {
		panic("catalog: " + err.Error())
	}
	return c
}

// Parse decodes and validates a catalog document.
func Parse(data []byte) (*Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	return &c, nil
}

// Validate reports the first thing wrong with the catalog.
func (c *Catalog) Validate() error {
	if len(c.Currency) != 3 || strings.ToLower(c.Currency) != c.Currency {
		return errors.New("currency must be a lowercase three-letter code")
	}
	if len(c.Packages) == 0 {
		return errors.New("at least one package is required")
	}
	seen := map[string]bool{}
	claim := func(key string) error {
		if !keyPattern.MatchString(key) {
			return fmt.Errorf("key %q must match %s", key, keyPattern)
		}
		if seen[key] {
			return fmt.Errorf("duplicate key %q", key)
		}
		seen[key] = true
		return nil
	}
	for _, p := range c.Packages {
		if err := claim(p.Key); err != nil {
			return err
		}
		if p.Monthly <= 0 {
			return fmt.Errorf("package %s: monthly must be positive", p.Key)
		}
		if !slices.Contains(validScopes, p.StoreScope) {
			return fmt.Errorf("package %s: store_scope must be one of %v", p.Key, validScopes)
		}
		if p.StoreScope == StoreScopeExplicit && p.IncludedStores < 1 {
			return fmt.Errorf("package %s: included_stores must be at least 1 for an explicit scope", p.Key)
		}
		if p.StoreScope != StoreScopeExplicit && p.IncludedStores != 0 {
			return fmt.Errorf("package %s: included_stores applies to an explicit scope only", p.Key)
		}
		if err := validateModes(p.Key, p.Modes); err != nil {
			return err
		}
	}
	for _, a := range c.Addons {
		if err := claim(a.Key); err != nil {
			return err
		}
		if a.Monthly <= 0 {
			return fmt.Errorf("addon %s: monthly must be positive", a.Key)
		}
		if len(a.AppliesTo) == 0 {
			return fmt.Errorf("addon %s: applies_to is empty", a.Key)
		}
		for _, key := range a.AppliesTo {
			if _, ok := c.Package(key); !ok {
				return fmt.Errorf("addon %s: applies_to names unknown package %q", a.Key, key)
			}
		}
	}
	if len(c.Intervals) == 0 {
		return errors.New("at least one interval is required")
	}
	public := false
	for _, iv := range c.Intervals {
		if err := claim(iv.Key); err != nil {
			return err
		}
		if !slices.Contains(validIntervals, iv.Interval) {
			return fmt.Errorf("interval %s: interval must be one of %v", iv.Key, validIntervals)
		}
		if iv.Count < 1 {
			return fmt.Errorf("interval %s: count must be at least 1", iv.Key)
		}
		public = public || iv.Public
	}
	if !public {
		return errors.New("at least one interval must be public")
	}
	if len(c.IncludedGames) == 0 {
		return errors.New("included_games is empty")
	}
	if len(c.SelectableStores) == 0 {
		return errors.New("selectable_stores is empty")
	}
	for i, s := range c.SelectableStores {
		if s == "" || strings.ToUpper(s) != s {
			return fmt.Errorf("selectable_stores: %q must be an uppercase shorthand", s)
		}
		if slices.Contains(c.SelectableStores[:i], s) {
			return fmt.Errorf("selectable_stores: duplicate %q", s)
		}
	}
	return nil
}

func validateModes(key string, modes []string) error {
	if len(modes) == 0 {
		return fmt.Errorf("package %s: at least one mode is required", key)
	}
	for i, m := range modes {
		if !slices.Contains(validModes, m) {
			return fmt.Errorf("package %s: unknown mode %q", key, m)
		}
		if slices.Contains(modes[:i], m) {
			return fmt.Errorf("package %s: duplicate mode %q", key, m)
		}
	}
	return nil
}

// Package returns the package with that key.
func (c *Catalog) Package(key string) (Package, bool) {
	for _, p := range c.Packages {
		if p.Key == key {
			return p, true
		}
	}
	return Package{}, false
}
