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
	"unicode"
)

//go:embed catalog.json
var embedded []byte

// StoreScopeExplicit marks a package whose stores the customer picks.
const StoreScopeExplicit = "explicit"

// StoreScopeBase is the BASE_ACCESS preset.
const StoreScopeBase = "BASE_ACCESS"

// StoreScopeAll is the ALL_ACCESS preset.
const StoreScopeAll = "ALL_ACCESS"

var (
	keyPattern      = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	currencyPattern = regexp.MustCompile(`^[a-z]{3}$`)
	validScopes     = []string{StoreScopeExplicit, StoreScopeBase, StoreScopeAll}
	validModes      = []string{"retail", "buylist", "sealed"}
	validIntervals  = []string{"month", "year"}
)

// Package is one price-data tier.
type Package struct {
	Key        string `json:"key"`
	Name       string `json:"name"`
	Monthly    int64  `json:"monthly"`
	StoreScope string `json:"store_scope"`
	// IncludedStores is how many selectable stores the price includes beyond the implied TCG.
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
	Currency      string     `json:"currency"`
	Packages      []Package  `json:"packages"`
	Addons        []Addon    `json:"addons"`
	Intervals     []Interval `json:"intervals"`
	IncludedGames []string   `json:"included_games"`
	// SelectableStores never lists TCG: TCGplayer is implied on the starter package and the gateway adds it to the entitlement.
	SelectableStores []string `json:"selectable_stores"`
}

// Load parses the embedded catalog.
func Load() (*Catalog, error) {
	return Parse(embedded)
}

// MustLoad is Load for package initializers; the embedded file is under test.
func MustLoad() *Catalog {
	c, err := Load()
	if err != nil {
		panic(err.Error())
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
	if !currencyPattern.MatchString(c.Currency) {
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
		if p.Name == "" {
			return fmt.Errorf("package %s: name is empty", p.Key)
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
		if a.Name == "" {
			return fmt.Errorf("addon %s: name is empty", a.Key)
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
	for i, g := range c.IncludedGames {
		if g == "" || strings.ToLower(g) != g {
			return fmt.Errorf("included_games: %q must be a lowercase game name", g)
		}
		if slices.Contains(c.IncludedGames[:i], g) {
			return fmt.Errorf("included_games: duplicate %q", g)
		}
	}
	if len(c.SelectableStores) == 0 {
		return errors.New("selectable_stores is empty")
	}
	for i, s := range c.SelectableStores {
		if s == "" || strings.ContainsRune(s, ',') || strings.IndexFunc(s, unicode.IsSpace) >= 0 {
			return fmt.Errorf("selectable_stores: %q must be a store shorthand with no comma or whitespace", s)
		}
		if slices.Contains(c.SelectableStores[:i], s) {
			return fmt.Errorf("selectable_stores: duplicate %q", s)
		}
	}
	if err := c.checkLookupKeyCollisions(); err != nil {
		return err
	}
	return nil
}

// checkLookupKeyCollisions reports when two items and intervals produce the same Stripe lookup key.
func (c *Catalog) checkLookupKeyCollisions() error {
	seen := map[string]bool{}
	items := make([]string, 0, len(c.Packages)+len(c.Addons))
	for _, p := range c.Packages {
		items = append(items, p.Key)
	}
	for _, a := range c.Addons {
		items = append(items, a.Key)
	}
	for _, item := range items {
		for _, iv := range c.Intervals {
			key := LookupKey(item, iv.Key)
			if seen[key] {
				return fmt.Errorf("lookup key %q is produced by more than one item and interval", key)
			}
			seen[key] = true
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

// Addon returns the add-on with that key.
func (c *Catalog) Addon(key string) (Addon, bool) {
	for _, a := range c.Addons {
		if a.Key == key {
			return a, true
		}
	}
	return Addon{}, false
}

// Interval returns the interval with that key.
func (c *Catalog) Interval(key string) (Interval, bool) {
	for _, iv := range c.Intervals {
		if iv.Key == key {
			return iv, true
		}
	}
	return Interval{}, false
}

// PublicIntervals returns the intervals a customer may pick without an invite.
func (c *Catalog) PublicIntervals() []Interval {
	var out []Interval
	for _, iv := range c.Intervals {
		if iv.Public {
			out = append(out, iv)
		}
	}
	return out
}

// Applies reports whether the add-on can be attached to the package.
func (a Addon) Applies(packageKey string) bool {
	return slices.Contains(a.AppliesTo, packageKey)
}

// Amount is the charge per billing period for a monthly amount.
// Validate only admits month and year, so the fallthrough is unreachable.
func (iv Interval) Amount(monthly int64) int64 {
	switch iv.Interval {
	case "month":
		return monthly * iv.Count
	case "year":
		return monthly * 12 * iv.Count
	}
	return 0
}

// LookupKey is the Stripe lookup_key for an item billed at an interval.
func LookupKey(itemKey, intervalKey string) string {
	return itemKey + "_" + intervalKey
}
