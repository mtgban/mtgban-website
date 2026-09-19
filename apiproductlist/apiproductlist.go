// Package apiproductlist is the API price list: what is sold, at what
// amount, and under which entitlement. The website renders the pricing page
// from it and the gateway seeds Stripe from it, so both read this one
// embedded file.
//
// The list carries structure (package keys, scopes, modes, store families,
// intervals) and the amounts Stripe is seeded with. Stripe holds the live
// Prices, keyed by LookupKey; the gateway looks them up by key and never
// parses a key. The gateway pins this module by commit, so an edit here
// reaches customers when the gateway bumps its dependency. The Patreon bundle
// is not listed: it is sold through Patreon and granted as a manual
// entitlement.
package apiproductlist

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

//go:embed products.json
var embedded []byte

// StoreScopeExplicit marks a package whose stores the customer picks.
const StoreScopeExplicit = "explicit"

// StoreScopeBase is the BASE_ACCESS preset: singles from the main region plus metadata-only indexes.
const StoreScopeBase = "BASE_ACCESS"

// StoreScopeAll is the ALL_ACCESS preset: every store; modes decide sealed.
const StoreScopeAll = "ALL_ACCESS"

// StoreScopes are the store_scope values a package may carry.
var StoreScopes = []string{StoreScopeExplicit, StoreScopeBase, StoreScopeAll}

// Modes are the API modes a package may grant, and the order a package must list them in.
var Modes = []string{"retail", "buylist", "sealed"}

// Currencies are the currencies Stripe is seeded in.
var Currencies = []string{"usd"}

var (
	keyPattern      = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	gamePattern     = regexp.MustCompile(`^[a-z0-9]+$`)
	storeKeyPattern = regexp.MustCompile(`^[A-Z0-9]+$`)
	validIntervals  = []string{"month"}
)

// Package is one price-data tier.
type Package struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	// Monthly is the price per month in the smallest unit of the currency (cents for usd).
	Monthly    int64  `json:"monthly"`
	StoreScope string `json:"store_scope"`
	// IncludedStores is how many selectable stores the price includes beyond the implied ones.
	IncludedStores int      `json:"included_stores"`
	Modes          []string `json:"modes"`
}

// Addon is a per-unit extra a package can carry.
type Addon struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	// Monthly is the price per unit per month in the smallest unit of the currency (cents for usd).
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

// Store is one seller a customer can name, with every shorthand the price
// API knows it by. Keys are uppercase because the gateway uppercases what a
// customer typed before matching; shorthands keep the backend's spelling.
type Store struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	// Implied stores are part of every explicit-scope package and are not selectable.
	Implied    bool     `json:"implied"`
	Shorthands []string `json:"shorthands"`
}

// ProductList is the whole price list.
type ProductList struct {
	Currency      string     `json:"currency"`
	Packages      []Package  `json:"packages"`
	Addons        []Addon    `json:"addons"`
	Intervals     []Interval `json:"intervals"`
	IncludedGames []string   `json:"included_games"`
	// Stores is the starter picker and the pricing page's store names. A
	// preset scope is expanded by the backend from its live scrapers and
	// never reads this list.
	Stores []Store `json:"stores"`
}

// Load parses the embedded list.
func Load() (*ProductList, error) {
	return Parse(embedded)
}

// MustLoad is Load for package initializers; the embedded file is under test.
func MustLoad() *ProductList {
	c, err := Load()
	if err != nil {
		panic(err)
	}
	return c
}

// Parse decodes and validates a product list document.
func Parse(data []byte) (*ProductList, error) {
	var c ProductList
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("apiproductlist: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("apiproductlist: %w", err)
	}
	return &c, nil
}

// Validate reports the first thing wrong with the list.
func (c *ProductList) Validate() error {
	if !slices.Contains(Currencies, c.Currency) {
		return fmt.Errorf("currency must be one of %v", Currencies)
	}
	if len(c.Packages) == 0 {
		return errors.New("at least one package is required")
	}
	// Packages, add-ons, and intervals share one key space: all of them become Stripe lookup keys.
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
	explicit := false
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
		if !slices.Contains(StoreScopes, p.StoreScope) {
			return fmt.Errorf("package %s: store_scope must be one of %v", p.Key, StoreScopes)
		}
		if p.StoreScope == StoreScopeExplicit && p.IncludedStores < 1 {
			return fmt.Errorf("package %s: included_stores must be at least 1 for an explicit scope", p.Key)
		}
		if p.StoreScope != StoreScopeExplicit && p.IncludedStores != 0 {
			return fmt.Errorf("package %s: included_stores applies to an explicit scope only", p.Key)
		}
		explicit = explicit || p.StoreScope == StoreScopeExplicit
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
		if err := uniqueList("addon "+a.Key+" applies_to", a.AppliesTo, c.hasPackage, "a known package"); err != nil {
			return err
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
	if err := uniqueList("included_games", c.IncludedGames, gamePattern.MatchString, "a lowercase game name"); err != nil {
		return err
	}
	if err := c.validateStores(explicit); err != nil {
		return err
	}
	selectable := len(c.SelectableStores())
	for _, p := range c.Packages {
		if p.StoreScope == StoreScopeExplicit && p.IncludedStores > selectable {
			return fmt.Errorf("package %s: included_stores %d exceeds the %d selectable stores", p.Key, p.IncludedStores, selectable)
		}
	}
	return c.checkLookupKeyCollisions()
}

// validateStores checks keys, names, shorthands, and that an explicit
// package has something implied and something to pick.
func (c *ProductList) validateStores(explicit bool) error {
	if len(c.Stores) == 0 {
		return errors.New("stores is empty")
	}
	shorthandOwner := map[string]string{}
	implied, selectable := false, false
	for i, s := range c.Stores {
		if !storeKeyPattern.MatchString(s.Key) {
			return fmt.Errorf("store %q: key must be uppercase letters and digits", s.Key)
		}
		for _, prev := range c.Stores[:i] {
			if prev.Key == s.Key {
				return fmt.Errorf("duplicate store %q", s.Key)
			}
		}
		if s.Name == "" {
			return fmt.Errorf("store %s: name is empty", s.Key)
		}
		if err := uniqueList("store "+s.Key+" shorthands", s.Shorthands, isToken, "a shorthand with no comma or whitespace"); err != nil {
			return err
		}
		for _, sh := range s.Shorthands {
			if owner, ok := shorthandOwner[sh]; ok {
				return fmt.Errorf("shorthand %q belongs to both %s and %s", sh, owner, s.Key)
			}
			shorthandOwner[sh] = s.Key
		}
		implied = implied || s.Implied
		selectable = selectable || !s.Implied
	}
	if explicit && !implied {
		return errors.New("an explicit package needs an implied store")
	}
	if explicit && !selectable {
		return errors.New("an explicit package needs a selectable store")
	}
	return nil
}

// checkLookupKeyCollisions reports when two items and intervals produce the same Stripe lookup key.
func (c *ProductList) checkLookupKeyCollisions() error {
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

// validateModes checks a package lists known modes once each, in canonical order.
func validateModes(key string, modes []string) error {
	field := "package " + key + " modes"
	if err := uniqueList(field, modes, isMode, "one of "+fmt.Sprint(Modes)); err != nil {
		return err
	}
	last := -1
	for _, m := range modes {
		i := slices.Index(Modes, m)
		if i < last {
			return fmt.Errorf("%s: must be listed in the order %v", field, Modes)
		}
		last = i
	}
	return nil
}

// uniqueList checks a list is non-empty, every entry passes ok, and none repeats.
func uniqueList(field string, items []string, ok func(string) bool, want string) error {
	if len(items) == 0 {
		return fmt.Errorf("%s is empty", field)
	}
	for i, s := range items {
		if !ok(s) {
			return fmt.Errorf("%s: %q must be %s", field, s, want)
		}
		if slices.Contains(items[:i], s) {
			return fmt.Errorf("%s: duplicate %q", field, s)
		}
	}
	return nil
}

func isMode(m string) bool {
	return slices.Contains(Modes, m)
}

// isToken accepts a value that survives comma-joining into metadata and signatures.
func isToken(s string) bool {
	return s != "" && !strings.ContainsRune(s, ',') && strings.IndexFunc(s, unicode.IsSpace) < 0
}

func (c *ProductList) hasPackage(key string) bool {
	_, ok := c.Package(key)
	return ok
}

// Package returns the package with that key.
func (c *ProductList) Package(key string) (Package, bool) {
	for _, p := range c.Packages {
		if p.Key == key {
			return p, true
		}
	}
	return Package{}, false
}

// Addon returns the add-on with that key.
func (c *ProductList) Addon(key string) (Addon, bool) {
	for _, a := range c.Addons {
		if a.Key == key {
			return a, true
		}
	}
	return Addon{}, false
}

// Interval returns the interval with that key.
func (c *ProductList) Interval(key string) (Interval, bool) {
	for _, iv := range c.Intervals {
		if iv.Key == key {
			return iv, true
		}
	}
	return Interval{}, false
}

// Store returns the store with that key.
func (c *ProductList) Store(key string) (Store, bool) {
	for _, s := range c.Stores {
		if s.Key == key {
			return s, true
		}
	}
	return Store{}, false
}

// PublicIntervals returns the intervals a customer may pick without an invite.
func (c *ProductList) PublicIntervals() []Interval {
	var out []Interval
	for _, iv := range c.Intervals {
		if iv.Public {
			out = append(out, iv)
		}
	}
	return out
}

// ImpliedStores returns the stores every explicit-scope package includes.
func (c *ProductList) ImpliedStores() []Store {
	var out []Store
	for _, s := range c.Stores {
		if s.Implied {
			out = append(out, s)
		}
	}
	return out
}

// SelectableStores returns the stores a customer may pick on an explicit-scope package.
func (c *ProductList) SelectableStores() []Store {
	var out []Store
	for _, s := range c.Stores {
		if !s.Implied {
			out = append(out, s)
		}
	}
	return out
}

// Applies reports whether the add-on can be attached to the package.
func (a Addon) Applies(packageKey string) bool {
	return slices.Contains(a.AppliesTo, packageKey)
}

// Amount is the charge per billing period for a monthly amount.
func (iv Interval) Amount(monthly int64) (int64, error) {
	if iv.Interval == "month" {
		return monthly * iv.Count, nil
	}
	return 0, fmt.Errorf("apiproductlist: interval %s: unsupported unit %q", iv.Key, iv.Interval)
}

// LookupKey is the Stripe lookup_key for an item billed at an interval.
// Consumers look prices up by the whole key and never split it; Validate
// rejects any two item and interval pairs that would produce the same key.
func LookupKey(itemKey, intervalKey string) string {
	return itemKey + "_" + intervalKey
}
