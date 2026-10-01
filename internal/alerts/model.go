// Package alerts holds the price alert model, its Postgres store and the
// pure evaluator that decides when an alert fires.
package alerts

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
)

// maxAmount is the largest price-like value Validate accepts; the
// NUMERIC(10,2) columns overflow at 10^8.
const maxAmount = 1e8

// roundCents rounds a float to the cent NUMERIC(10,2) columns store.
func roundCents(v float64) float64 { return math.Round(v*100) / 100 }

// Side is which market an alert watches.
type Side string

// Sides an alert can watch.
const (
	SideRetail  Side = "retail"
	SideBuylist Side = "buylist"
)

// Kind is how a threshold value is read.
type Kind string

// Threshold kinds.
const (
	KindAbs Kind = "abs"
	KindPct Kind = "pct"
)

// Status is an alert's lifecycle state; the user sets the first two.
type Status string

// Alert statuses; the user sets the first two.
const (
	StatusActive        Status = "active"
	StatusPaused        Status = "paused"
	StatusOverAllowance Status = "over_allowance"
	StatusUndeliverable Status = "undeliverable"
	StatusUnresolvable  Status = "unresolvable"
)

// Delivery is the channel an alert fires on; email is reserved.
type Delivery string

// Delivery channels; email is reserved.
const (
	DeliveryDiscord Delivery = "discord"
	DeliveryEmail   Delivery = "email"
)

// Conditions is every grade an alert may compare, best first.
var Conditions = []string{"NM", "SP", "MP", "HP", "PO"}

// Threshold is one side of an alert; an empty Kind means unset.
type Threshold struct {
	Kind  Kind    `json:"kind,omitempty"`
	Value float64 `json:"value,omitempty"`
}

// Set reports whether the threshold is in use.
func (t Threshold) Set() bool { return t.Kind != "" }

// Resolve is the price the threshold stands at against reference.
func (t Threshold) Resolve(reference float64, above bool) float64 {
	switch t.Kind {
	case KindAbs:
		return t.Value
	case KindPct:
		x := reference * (1 - t.Value/100)
		if above {
			x = reference * (1 + t.Value/100)
		}
		// Round to cents so an exact-cent target is not missed by float error.
		return roundCents(x)
	}
	return 0
}

// Contact is what the evaluator knows about a user beyond their alerts.
type Contact struct {
	UserHash string
	// DiscordKnown is true when this login's Patreon answer had an opinion
	// (linked or explicitly unlinked) about the Discord id, false when the
	// field could not be read; only a known, verified login may change it.
	DiscordKnown  bool
	DiscordUserID string
	Tier          string
	UpdatedAt     time.Time
}

// Card is the display snapshot kept on the row.
type Card struct {
	Name   string `json:"name"`
	Set    string `json:"set"`
	Number string `json:"number"`
	Finish string `json:"finish"`
}

// Alert is one saved alert.
type Alert struct {
	ID             int64      `json:"id"`
	UserHash       string     `json:"-"`
	Game           string     `json:"game"`
	CardID         string     `json:"card_id"`
	Side           Side       `json:"side"`
	Condition      string     `json:"condition"`
	Stores         []string   `json:"stores"`
	ReferencePrice float64    `json:"reference_price"`
	Above          Threshold  `json:"above"`
	Below          Threshold  `json:"below"`
	Delivery       Delivery   `json:"delivery"`
	Status         Status     `json:"status"`
	AboveArmed     bool       `json:"above_armed"`
	BelowArmed     bool       `json:"below_armed"`
	LastFiredAt    *time.Time `json:"last_fired_at,omitempty"`
	LastError      string     `json:"last_error,omitempty"`
	Card           Card       `json:"card"`
	CreatedPrice   *float64   `json:"created_price,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	// Origin is the site the alert was last saved on, which its DM links
	// to; empty leaves the links out.
	Origin string `json:"-"`
}

// State is what the evaluator writes back on a row.
type State struct {
	Status      Status
	AboveArmed  bool
	BelowArmed  bool
	LastFiredAt *time.Time
	LastError   string
}

// Event is one firing, delivered or not.
type Event struct {
	ID        int64     `json:"id"`
	AlertID   int64     `json:"alert_id"`
	FiredAt   time.Time `json:"fired_at"`
	Threshold string    `json:"threshold"`
	Store     string    `json:"store"`
	Price     float64   `json:"price"`
	Delivered bool      `json:"delivered"`
	Error     string    `json:"error,omitempty"`
}

// validate rounds Value to cents in place, then checks it.
func (t *Threshold) validate(name string, below bool) error {
	if !t.Set() {
		return nil
	}
	if t.Kind != KindAbs && t.Kind != KindPct {
		return fmt.Errorf("%s: unknown kind %q", name, t.Kind)
	}
	err := validateAmount(name, t.Value)
	if err != nil {
		return err
	}
	t.Value = roundCents(t.Value)
	if t.Value <= 0 {
		return fmt.Errorf("%s: value must be above zero", name)
	}
	if below && t.Kind == KindPct && t.Value >= 100 {
		return errors.New("below: a percentage must be under 100")
	}
	return nil
}

// validateAmount rejects a non-finite or overflowing amount before rounding.
func validateAmount(name string, v float64) error {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return fmt.Errorf("%s: value is not finite", name)
	}
	if v >= maxAmount || v <= -maxAmount {
		return fmt.Errorf("%s: value too large", name)
	}
	return nil
}

// Validate checks the user-editable fields, rounding price-like fields to
// cents in place first.
func (a *Alert) Validate() error {
	if a.CardID == "" {
		return errors.New("card is required")
	}
	if a.Side != SideRetail && a.Side != SideBuylist {
		return fmt.Errorf("unknown side %q", a.Side)
	}
	if !slices.Contains(Conditions, a.Condition) {
		return fmt.Errorf("unknown condition %q", a.Condition)
	}
	if a.Delivery != DeliveryDiscord && a.Delivery != DeliveryEmail {
		return fmt.Errorf("unknown delivery %q", a.Delivery)
	}
	err := validateAmount("reference price", a.ReferencePrice)
	if err != nil {
		return err
	}
	a.ReferencePrice = roundCents(a.ReferencePrice)
	if a.ReferencePrice <= 0 {
		return errors.New("reference price must be above zero")
	}
	if !a.Above.Set() && !a.Below.Set() {
		return errors.New("at least one threshold is required")
	}
	err = a.Above.validate("above", false)
	if err != nil {
		return err
	}
	err = a.Below.validate("below", true)
	if err != nil {
		return err
	}
	if a.Above.Set() && a.Above.Kind == KindAbs && a.Above.Value <= a.ReferencePrice {
		return errors.New("above must be over the reference")
	}
	if a.Below.Set() && a.Below.Kind == KindAbs && a.Below.Value >= a.ReferencePrice {
		return errors.New("below must be under the reference")
	}

	seen := make(map[string]bool, len(a.Stores))
	stores := a.Stores[:0]
	for _, store := range a.Stores {
		store = strings.TrimSpace(store)
		if store == "" {
			return errors.New("blank store in the list")
		}
		key := strings.ToLower(store)
		if seen[key] {
			continue
		}
		seen[key] = true
		stores = append(stores, store)
	}
	a.Stores = stores
	return nil
}
