package observability

import (
	"slices"
	"strconv"
)

// Family says where a name is emitted from.
type Family int

// The families a name belongs to.
const (
	FamilyServer Family = iota
	FamilyUI
	FamilyState
	FamilyStock
)

// ValueKind says what a name's value may hold.
type ValueKind int

// The kinds of value a name takes.
const (
	ValueNone ValueKind = iota
	ValueEnum
	ValueBucket
	ValueStore
	ValueFlag
	ValuePage
	ValueSetting
	ValueOrigin
)

// ScopeKind says what a name's scope may hold.
type ScopeKind int

// The kinds of scope a name takes.
const (
	ScopeNone ScopeKind = iota
	ScopeRoute
	ScopePage
	ScopeEnum
	ScopeStore
	ScopeSetting
)

// ReportKind says how a report treats a name.
type ReportKind int

// The report treatments.
const (
	ReportCandidate ReportKind = iota
	ReportSignal
	ReportContext
	ReportInternal
)

// UnitKind says what one candidate is in a report.
type UnitKind int

// The candidate units.
const (
	UnitValue UnitKind = iota
	UnitScope
	UnitScopeAndValue
)

// Name is one thing the counter may count.
type Name struct {
	Name   string
	Family Family
	Values ValueKind
	Enum   []string
	Scope  ScopeKind
	Scopes []string
	Area   string
	Page   string // "", "*" or comma-separated page labels with no spaces
	Denom  string // a registered name; used instead of Page when set
	Report ReportKind
	Unit   UnitKind
	Kind   string
	Help   string
}

// Validators answers the checks the registry cannot make by itself.
type Validators struct {
	Store        func(string) bool
	Page         func(string) bool
	Route        func(string) bool
	Setting      func(string) bool
	SettingValue func(setting, value string) bool
	Origin       func(string) bool
}

var names = []Name{
	{Name: "metrics.flush", Report: ReportInternal, Help: "Counter flushes written to the database."},
	{Name: "metrics.dropped", Report: ReportInternal, Help: "Counts dropped because the counter was full."},
	{Name: "metrics.flush_fail", Report: ReportInternal, Help: "Counter flushes that failed."},
	{Name: "metrics.rejected", Report: ReportInternal, Help: "Counts the registry refused to store."},
	{Name: "page.view", Values: ValuePage, Report: ReportCandidate, Unit: UnitValue, Kind: "page", Area: "site", Help: "Page views, by page."},
	{Name: "http.status", Report: ReportContext, Values: ValueEnum, Enum: []string{"2xx", "3xx", "4xx", "5xx"}, Scope: ScopeRoute, Help: "Responses by status class, per route."},
	{Name: "http.duration", Report: ReportContext, Values: ValueBucket, Enum: []string{"<50ms", "<200ms", "<1s", "<5s", "5s+"}, Scope: ScopeRoute, Help: "Response time buckets, per route."},
	{Name: "auth.refuse", Report: ReportSignal, Area: "account", Values: ValueEnum, Enum: []string{"unauthenticated", "no_access", "rate_limited", "other"}, Scope: ScopeRoute, Help: "Requests refused at the door, by reason."},
	{Name: "ratelimit.reject", Report: ReportSignal, Area: "site", Values: ValueEnum, Enum: []string{"page", "api", "vote", "upload_share", "favorites_share", "userstate", "alerts", "alerts_confirm", "metrics"}, Help: "Requests a rate limiter refused, by limiter."},
}

var byName map[string]Name

func init() {
	byName = make(map[string]Name, len(names))
	for _, n := range names {
		byName[n.Name] = n
	}
}

// Lookup returns the registered name.
func Lookup(name string) (Name, bool) {
	n, ok := byName[name]
	return n, ok
}

// All returns every registered name.
func All() []Name {
	return slices.Clone(names)
}

func foldOther(f func(string) bool, s string) string {
	if f == nil || !f(s) {
		return "other"
	}
	return s
}

// Check returns the scope and value to store, or ok=false to reject.
func (n Name) Check(scope, value string, v Validators) (string, string, bool) {
	if n.Scope == ScopeNone {
		if scope != "" {
			return "", "", false
		}
	} else {
		if scope == "" {
			return "", "", false
		}
		switch n.Scope {
		case ScopeEnum:
			if !slices.Contains(n.Scopes, scope) {
				return "", "", false
			}
		case ScopeSetting:
			if v.Setting == nil || !v.Setting(scope) {
				return "", "", false
			}
		case ScopeRoute:
			scope = foldOther(v.Route, scope)
		case ScopePage:
			scope = foldOther(v.Page, scope)
		case ScopeStore:
			scope = foldOther(v.Store, scope)
		}
	}

	switch n.Values {
	case ValueNone:
		if value != "" {
			return "", "", false
		}
	case ValueEnum, ValueBucket:
		if !slices.Contains(n.Enum, value) {
			return "", "", false
		}
	case ValueFlag:
		if value != "on" && value != "off" {
			return "", "", false
		}
	case ValueSetting:
		if v.SettingValue == nil || !v.SettingValue(scope, value) {
			return "", "", false
		}
	case ValueStore:
		value = foldOther(v.Store, value)
	case ValuePage:
		value = foldOther(v.Page, value)
	case ValueOrigin:
		value = foldOther(v.Origin, value)
	}
	return scope, value, true
}

// Bucket names the range of edges that n falls in.
func Bucket(edges []int64, n int64) string {
	if len(edges) == 0 || n < edges[0] {
		return "0"
	}
	i := 0
	for i+1 < len(edges) && edges[i+1] <= n {
		i++
	}
	lo := strconv.FormatInt(edges[i], 10)
	if i == len(edges)-1 {
		return lo + "+"
	}
	if edges[i+1]-1 == edges[i] {
		return lo
	}
	return lo + "-" + strconv.FormatInt(edges[i+1]-1, 10)
}
