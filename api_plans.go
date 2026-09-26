package main

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/apiproductlist"
)

// apiProducts is the embedded price list, validated by its own package tests.
var apiProducts = apiproductlist.MustLoad()

// APIPlansVars is what api-plans.html renders beyond the shared PageVars.
type APIPlansVars struct {
	Products   *apiproductlist.ProductList
	GatewayURL string
	// Cards is the packages in podium order; TopCard is the one on the podium step.
	Cards   []apiproductlist.Package
	TopCard string
	// Default is the package checked on arrival: the top card, so the fullest
	// package is what the page opens on.
	Default        apiproductlist.Package
	DefaultPackage string
	// DefaultExplicit is true when the package on arrival lets the reader pick stores.
	DefaultExplicit bool
	// ExtraGameMonthly is the add-on price for a game past the included count, in cents.
	ExtraGameMonthly int64
	// ExtraStoreMonthly is the add-on price for a store past the included count, in cents.
	ExtraStoreMonthly int64
	Games             []APIPlanGame
	ReturnTo          string
	Invite            string
	// Change is set when the account page sent the reader here to change a plan
	Change bool
	// Email is the signed-in reader, empty for anonymous
	Email    string
	CanTrial bool
	// HandoffOn is true when this site can send this reader through the gateway handoff.
	HandoffOn bool
	// Stores are the selectable families this site carries, in list order.
	Stores []apiproductlist.Store

	// TrialDays must match the gateway's trial_days config.
	TrialDays int
}

// APIPlanGame is one game checkbox in the configurator.
type APIPlanGame struct {
	Key     string
	Name    string
	Checked bool
}

// APIPlans renders the public pricing page and configurator, and serves the
// handoff sub-pages that hang off it.
func APIPlans(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api-trial":
		APITrial(w, r)
		return
	case "/api-login":
		APILogin(w, r)
		return
	}
	// The page may be served without enforceSigning, so only a verified signature names the reader.
	sig := verifiedSignature(r)
	pageVars := genPageNav(r, "API", sig)
	pageVars.IsMobile = isMobileRequest(r)
	if pageVars.IsMobile {
		pageVars.Nav = filterNavForMobile(pageVars.Nav)
	}
	pageVars.API = apiPlansVars(r, sig)
	render(w, "api-plans.html", pageVars)
}

// apiPlansVars gathers what the page and its configurator need.
func apiPlansVars(r *http.Request, sig string) *APIPlansVars {
	origin := requestOrigin(r)
	if origin == "" {
		origin = DefaultExternalURL
	}
	invite := r.FormValue("invite")
	change := r.FormValue("change") == "1"
	// return_to carries invite and change so a checkout bounce back keeps the reader's context.
	returnTo := origin + "/api-plans"
	rv := url.Values{}
	if invite != "" {
		rv.Set("invite", invite)
	}
	if change {
		rv.Set("change", "1")
	}
	if len(rv) > 0 {
		returnTo += "?" + rv.Encode()
	}
	v := &APIPlansVars{
		Products:   apiProducts,
		GatewayURL: Config.APIGateway.URL,
		ReturnTo:   returnTo,
		Invite:     invite,
		Change:     change,
		Email:      GetParamFromSig(sig, "UserEmail"),
		TrialDays:  15,
	}
	v.Cards, v.TopCard = podiumOrder(apiProducts.Packages)
	v.Stores = siteStores(apiProducts)
	if change {
		v.Stores = paidStores(apiProducts, v.Stores, r.URL.Query()["stores"])
	}
	v.Default = apiProducts.Packages[0]
	for _, p := range apiProducts.Packages {
		if p.Key == v.TopCard {
			v.Default = p
		}
	}
	// A change link names the package the reader is on, so the form opens on it.
	if p, ok := apiProducts.Package(r.FormValue("package")); ok {
		v.Default = p
	}
	v.DefaultPackage = v.Default.Key
	v.DefaultExplicit = v.Default.StoreScope == apiproductlist.StoreScopeExplicit
	if a, ok := apiProducts.Addon("extra_game"); ok {
		v.ExtraGameMonthly = a.Monthly
	}
	if a, ok := apiProducts.Addon("extra_store"); ok {
		v.ExtraStoreMonthly = a.Monthly
	}
	// The gateway signs in whoever the email names, so Patreon must have confirmed it.
	emailOK := v.Email != "" && GetParamFromSig(sig, "UserEmailUnverified") != "true"
	v.HandoffOn = emailOK && apiGatewaySecret() != ""
	v.CanTrial = v.HandoffOn && GetParamFromSig(sig, "UserTier") != ""
	// The site's own game is preselected; the base price covers one game of the buyer's choice.
	for _, g := range Config.APIGateway.Games {
		v.Games = append(v.Games, APIPlanGame{Key: g, Name: mtgmatcher.Title(g), Checked: g == Config.Game})
	}
	return v
}

// siteStores keeps the selectable families with at least one shorthand this
// site is configured to load. With nothing configured it falls back to the
// served snapshot, and with nothing loaded either (tests, a cold start) it
// keeps them all rather than offer an empty row.
func siteStores(cat *apiproductlist.ProductList) []apiproductlist.Store {
	carried := configuredShorthands()
	if len(carried) == 0 {
		carried = loadedShorthands()
	}
	all := cat.SelectableStores()
	if len(carried) == 0 {
		return all
	}
	var out []apiproductlist.Store
	for _, st := range all {
		for _, sh := range st.Shorthands {
			if carried[strings.ToLower(sh)] {
				out = append(out, st)
				break
			}
		}
	}
	if len(out) == 0 {
		return all
	}
	return out
}

// configuredShorthands are the scrapers the site boots with, lowercased the
// way isConfiguredScraper compares them.
func configuredShorthands() map[string]bool {
	out := map[string]bool{}
	for _, sections := range Config.ScraperConfig.Config {
		for _, list := range sections {
			for _, sh := range list {
				out[strings.ToLower(sh)] = true
			}
		}
	}
	return out
}

// loadedShorthands are the scrapers currently served, session uploads included.
func loadedShorthands() map[string]bool {
	out := map[string]bool{}
	for _, s := range GetSellers() {
		out[strings.ToLower(s.Info().Shorthand)] = true
	}
	for _, v := range GetVendors() {
		out[strings.ToLower(v.Info().Shorthand)] = true
	}
	return out
}

// paidStores adds back the families named in the request's stores query, so a
// store the reader already pays for is always offered.
func paidStores(cat *apiproductlist.ProductList, stores []apiproductlist.Store, query []string) []apiproductlist.Store {
	want := map[string]bool{}
	for _, field := range query {
		for _, key := range strings.Split(field, ",") {
			if key = strings.ToUpper(strings.TrimSpace(key)); key != "" {
				want[key] = true
			}
		}
	}
	if len(want) == 0 {
		return stores
	}
	have := map[string]bool{}
	for _, st := range stores {
		have[st.Key] = true
	}
	var out []apiproductlist.Store
	for _, st := range cat.SelectableStores() {
		if have[st.Key] || want[st.Key] {
			out = append(out, st)
		}
	}
	return out
}

// podiumOrder puts the priciest package in the middle with the runner-up on
// its left: 500, 800, 200 for the three-package list. Fewer or more packages
// stay in ascending order. The second result is the key of the middle card.
func podiumOrder(packages []apiproductlist.Package) ([]apiproductlist.Package, string) {
	sorted := slices.Clone(packages)
	slices.SortStableFunc(sorted, func(a, b apiproductlist.Package) int {
		return int(a.Monthly - b.Monthly)
	})
	if len(sorted) != 3 {
		return sorted, ""
	}
	return []apiproductlist.Package{sorted[1], sorted[2], sorted[0]}, sorted[2].Key
}

// apiPlansJSON is the configurator's data: every amount the client total needs.
func apiPlansJSON(v *APIPlansVars) template.JS {
	if v == nil {
		return "null"
	}
	type pkg struct {
		Key            string `json:"key"`
		Name           string `json:"name"`
		Monthly        int64  `json:"monthly"`
		Explicit       bool   `json:"explicit"`
		IncludedStores int    `json:"includedStores"`
	}
	type interval struct {
		Key   string `json:"key"`
		Count int64  `json:"count"`
	}
	out := struct {
		Packages      []pkg            `json:"packages"`
		Addons        map[string]int64 `json:"addons"`
		Intervals     []interval       `json:"intervals"`
		IncludedGames int              `json:"includedGames"`
	}{Addons: map[string]int64{}, IncludedGames: v.Products.IncludedGames}
	for _, p := range v.Products.Packages {
		out.Packages = append(out.Packages, pkg{p.Key, p.Name, p.Monthly, p.StoreScope == apiproductlist.StoreScopeExplicit, p.IncludedStores})
	}
	for _, a := range v.Products.Addons {
		out.Addons[a.Key] = a.Monthly
	}
	for _, iv := range v.Products.Intervals {
		out.Intervals = append(out.Intervals, interval{iv.Key, iv.Count})
	}
	data, err := json.Marshal(out)
	if err != nil {
		return "null"
	}
	return template.JS(data)
}

// tierIcons are the pricing page's tier marks, keyed by the catalog's icon
// names. Paths are from Lucide (ISC). An unknown name draws a dot.
var tierIcons = map[string]string{
	"globe":   `<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>`,
	"crown":   `<path d="M11.562 3.266a.5.5 0 0 1 .876 0L15.39 8.87a1 1 0 0 0 1.516.294L21.183 5.5a.5.5 0 0 1 .798.519l-2.834 10.246a1 1 0 0 1-.956.734H5.81a1 1 0 0 1-.957-.734L2.02 6.02a.5.5 0 0 1 .798-.519l4.276 3.664a1 1 0 0 0 1.516-.294z"/><path d="M5 21h14"/>`,
	"sliders": `<line x1="21" x2="14" y1="4" y2="4"/><line x1="10" x2="3" y1="4" y2="4"/><line x1="21" x2="12" y1="12" y2="12"/><line x1="8" x2="3" y1="12" y2="12"/><line x1="21" x2="16" y1="20" y2="20"/><line x1="12" x2="3" y1="20" y2="20"/><line x1="14" x2="14" y1="2" y2="6"/><line x1="8" x2="8" y1="10" y2="14"/><line x1="16" x2="16" y1="18" y2="22"/>`,
}

// planIcon renders a tier icon as inline SVG.
func planIcon(name string) template.HTML {
	paths, ok := tierIcons[name]
	if !ok {
		paths = `<circle cx="12" cy="12" r="4"/>`
	}
	return template.HTML(`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">` + paths + `</svg>`)
}

// formatUSD renders cents as $200, $1,500, or $12.50.
func formatUSD(cents int64) string {
	dollars := strconv.FormatInt(cents/100, 10)
	for i := len(dollars) - 3; i > 0; i -= 3 {
		dollars = dollars[:i] + "," + dollars[i:]
	}
	if cents%100 == 0 {
		return "$" + dollars
	}
	return "$" + dollars + "." + strconv.FormatInt(100+cents%100, 10)[1:]
}
