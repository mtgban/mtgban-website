package main

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/apiproductlist"
)

// apiProducts is the embedded price list, validated by its own package tests.
var apiProducts = apiproductlist.MustLoad()

// Amounts quoted on the page that Stripe does not sell, in cents, from issue #230.
const (
	patreonBundleMonthly = 100000
)

// APIPlansVars is what api-plans.html renders beyond the shared PageVars.
type APIPlansVars struct {
	Products   *apiproductlist.ProductList
	GatewayURL string
	Games      []APIPlanGame
	// GameChoice is false when every configured game is included, so the games group hides.
	GameChoice bool
	ReturnTo   string
	Invite     string
	// Change is set when the account page sent the reader here to change a plan
	Change bool
	// Email is the signed-in reader, empty for anonymous
	Email    string
	CanTrial bool

	PatreonBundle int64

	// TrialDays must match the gateway's trial_days config.
	TrialDays int
}

// APIPlanGame is one game checkbox in the configurator.
type APIPlanGame struct {
	Key      string
	Name     string
	Included bool
	Checked  bool
}

// APIPlans renders the public pricing page and configurator.
func APIPlans(w http.ResponseWriter, r *http.Request) {
	sig := getSignatureFromCookies(r)
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
		Products:      apiProducts,
		GatewayURL:    Config.APIGateway.URL,
		ReturnTo:      returnTo,
		Invite:        invite,
		Change:        change,
		Email:         GetParamFromSig(sig, "UserEmail"),
		PatreonBundle: patreonBundleMonthly,
		TrialDays:     15,
	}
	v.CanTrial = v.Email != "" && GetParamFromSig(sig, "UserTier") != "" && os.Getenv("TRIAL_SECRET") != ""
	for _, g := range Config.APIGateway.Games {
		included := slices.Contains(apiProducts.IncludedGames, g)
		v.Games = append(v.Games, APIPlanGame{Key: g, Name: mtgmatcher.Title(g), Included: included, Checked: included || g == Config.Game})
		v.GameChoice = v.GameChoice || !included
	}
	return v
}

// apiPlansJSON is the configurator's data: every amount the client total needs.
func apiPlansJSON(v *APIPlansVars) template.JS {
	if v == nil {
		return "null"
	}
	type pkg struct {
		Key            string `json:"key"`
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
	}{Addons: map[string]int64{}}
	for _, p := range v.Products.Packages {
		out.Packages = append(out.Packages, pkg{p.Key, p.Monthly, p.StoreScope == apiproductlist.StoreScopeExplicit, p.IncludedStores})
	}
	for _, a := range v.Products.Addons {
		out.Addons[a.Key] = a.Monthly
	}
	for _, iv := range v.Products.Intervals {
		out.Intervals = append(out.Intervals, interval{iv.Key, iv.Count})
	}
	// Counts only the included games actually offered by this deployment's gateway.
	for _, g := range v.Games {
		if g.Included {
			out.IncludedGames++
		}
	}
	data, err := json.Marshal(out)
	if err != nil {
		return "null"
	}
	return template.JS(data)
}

// scopeBullets are the two price-card bullets for a package's store scope.
func scopeBullets(p apiproductlist.Package, cat *apiproductlist.ProductList) []string {
	var names []string
	for _, s := range cat.ImpliedStores() {
		names = append(names, s.Name)
	}
	implied := strings.Join(names, ", ")
	switch p.StoreScope {
	case apiproductlist.StoreScopeExplicit:
		first := "One store of your choice, " + implied + " always included"
		if p.IncludedStores != 1 {
			first = strconv.Itoa(p.IncludedStores) + " stores of your choice, " + implied + " always included"
		}
		return []string{first, "Add more stores as you need them"}
	case apiproductlist.StoreScopeBase:
		return []string{"Every EU and US store we track", "Singles only, no sealed product"}
	default:
		return []string{"Every store, every mode", "Sealed product included"}
	}
}

// addonScope names, from the catalog, which packages an addon applies to.
func addonScope(a apiproductlist.Addon, packages []apiproductlist.Package) string {
	covers := true
	var names []string
	for _, p := range packages {
		if slices.Contains(a.AppliesTo, p.Key) {
			names = append(names, p.Name)
		} else {
			covers = false
		}
	}
	if covers {
		return "on any package"
	}
	return "on the " + strings.Join(names, ", ") + " package"
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
