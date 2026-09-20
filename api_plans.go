package main

import (
	"encoding/json"
	"html/template"
	"net/http"
	"os"
	"slices"
	"strconv"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/apiproductlist"
)

// apiProducts is the embedded price list, validated by its own package tests.
var apiProducts = apiproductlist.MustLoad()

// Amounts quoted on the page that Stripe does not sell, in cents, from issue #230.
const (
	patreonBundleMonthly  = 100000
	velocityMonthly       = 100000
	velocityBundleMonthly = 150000
)

// APIPlansVars is what api-plans.html renders beyond the shared PageVars.
type APIPlansVars struct {
	Products   *apiproductlist.ProductList
	GatewayURL string
	Games      []APIPlanGame
	ReturnTo   string
	Invite     string
	// Change is set when the account page sent the reader here to change a plan
	Change bool
	// Email is the signed-in reader, empty for anonymous
	Email    string
	CanTrial bool

	PatreonBundle  int64
	Velocity       int64
	VelocityBundle int64
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
	v := &APIPlansVars{
		Products:       apiProducts,
		GatewayURL:     Config.APIGateway.URL,
		ReturnTo:       origin + "/api-plans",
		Invite:         r.FormValue("invite"),
		Change:         r.FormValue("change") == "1",
		Email:          GetParamFromSig(sig, "UserEmail"),
		PatreonBundle:  patreonBundleMonthly,
		Velocity:       velocityMonthly,
		VelocityBundle: velocityBundleMonthly,
	}
	v.CanTrial = v.Email != "" && GetParamFromSig(sig, "UserTier") != "" && os.Getenv("TRIAL_SECRET") != ""
	for _, g := range Config.APIGateway.Games {
		included := slices.Contains(apiProducts.IncludedGames, g)
		v.Games = append(v.Games, APIPlanGame{Key: g, Name: mtgmatcher.Title(g), Included: included, Checked: included || g == Config.Game})
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
		Packages      []pkg               `json:"packages"`
		Addons        map[string]int64    `json:"addons"`
		AddonApplies  map[string][]string `json:"addonApplies"`
		Intervals     []interval          `json:"intervals"`
		IncludedGames int                 `json:"includedGames"`
	}{Addons: map[string]int64{}, AddonApplies: map[string][]string{}, IncludedGames: len(v.Products.IncludedGames)}
	for _, p := range v.Products.Packages {
		out.Packages = append(out.Packages, pkg{p.Key, p.Monthly, p.StoreScope == apiproductlist.StoreScopeExplicit, p.IncludedStores})
	}
	for _, a := range v.Products.Addons {
		out.Addons[a.Key] = a.Monthly
		out.AddonApplies[a.Key] = a.AppliesTo
	}
	for _, iv := range v.Products.Intervals {
		out.Intervals = append(out.Intervals, interval{iv.Key, iv.Count})
	}
	data, _ := json.Marshal(out)
	return template.JS(data)
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
