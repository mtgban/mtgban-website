package main

import (
	"cmp"
	"encoding/json"
	"html/template"
	"log"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/mtgban/go-mtgban/mtgban"
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
	// Stores are the selectable families this site serves, sorted by name.
	Stores []StoreFamily
	// ImpliedStores are the families every explicit package includes.
	ImpliedStores []StoreFamily
	// WantedStores are the family keys a change request names, checked on arrival.
	WantedStores []string
	// PaidStores are keys a change request names that this site no longer offers.
	PaidStores []string

	// TrialDays must match the gateway's trial_days config.
	TrialDays int
}

// StoreFamily is the config keys sharing a prefix and the shorthands of them this site serves.
type StoreFamily struct {
	Key        string   `json:"key"`
	Name       string   `json:"name"`
	Shorthands []string `json:"shorthands"`
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
	case "/api-plans/stores.json":
		APIStores(w, r)
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

// APIStores serves this site's store families for the gateway to price and resolve.
func APIStores(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// A cold start would serve a partial list, so the gateway keeps its last good one.
	if len(GetSellers()) == 0 || len(GetVendors()) == 0 {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusServiceUnavailable)
		if err := json.NewEncoder(w).Encode(map[string]string{"error": "Stores are still loading."}); err != nil {
			log.Println("api-plans stores.json:", err)
		}
		return
	}
	out := struct {
		Game    string        `json:"game"`
		Implied []StoreFamily `json:"implied"`
		Stores  []StoreFamily `json:"stores"`
	}{Game: Config.Game, Implied: []StoreFamily{}, Stores: []StoreFamily{}}
	implied, stores := storeFamilies()
	out.Implied = append(out.Implied, implied...)
	out.Stores = append(out.Stores, stores...)
	w.Header().Set("Cache-Control", "public, max-age=300")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		log.Println("api-plans stores.json:", err)
	}
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
	v.ImpliedStores, v.Stores = storeFamilies()
	if change {
		v.WantedStores = wantedStores(r.URL.Query()["stores"])
		v.PaidStores = paidStores(v.WantedStores, v.Stores)
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

// familyKeys maps each lowercased configured shorthand to its family key, the config key up to its first underscore.
func familyKeys() map[string]string {
	keyOf := map[string]string{}
	for _, key := range slices.Sorted(maps.Keys(Config.ScraperConfig.Config)) {
		if strings.HasSuffix(key, "_sealed") {
			continue
		}
		// tcg_index and tcg_market are both the tcg family.
		family, _, _ := strings.Cut(strings.ToLower(key), "_")
		for _, list := range Config.ScraperConfig.Config[key] {
			for _, sh := range list {
				if _, taken := keyOf[strings.ToLower(sh)]; !taken {
					keyOf[strings.ToLower(sh)] = family
				}
			}
		}
	}
	return keyOf
}

// storeFamilies groups the served scrapers by config key prefix, minus what the search blocklists hide.
func storeFamilies() (implied, selectable []StoreFamily) {
	keyOf := familyKeys()
	var families []*StoreFamily
	add := func(info mtgban.ScraperInfo, blocklist []string) {
		shorthand := info.Shorthand
		key, ok := keyOf[strings.ToLower(shorthand)]
		if !ok || info.SealedMode || !storeEligible(shorthand, nil, blocklist) {
			return
		}
		i := slices.IndexFunc(families, func(f *StoreFamily) bool { return f.Key == key })
		if i < 0 {
			families = append(families, &StoreFamily{Key: key})
			i = len(families) - 1
		}
		if !slices.Contains(families[i].Shorthands, shorthand) {
			families[i].Shorthands = append(families[i].Shorthands, shorthand)
		}
	}
	for _, seller := range GetSellers() {
		add(seller.Info(), Config.SearchRetailBlockList)
	}
	for _, vendor := range GetVendors() {
		add(vendor.Info(), Config.SearchBuylistBlockList)
	}
	for _, f := range families {
		slices.Sort(f.Shorthands)
		if f.Key == apiProducts.Implied.Key {
			f.Name = apiProducts.Implied.Name
			implied = append(implied, *f)
			continue
		}
		names := make([]string, 0, len(f.Shorthands))
		for _, sh := range f.Shorthands {
			if name := scraperName(sh); name != "" {
				names = append(names, name)
			}
		}
		name := familyName(names)
		if override, ok := Config.ScraperConfig.NameOverride[name]; ok {
			name = override
		}
		f.Name = cmp.Or(name, f.Key)
		selectable = append(selectable, *f)
	}
	slices.SortFunc(selectable, func(a, b StoreFamily) int {
		return cmp.Or(strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)), strings.Compare(a.Key, b.Key))
	})
	return implied, selectable
}

// familyName is the leading words every name shares, ignoring case, else the shortest name.
func familyName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	shortest := slices.MinFunc(names, func(a, b string) int {
		return cmp.Or(len(a)-len(b), strings.Compare(a, b))
	})
	words := strings.Fields(shortest)
	shared := len(words)
	for _, n := range names {
		other := strings.Fields(n)
		i := 0
		for i < shared && i < len(other) && strings.EqualFold(words[i], other[i]) {
			i++
		}
		shared = i
	}
	if shared == 0 {
		return shortest
	}
	return strings.Join(words[:shared], " ")
}

// wantedStores resolves a change request's stores query to family keys; the implied family is left out.
func wantedStores(query []string) []string {
	keyOf := familyKeys()
	served := map[string]bool{}
	for _, seller := range GetSellers() {
		served[strings.ToLower(seller.Info().Shorthand)] = true
	}
	for _, vendor := range GetVendors() {
		served[strings.ToLower(vendor.Info().Shorthand)] = true
	}
	families := map[string]bool{}
	for _, key := range keyOf {
		families[key] = true
	}
	var out []string
	for _, field := range query {
		for _, key := range strings.Split(field, ",") {
			key = strings.ToLower(strings.TrimSpace(key))
			// A legacy link names a served shorthand rather than its family.
			if family, ok := keyOf[key]; ok && served[key] && !families[key] {
				key = family
			}
			if key == "" || key == apiProducts.Implied.Key || slices.Contains(out, key) {
				continue
			}
			out = append(out, key)
		}
	}
	return out
}

// paidStores are wanted keys not on offer, so a store the customer pays for is kept.
func paidStores(wanted []string, offered []StoreFamily) []string {
	var out []string
	for _, key := range wanted {
		if !hasFamily(offered, key) {
			out = append(out, key)
		}
	}
	return out
}

// hasFamily reports whether a family with that key is listed.
func hasFamily(families []StoreFamily, key string) bool {
	return slices.ContainsFunc(families, func(f StoreFamily) bool { return f.Key == key })
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
		StoreKeys     []string         `json:"storeKeys,omitempty"`
	}{Addons: map[string]int64{}, IncludedGames: v.Products.IncludedGames, StoreKeys: v.WantedStores}
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
