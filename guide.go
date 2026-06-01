package main

import (
	"encoding/json"
	"html/template"
	"net/http"
)

func Guide(w http.ResponseWriter, r *http.Request) {
	sig := getSignatureFromCookies(r)
	pageVars := genPageNav("Guide", sig)
	pageVars.IsMobile = isMobileRequest(r)
	if pageVars.IsMobile {
		pageVars.Nav = filterNavForMobile(pageVars.Nav)
	}
	render(w, "guide.html", pageVars)
}

// GuideStore is one store entry exposed to the guide page so the
// store-shorthand reference stays in sync with the registered scrapers.
type GuideStore struct {
	Name    string `json:"name"`
	Code    string `json:"code"`
	Retail  bool   `json:"retail"`
	Buylist bool   `json:"buylist"`
	Index   bool   `json:"index"`
	Sealed  bool   `json:"sealed"`
}

// guideStoresJSON returns every registered store shorthand with its role
// markers, sorted by display name. The full set is always emitted: any
// shorthand is valid syntax regardless of tier, which only gates results.
func guideStoresJSON() template.JS {
	stores := map[string]*GuideStore{}

	ensure := func(name, shorthand string, sealed bool) *GuideStore {
		s := stores[shorthand]
		if s == nil {
			s = &GuideStore{Name: name, Code: shorthand, Sealed: sealed}
			stores[shorthand] = s
		}
		return s
	}

	for _, seller := range GetSellers() {
		if seller == nil {
			continue
		}
		info := seller.Info()
		s := ensure(info.Name, info.Shorthand, info.SealedMode)
		if info.MetadataOnly {
			s.Index = true
		} else {
			s.Retail = true
		}
	}
	for _, vendor := range GetVendors() {
		if vendor == nil {
			continue
		}
		info := vendor.Info()
		s := ensure(info.Name, info.Shorthand, info.SealedMode)
		s.Buylist = true
	}

	keys := make([]string, 0, len(stores))
	for k := range stores {
		keys = append(keys, k)
	}
	keys = sortKeysByScraperName(keys)

	out := make([]*GuideStore, 0, len(keys))
	for _, k := range keys {
		out = append(out, stores[k])
	}

	data, _ := json.Marshal(out)
	return template.JS(data)
}
