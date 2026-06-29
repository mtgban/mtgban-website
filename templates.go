package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

var funcMap = template.FuncMap{
	"inc": func(i, j int) int {
		return i + j
	},
	"dec": func(i, j int) int {
		return i - j
	},
	"mul": func(i float64, j int) float64 {
		return i * float64(j)
	},
	"mulf": func(i, j float64) float64 {
		return i * j
	},
	"print_perc": func(s string) string {
		n, _ := strconv.ParseFloat(s, 64)
		return fmt.Sprintf("%0.2f %%", n*100)
	},
	"perc_class": func(s string) string {
		n, _ := strconv.ParseFloat(s, 64)
		if n > 0 {
			return "news-perc-up"
		}
		if n < 0 {
			return "news-perc-down"
		}
		return "news-perc-zero"
	},
	"print_price": func(s string) string {
		n, _ := strconv.ParseFloat(s, 64)
		return fmt.Sprintf("$ %0.2f", n)
	},
	"scraper_name": func(s string) string {
		return scraperName(s)
	},
	"strip_edition": func(name, edition string, sealed bool) string {
		if !sealed || edition == "" {
			return name
		}
		if strings.HasPrefix(name, edition) {
			shortened := strings.TrimPrefix(name, edition)
			shortened = strings.TrimLeft(shortened, " :-–—")
			if shortened != "" {
				return shortened
			}
		}
		return name
	},
	"slug": func(s string) string {
		s = strings.ToLower(s)
		s = strings.ReplaceAll(s, " ", "-")
		var b strings.Builder
		for _, r := range s {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				b.WriteRune(r)
			}
		}
		return b.String()
	},
	"slice_has": func(s []string, p string) bool {
		return slices.Contains(s, p)
	},
	"has_prefix": func(s, p string) bool {
		return strings.HasPrefix(s, p)
	},
	"contains": func(s, p string) bool {
		return strings.Contains(s, p)
	},
	"is_sealed_scraper": func(shorthand string) bool {
		for _, seller := range GetSellers() {
			if seller != nil && seller.Info().Shorthand == shorthand {
				return seller.Info().SealedMode
			}
		}
		for _, vendor := range GetVendors() {
			if vendor != nil && vendor.Info().Shorthand == shorthand {
				return vendor.Info().SealedMode
			}
		}
		return false
	},
	"triple_column_start": func(i int, length int) bool {
		return i == 0 || i == length/3 || i == length*2/3
	},
	"triple_column_end": func(i int, length int) bool {
		return i == length/3-1 || i == length*2/3-1 || i == length-1
	},
	"load_partner": func(s string) string {
		return Config.Affiliate[s]
	},
	"game_title": func() string {
		return gameMap[Config.Game]
	},
	// amazon_search_url builds a game-aware Amazon Associates search link
	// (e.g. ?k=Magic:+The+Gathering). Amazon's Associates policy flags
	// linking to a bare storefront/browse-node with no product, so this
	// lands on real product results instead. The affiliate tag is appended
	// when configured.
	"amazon_search_url": func() string {
		keyword := gameMap[Config.Game]
		if keyword == "" {
			keyword = "trading card games"
		}
		link := "https://www.amazon.com/s?k=" + url.QueryEscape(keyword)
		if tag := Config.Affiliate["AMZN"]; tag != "" {
			link += "&tag=" + url.QueryEscape(tag)
		}
		return link
	},
	"uuid2ckid": func(s string) string {
		bl, err := findVendorBuylist("CK")
		if err != nil {
			return ""
		}
		entries, found := bl[s]
		if !found {
			return ""
		}
		return entries[0].OriginalId
	},
	"uuid2tcgid": func(s string) string {
		return findTCGproductId(s)
	},
	"isSussy": func(m map[string]float64, s string) bool {
		_, found := m[s]
		return found
	},
	"invalid_direct": invalidDirect,
	"color2hex": func(s string) string {
		color, found := colorValues[s]
		if !found {
			return "#111111"
		}
		return color
	},
	"credit_factor": findCredit,
	"tcg_market_price": func(s string) float64 {
		return getTCGMarketPrice(s)
	},
	// buylist_badge renders Card Kingdom's 3-month hotlist star next to the store
	// name when the store is the card's hotlist store, otherwise "".
	"buylist_badge": func(shorthand, hotlistStore string) template.HTML {
		if shorthand == hotlistStore {
			return template.HTML(` <span class="emoji" title="Highest price in 3 months">&#127775;</span>`)
		}
		return ""
	},
	"base64enc": func(s string) string {
		return base64.StdEncoding.EncodeToString([]byte(s))
	},
	"sixMonthsAgo": func(t time.Time) bool {
		sixMonthsAgo := time.Now().AddDate(0, -6, 0)
		return sixMonthsAgo.After(t)
	},
	"uuid2edition": func(s string) string {
		return editionTitle(s)
	},
	"is_best_price": func(prices map[string]float64, store string, storeKeys []string, isBuylist bool) bool {
		target := prices[store]
		if target == 0 {
			return false
		}
		for _, key := range storeKeys {
			price := prices[key]
			if price == 0 {
				continue
			}
			if !isBuylist && price > target {
				return false
			}
			if isBuylist && price < target {
				return false
			}
		}
		return true
	},
	"palette_newspaper_targets": paletteNewspaperTargetsJSON,
	"palette_sleepers_targets":  paletteSleepersTargetsJSON,
	"palette_arbit_targets":     func() template.JS { return paletteArbitTargetsJSON("arbit") },
	"palette_reverse_targets":   func() template.JS { return paletteArbitTargetsJSON("reverse") },
	"palette_global_targets":    func() template.JS { return paletteArbitTargetsJSON("global") },
	"guide_stores":              guideStoresJSON,
	"dict": func(values ...interface{}) (map[string]interface{}, error) {
		if len(values)%2 != 0 {
			return nil, errors.New("dict requires even number of args")
		}
		m := make(map[string]interface{}, len(values)/2)
		for i := 0; i < len(values); i += 2 {
			k, ok := values[i].(string)
			if !ok {
				return nil, errors.New("dict keys must be strings")
			}
			m[k] = values[i+1]
		}
		return m, nil
	},
}
