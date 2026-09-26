package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/mtgban/mtgban-website/internal/dsreload"

	"github.com/mtgban/mtgban-website/internal/palette"
	"github.com/mtgban/mtgban-website/observability"
)

// csvWithout returns csv with `drop` and any empty entries removed. Used by
// the templates to build "remove this card" URLs that strip one entry from the
// chart roster while keeping the rest in order.
// firstCSV joins the first n elements of keys into a comma-separated string,
// capping n at len(keys). Used to build the "chart the top results" link from
// the ordered result keys (AllKeys).
func firstCSV(keys []string, n int) string {
	if n > len(keys) {
		n = len(keys)
	}
	if n <= 0 {
		return ""
	}
	return strings.Join(keys[:n], ",")
}

func csvWithout(csv, drop string) string {
	parts := strings.Split(csv, ",")
	out := parts[:0]
	for _, p := range parts {
		if p != "" && p != drop {
			out = append(out, p)
		}
	}
	return strings.Join(out, ",")
}

const cardArtPlaceholder = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"

var funcMap = template.FuncMap{
	// A URL, or html/template rewrites the data: scheme in src to
	// #ZgotmplZ, which the browser fetches as the page's own address.
	"card_art_placeholder": func() template.URL {
		return template.URL(cardArtPlaceholder)
	},
	// jsonArray writes a list of strings for a script to read out of an
	// attribute. A list that cannot be written comes out as an empty one:
	// for the handoff page, whose attribute names who may hand it a card
	// list, that is a page listening to nobody rather than to everybody.
	// What a page documenting the upload may say about its size, read off
	// the handler's own constants rather than written out beside them.
	"uploadLimit":    func() int { return MaxUploadEntries },
	"uploadProLimit": func() int { return MaxUploadProEntries },
	"uploadMaxMB":    func() int { return MaxUploadFileSize >> 20 },
	"jsonArray": func(values []string) string {
		if values == nil {
			values = []string{}
		}
		encoded, err := json.Marshal(values)
		if err != nil {
			return "[]"
		}
		return string(encoded)
	},
	// The datastore reload runs in the background, so the page that reports
	// it asks at render time rather than being handed a copy that is stale
	// by the time it is drawn.
	"datastore_reload": func() dsreload.State {
		return datastoreReloads.Status()
	},
	// sourceLink answers with a URL a results row can be made clickable
	// with, or "" for a note that is not one.
	//
	// The notes column is whatever the uploaded file put in it, so only an
	// absolute http or https URL becomes a link and every other note stays
	// the text it is. html/template would refuse a javascript: href on its
	// own, but a note is not a link merely for being a string, and a row
	// whose note is a sentence should not look like one.
	"sourceLink": func(note string) string {
		parsed, err := url.Parse(strings.TrimSpace(note))
		if err != nil || parsed.Host == "" {
			return ""
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return ""
		}
		// Rebuilt rather than echoed, the same way the handoff link is:
		// Host excludes userinfo, so https://user:pass@host/... would get
		// this far and keep the credentials in the href, which a browser
		// may then send as Basic auth.
		clean := url.URL{
			Scheme:   parsed.Scheme,
			Host:     parsed.Host,
			Path:     parsed.Path,
			RawPath:  parsed.RawPath,
			RawQuery: parsed.RawQuery,
			Fragment: parsed.Fragment,
		}
		return clean.String()
	},
	"inc": func(i, j int) int {
		return i + j
	},
	"csv_without": csvWithout,
	"first_csv":   firstCSV,
	// Which of the three readings a sealed product's link opens, given what
	// the product holds and what the reader asked for in the settings
	"sealed_contents_filter": sealedContentsFilter,
	"dec": func(i, j int) int {
		return i - j
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
	"load_partner": func(s string) string {
		return Affiliates().Codes[s]
	},
	"game_title": func() string {
		return gameMap[Config.Game]
	},
	// game_badge names the game a deployment serves for the brand lockup,
	// where the wordmark alone says nothing about which site this is. Empty
	// on Magic, whose logo already reads MTGBAN.
	"game_badge": func() string {
		if Config.Game == DefaultGame {
			return ""
		}
		return gameBadgeMap[Config.Game]
	},
	// game is the slug the deployment serves, for the places that style or
	// address a game rather than name it.
	"game": func() string {
		return Config.Game
	},
	"card_back": func() string {
		return "/img/backs/" + Config.Game + ".webp"
	},
	// set_symbol hands the set-symbol block the image a set's cards print,
	// where the game publishes one to point at. Only Pokemon does, on most
	// of its sets; everywhere else this is empty and the block draws what
	// it drew before.
	"set_symbol": func(code string) string {
		set, err := backend().GetSet(code)
		if err != nil {
			return ""
		}
		return set.Symbol
	},
	// rarity_badge hands the set-symbol block the drawing for one rarity,
	// already sized for the code it has to hold.
	"rarity_badge": func(rarity, code string) rarityBadge {
		badge, found := rarityBadges[rarity]
		if !found {
			badge = rarityBadges[""]
		}
		return fitCode(badge, code)
	},
	// promo_label spells a raw promo type token ("galaxyfoil") the way a
	// page should show it ("Galaxy foil"). GenericCard carries the token
	// alone - a PromoTypes or Treatments entry - so a card row asks for the
	// spelling at render time rather than a Go field baking one in ahead of
	// it.
	"promo_label": promoTypeLabel,
	"uuid2ckid": func(s string) string {
		bl, err := findVendorBuylist("CK")
		if err != nil {
			return ""
		}
		entries, found := bl[s]
		if !found {
			return ""
		}
		return entries[0].OriginalID
	},
	"uuid2tcgid": func(s string) string {
		return findTCGproductID(s)
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
	// buylist_detail renders a card's precomputed Card Kingdom "Good" (P90) and
	// "Highest" (90-day) buylist prices (passed in) as small, labeled prices for a
	// dedicated column — the badge emoji itself lives next to the card name (see
	// buylist_badge). With always=false it returns "" unless the entry carries a
	// badge (store is the hotlist store, or the offer meets good); with always=true
	// it shows the prices whenever they exist.
	"buylist_detail": func(shorthand, hotlistStore string, price, good, highest float64, always bool) template.HTML {
		hasBadge := shorthand == hotlistStore || (good > 0 && price >= good)
		if !hasBadge && !always {
			return ""
		}
		prices := ""
		if good > 0 {
			// In always-show (optimizer) mode, tint Good by how the offer compares
			// to it: green well above the latest P90, red well below.
			goodClass := ""
			if always {
				if price > good*1.10 {
					goodClass = ` class="bl-good-high"`
				} else if price < good*0.80 {
					goodClass = ` class="bl-good-low"`
				}
			}
			prices += fmt.Sprintf(`<span%s title="Card Kingdom's latest P90">Good: $ %.2f</span>`, goodClass, good)
		}
		if highest > 0 {
			prices += fmt.Sprintf(`<span title="90-day high">Highest: $ %.2f</span>`, highest)
		}
		if prices == "" {
			return ""
		}
		return template.HTML(fmt.Sprintf(`<span class="bl-prices">%s</span>`, prices))
	},
	"base64enc": func(s string) string {
		return base64.StdEncoding.EncodeToString([]byte(s))
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
	"palette_newspaper_targets": func() template.JS { return paletteService.NewspaperTargetsJSON() },
	"palette_sleepers_targets":  palette.SleepersTargetsJSON,
	"palette_arbit_targets":     func() template.JS { return paletteService.ArbitTargetsJSON("arbit") },
	"palette_reverse_targets":   func() template.JS { return paletteService.ArbitTargetsJSON("reverse") },
	"palette_global_targets":    func() template.JS { return paletteService.ArbitTargetsJSON("global") },
	"guide_stores":              guideStoresJSON,
	"usd":                       formatUSD,
	"api_plans_json":            apiPlansJSON,
	"plan_icon":                 planIcon,
	"usage_path_url":            observability.PathURL,
	"dict": func(values ...any) (map[string]any, error) {
		if len(values)%2 != 0 {
			return nil, errors.New("dict requires even number of args")
		}
		m := make(map[string]any, len(values)/2)
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
