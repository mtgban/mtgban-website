package collectr

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/RomainMichau/cloudscraper_go/cloudscraper"
)

const (
	pageBase = "https://app.getcollectr.com"
)

// CategoryID maps game names to Collectr category IDs.
var CategoryID = map[string]string{
	"magic":   "1",
	"lorcana": "71",
}

// CategoryFilter maps game names to the catalog_category_name used by the API.
var CategoryFilter = map[string]string{
	"magic":   "Magic: The Gathering",
	"lorcana": "Lorcana",
}

type Item struct {
	ProductID string
	Name      string
	SetName   string
	Number    string
	Rarity    string
	Quantity  int
	Condition string
	IsFoil    bool
	IsSealed  bool
	Price     float64
}

type showcaseProduct struct {
	ProductID      string `json:"product_id"`
	ProductName    string `json:"product_name"`
	CatalogGroup   string `json:"catalog_group"`
	CardNumber     string `json:"card_number"`
	Rarity         string `json:"rarity"`
	Quantity       string `json:"quantity"`
	MarketPrice    string `json:"market_price"`
	CardCondition  string `json:"card_condition"`
	ProductSubType string `json:"product_sub_type"`
	IsCard         bool   `json:"is_card"`
	CategoryName   string `json:"catalog_category_name"`
}

// ParseShowcaseURL extracts the handle from a Collectr showcase URL.
// Accepted formats:
//
//	https://app.getcollectr.com/showcase/profile/@handle
//	https://app.getcollectr.com/showcase/profile/@handle?category=1&cardType=cards
func ParseShowcaseURL(link string) (handle string, err error) {
	u, err := url.Parse(link)
	if err != nil {
		return "", err
	}

	if u.Host != "app.getcollectr.com" {
		return "", fmt.Errorf("unsupported host: %s", u.Host)
	}

	// Path: /showcase/profile/@handle
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) < 3 || parts[0] != "showcase" || parts[1] != "profile" {
		return "", fmt.Errorf("invalid showcase URL path: %s", u.Path)
	}

	handle = parts[2]
	if !strings.HasPrefix(handle, "@") {
		return "", fmt.Errorf("invalid handle: %s", handle)
	}

	return handle, nil
}

// productsMarkers describes the two encodings of the products array we know how to handle:
//
//   - HTML payload: the RSC chunks are embedded as JS-escaped strings, so we
//     see literal backslash-quote sequences ( \"products\":[{ ).
//   - RSC payload: requesting the same URL with `RSC: 1` returns the streamed
//     React Server Components body directly. There's no JS-string wrapping,
//     so it's plain JSON ( "products":[{ ).
//
// Hitting the page over an IP that Cloudflare considers low-reputation
// (e.g. a DigitalOcean datacenter address) sometimes causes the HTML form to
// be served without the RSC chunks embedded. The plain RSC fetch is the
// reliable path; we keep the escaped form as a fallback.
var productsMarkers = []struct {
	marker   string
	unescape bool
}{
	{marker: `"products":[{`, unescape: false},
	{marker: `\"products\":[{`, unescape: true},
}

// sortVariants are URL suffixes appended to maximize product coverage.
// Each sort order causes the server to pre-render a different slice of
// the collection, so fetching multiple variants and deduplicating gives
// broader coverage than a single page load.
var sortVariants = []string{
	"",
	"&sortType=price&sortOrder=ASC",
	"&sortType=price&sortOrder=DESC",
	"&sortType=product_name&sortOrder=ASC",
	"&sortType=product_name&sortOrder=DESC",
	"&sortType=date_added&sortOrder=ASC",
}

// Load fetches cards from a public Collectr showcase for the given game.
// It fetches the showcase page HTML via cloudscraper (to bypass Cloudflare)
// and extracts the pre-rendered product data embedded by Next.js.
// Multiple page fetches with different sort orders are combined to
// maximize coverage of the full collection.
func Load(ctx context.Context, link string, game string, maxRows int) ([]Item, error) {
	_, err := ParseShowcaseURL(link)
	if err != nil {
		return nil, err
	}

	catID, ok := CategoryID[game]
	if !ok {
		return nil, fmt.Errorf("unsupported game: %s", game)
	}
	catName := CategoryFilter[game]

	scraper, err := cloudscraper.Init(false, false)
	if err != nil {
		return nil, fmt.Errorf("cloudscraper init: %w", err)
	}

	// Strip any existing query params
	if i := strings.Index(link, "?"); i >= 0 {
		link = link[:i]
	}

	// Fetch both cards and sealed products
	cardTypes := []string{"cards", "sealed"}

	seen := map[string]bool{}
	var allItems []Item
	var lastErr error

	for _, cardType := range cardTypes {
		baseURL := link + "?category=" + catID + "&cardType=" + cardType

		for _, variant := range sortVariants {
			if ctx.Err() != nil {
				break
			}

			pageURL := baseURL + variant
			// Request the React Server Components stream — it carries the
			// products array as plain JSON instead of JS-escaped HTML chunks,
			// which is materially more reliable from datacenter IPs.
			resp, err := scraper.Get(pageURL, map[string]string{
				"Accept":   "text/x-component,text/html,application/xhtml+xml",
				"RSC":      "1",
				"Next-Url": "/showcase/profile/",
			}, "")
			if err != nil {
				lastErr = fmt.Errorf("fetch %s: %w", cardType, err)
				continue
			}
			if resp.Status != 200 {
				lastErr = fmt.Errorf("fetch %s: status %d", cardType, resp.Status)
				continue
			}

			items, err := parseProducts(resp.Body, catName, 0)
			if err != nil {
				lastErr = fmt.Errorf("parse %s: %w", cardType, err)
				continue
			}

			newFound := false
			for _, item := range items {
				key := item.ProductID
				if key == "" {
					key = item.Name + "|" + item.SetName + "|" + item.Number + "|" + fmt.Sprintf("%v|%v", item.IsFoil, item.IsSealed)
				}
				if seen[key] {
					continue
				}
				seen[key] = true
				newFound = true
				allItems = append(allItems, item)

				if maxRows > 0 && len(allItems) >= maxRows {
					return allItems, nil
				}
			}

			// Skip remaining sort variants if this one found nothing new
			if !newFound {
				break
			}
		}
	}

	if len(allItems) == 0 {
		if lastErr != nil {
			return nil, fmt.Errorf("no products found in showcase: %w", lastErr)
		}
		return nil, fmt.Errorf("no products found in showcase")
	}

	return allItems, nil
}

// parseProducts extracts product data from a Collectr showcase response.
// The same products array can appear in either of two encodings depending on
// whether the response is the SSR HTML or the RSC stream (see productsMarkers).
// Multiple product arrays may exist (e.g. unfiltered + filtered views).
func parseProducts(body string, categoryName string, maxRows int) ([]Item, error) {
	seen := map[string]bool{}
	var items []Item

	for _, m := range productsMarkers {
		extractWithMarker(body, m.marker, m.unescape, categoryName, seen, &items, maxRows)
		if maxRows > 0 && len(items) >= maxRows {
			break
		}
	}

	if len(items) == 0 {
		return nil, fmt.Errorf("no product data found in page")
	}

	return items, nil
}

// extractWithMarker scans body for arrays preceded by marker (e.g. `"products":[{`
// or its JS-escaped form) and appends every new product matching categoryName
// to items. Each unique entry (keyed by name+set+number+subtype) is added once.
func extractWithMarker(body, marker string, unescape bool, categoryName string, seen map[string]bool, items *[]Item, maxRows int) {
	searchStart := 0
	for {
		idx := strings.Index(body[searchStart:], marker)
		if idx < 0 {
			return
		}
		idx += searchStart

		// The marker ends just past `[`, so locate the array start exactly.
		arrayStart := idx + strings.Index(marker, "[")

		arrayEnd := findArrayEnd(body, arrayStart)
		if arrayEnd < 0 {
			searchStart = idx + len(marker)
			continue
		}

		raw := body[arrayStart:arrayEnd]
		if unescape {
			// JS-escaped form: \" -> "  and  \\ -> \
			raw = strings.ReplaceAll(raw, `\"`, `"`)
			raw = strings.ReplaceAll(raw, `\\`, `\`)
		}

		var products []showcaseProduct
		if err := json.Unmarshal([]byte(raw), &products); err != nil {
			searchStart = arrayEnd
			continue
		}

		for _, p := range products {
			if p.CategoryName != categoryName {
				continue
			}

			key := p.ProductName + "|" + p.CatalogGroup + "|" + p.CardNumber + "|" + p.ProductSubType
			if seen[key] {
				continue
			}
			seen[key] = true

			qty, _ := strconv.Atoi(p.Quantity)
			if qty < 1 {
				qty = 1
			}

			price, _ := strconv.ParseFloat(p.MarketPrice, 64)

			*items = append(*items, Item{
				ProductID: p.ProductID,
				Name:      strings.TrimSpace(p.ProductName),
				SetName:   p.CatalogGroup,
				Number:    p.CardNumber,
				Rarity:    p.Rarity,
				Quantity:  qty,
				Condition: mapCondition(p.CardCondition),
				IsFoil:    p.ProductSubType == "Foil",
				IsSealed:  !p.IsCard,
				Price:     price,
			})

			if maxRows > 0 && len(*items) >= maxRows {
				return
			}
		}

		searchStart = arrayEnd
	}
}

// findArrayEnd returns the index just past the closing `]` of the JSON array
// whose opening `[` is at start. Returns -1 if no balanced match is found.
func findArrayEnd(body string, start int) int {
	if start >= len(body) || body[start] != '[' {
		return -1
	}
	depth := 0
	for i := start; i < len(body); i++ {
		switch body[i] {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return -1
}

// LoadReader parses product data from a pre-fetched page HTML body.
func LoadReader(r io.Reader, game string, maxRows int) ([]Item, error) {
	catName, ok := CategoryFilter[game]
	if !ok {
		return nil, fmt.Errorf("unsupported game: %s", game)
	}
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return parseProducts(string(buf), catName, maxRows)
}

func mapCondition(cond string) string {
	switch strings.ToUpper(strings.TrimSpace(cond)) {
	case "NM", "NEAR MINT":
		return "NM"
	case "LP", "LIGHTLY PLAYED":
		return "SP"
	case "MP", "MODERATELY PLAYED":
		return "MP"
	case "HP", "HEAVILY PLAYED":
		return "HP"
	case "DMG", "DAMAGED":
		return "PO"
	default:
		return "NM"
	}
}
