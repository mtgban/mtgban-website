package collectr

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
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

// productsPattern matches the escaped JSON products array embedded in Next.js RSC data.
// The products are in the format: \"products\":[{...},{...}]
var productsPattern = regexp.MustCompile(`\\"products\\":\[(\{.*?\})\]`)

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

	for _, cardType := range cardTypes {
		baseURL := link + "?category=" + catID + "&cardType=" + cardType

		for _, variant := range sortVariants {
			if ctx.Err() != nil {
				break
			}

			pageURL := baseURL + variant
			resp, err := scraper.Get(pageURL, map[string]string{
				"Accept": "text/html,application/xhtml+xml",
			}, "")
			if err != nil || resp.Status != 200 {
				continue
			}

			items, err := parseProducts(resp.Body, catName, 0)
			if err != nil {
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
		return nil, fmt.Errorf("no products found in showcase")
	}

	return allItems, nil
}

// parseProducts extracts product data from page HTML.
// The data is embedded in Next.js RSC script chunks as escaped JSON.
// Multiple product arrays may exist (e.g. unfiltered + filtered views).
func parseProducts(html string, categoryName string, maxRows int) ([]Item, error) {
	const marker = `\"products\":[{`

	seen := map[string]bool{}
	var items []Item
	searchStart := 0

	for {
		idx := strings.Index(html[searchStart:], marker)
		if idx == -1 {
			break
		}
		idx += searchStart

		// Move to the start of the array
		arrayStart := idx + len(`\"products\":`)

		// Find the matching closing bracket, accounting for nesting
		depth := 0
		arrayEnd := -1
		for i := arrayStart; i < len(html); i++ {
			switch html[i] {
			case '[':
				depth++
			case ']':
				depth--
				if depth == 0 {
					arrayEnd = i + 1
				}
			}
			if arrayEnd > 0 {
				break
			}
		}
		if arrayEnd < 0 {
			searchStart = idx + len(marker)
			continue
		}

		// Unescape the JSON (\" -> ", \\ -> \)
		raw := html[arrayStart:arrayEnd]
		raw = strings.ReplaceAll(raw, `\"`, `"`)
		raw = strings.ReplaceAll(raw, `\\`, `\`)

		var products []showcaseProduct
		if err := json.Unmarshal([]byte(raw), &products); err != nil {
			searchStart = arrayEnd
			continue
		}

		for _, p := range products {
			if p.CategoryName != categoryName {
				continue
			}

			// Deduplicate by product_id-like key
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

			items = append(items, Item{
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

			if maxRows > 0 && len(items) >= maxRows {
				return items, nil
			}
		}

		searchStart = arrayEnd
	}

	if len(items) == 0 {
		return nil, fmt.Errorf("no product data found in page")
	}

	return items, nil
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
