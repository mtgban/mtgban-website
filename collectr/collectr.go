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

type Item struct {
	ProductID string
	Name      string
	SetName   string
	Number    string
	Rarity    string
	Quantity  int
	Condition string
	IsFoil    bool
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

// Load fetches all MTG cards from a public Collectr showcase.
// It fetches the showcase page HTML via cloudscraper (to bypass Cloudflare)
// and extracts the pre-rendered product data embedded by Next.js.
// Multiple page fetches with different sort orders are combined to
// maximize coverage of the full collection.
func Load(ctx context.Context, link string, maxRows int) ([]Item, error) {
	_, err := ParseShowcaseURL(link)
	if err != nil {
		return nil, err
	}

	scraper, err := cloudscraper.Init(false, false)
	if err != nil {
		return nil, fmt.Errorf("cloudscraper init: %w", err)
	}

	// Ensure the link has the MTG cards filter
	if !strings.Contains(link, "category=") {
		if strings.Contains(link, "?") {
			link += "&category=1&cardType=cards"
		} else {
			link += "?category=1&cardType=cards"
		}
	}

	seen := map[string]bool{}
	var allItems []Item

	for _, variant := range sortVariants {
		if ctx.Err() != nil {
			break
		}

		pageURL := link + variant
		resp, err := scraper.Get(pageURL, map[string]string{
			"Accept": "text/html,application/xhtml+xml",
		}, "")
		if err != nil || resp.Status != 200 {
			continue
		}

		items, err := parseProducts(resp.Body, 0)
		if err != nil {
			continue
		}

		for _, item := range items {
			key := item.Name + "|" + item.SetName + "|" + item.Number + "|" + fmt.Sprintf("%v", item.IsFoil)
			if seen[key] {
				continue
			}
			seen[key] = true
			allItems = append(allItems, item)

			if maxRows > 0 && len(allItems) >= maxRows {
				return allItems, nil
			}
		}

		// Stop early if we're not finding new items
		if len(allItems) > 0 && len(items) > 0 {
			newRatio := float64(len(allItems)) / float64(len(allItems)+len(items)-len(allItems))
			_ = newRatio // could use to decide early termination
		}
	}

	if len(allItems) == 0 {
		return nil, fmt.Errorf("no MTG cards found in showcase")
	}

	return allItems, nil
}

// parseProducts extracts product data from page HTML.
// The data is embedded in Next.js RSC script chunks as escaped JSON.
// Multiple product arrays may exist (e.g. unfiltered + filtered views).
func parseProducts(html string, maxRows int) ([]Item, error) {
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
			if !p.IsCard || p.CategoryName != "Magic: The Gathering" {
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
func LoadReader(r io.Reader, maxRows int) ([]Item, error) {
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return parseProducts(string(buf), maxRows)
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
