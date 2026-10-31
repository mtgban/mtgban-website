// Package manabox reads public decks from ManaBox's cloud API.
package manabox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/mtgban/go-mtgban/mtgban"
)

const apiBase = "https://cloud.manabox.app"

// client gives up on a stalled ManaBox rather than holding the upload, and
// retries nothing, so one that is down fails at once.
var client = mtgban.NewHTTPClient(
	mtgban.WithHTTPTimeout(30*time.Second),
	mtgban.WithHTTPRetries(0),
	// Hand back a 5xx as it came, for the status check to report
	mtgban.WithHTTPErrorHandler(retryablehttp.PassthroughErrorHandler),
)

// maxBody holds about 19,000 rows at the 1.7 KB a ManaBox row
// takes.
const maxBody = 32 << 20

// ManaBox card finish (variant field on each card).
const (
	variantNormal = 0
	variantFoil   = 1
	variantEtched = 2
)

// Item is one card row from a public ManaBox deck.
type Item struct {
	ScryfallID string
	Name       string
	Quantity   int
	IsFoil     bool
	IsEtched   bool
}

type deckPayload struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Cards []struct {
		Name       string `json:"name"`
		ScryfallID string `json:"scryfallId"`
		Quantity   int    `json:"quantity"`
		Variant    int    `json:"variant"`
		Proxy      bool   `json:"proxy"`
	} `json:"cards"`
}

// ParseDeckURL extracts the public share id from a manabox.app /decks/… URL.
func ParseDeckURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("invalid ManaBox URL")
	}
	host := strings.ToLower(u.Host)
	if host != "manabox.app" && host != "www.manabox.app" {
		return "", errors.New("invalid ManaBox URL")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 || parts[0] != "decks" || parts[1] == "" {
		return "", errors.New("invalid ManaBox deck URL")
	}
	id := parts[1]
	if strings.Contains(id, "/") {
		return "", errors.New("invalid ManaBox deck URL")
	}
	return id, nil
}

// Load fetches a public ManaBox deck by share id (or full URL) and returns
// its cards plus the deck name.
func Load(ctx context.Context, shareOrURL string, maxRows int) ([]Item, string, error) {
	shareID := shareOrURL
	if strings.Contains(shareOrURL, "://") {
		id, err := ParseDeckURL(shareOrURL)
		if err != nil {
			return nil, "", err
		}
		shareID = id
	}
	shareID = path.Base(strings.Trim(shareID, "/"))
	// PathEscape leaves dots alone, so ".." would walk up from /decks/
	if shareID == "" || shareID == "." || shareID == ".." {
		return nil, "", errors.New("invalid ManaBox deck URL")
	}

	apiURL := apiBase + "/decks/" + url.PathEscape(shareID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "mtgban-website/manabox")

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("ManaBox returned status %d", resp.StatusCode)
	}

	var deck deckPayload
	err = json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&deck)
	if err != nil {
		return nil, "", fmt.Errorf("decode ManaBox deck: %w", err)
	}

	items := make([]Item, 0, len(deck.Cards))
	for _, c := range deck.Cards {
		if c.Proxy || c.Quantity <= 0 || c.ScryfallID == "" {
			continue
		}
		if maxRows > 0 && len(items) >= maxRows {
			break
		}
		items = append(items, Item{
			ScryfallID: c.ScryfallID,
			Name:       c.Name,
			Quantity:   c.Quantity,
			IsFoil:     c.Variant == variantFoil,
			IsEtched:   c.Variant == variantEtched,
		})
	}

	name := deck.Name
	if name == "" {
		name = shareID
	}
	return items, name, nil
}
