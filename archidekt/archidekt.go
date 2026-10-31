// Package archidekt reads public decks from Archidekt's API.
package archidekt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/mtgban/go-mtgban/mtgban"
)

const apiBase = "https://archidekt.com/api/decks/"

// client gives up on a stalled Archidekt rather than holding the upload, and
// retries nothing, so one that is down fails at once.
var client = mtgban.NewHTTPClient(
	mtgban.WithHTTPTimeout(30*time.Second),
	mtgban.WithHTTPRetries(0),
	// Hand back a 5xx as it came, for the status check to report
	mtgban.WithHTTPErrorHandler(retryablehttp.PassthroughErrorHandler),
)

// maxBody holds about 10,000 rows at the 3.2 KB an Archidekt row
// takes.
const maxBody = 32 << 20

// Item is one card row from a public Archidekt deck.
type Item struct {
	ScryfallID string
	Name       string
	Quantity   int
	IsFoil     bool
	IsEtched   bool
}

type deckPayload struct {
	Name       string `json:"name"`
	Categories []struct {
		Name           string `json:"name"`
		IncludedInDeck bool   `json:"includedInDeck"`
	} `json:"categories"`
	Cards []struct {
		Quantity   int      `json:"quantity"`
		Modifier   string   `json:"modifier"`
		Categories []string `json:"categories"`
		Card       struct {
			UID        string `json:"uid"`
			OracleCard struct {
				Name string `json:"name"`
			} `json:"oracleCard"`
		} `json:"card"`
	} `json:"cards"`
}

// ParseDeckURL extracts the numeric deck id from an archidekt.com/decks/…
// URL, such as https://archidekt.com/decks/27936929/breena.
func ParseDeckURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("invalid Archidekt URL")
	}
	host := strings.ToLower(u.Host)
	if host != "archidekt.com" && host != "www.archidekt.com" {
		return "", errors.New("invalid Archidekt URL")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 || parts[0] != "decks" {
		return "", errors.New("invalid Archidekt deck URL")
	}
	// A plain number, so nothing else can reach the API path
	_, err = strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return "", errors.New("invalid Archidekt deck URL")
	}
	return parts[1], nil
}

// Load fetches a public Archidekt deck by its URL and returns its cards plus
// the deck name. Cards filed under a category left out of the deck, such as
// the Maybeboard, are skipped; the Sideboard is left out too but kept, since
// its cards are part of the deck someone owns.
func Load(ctx context.Context, link string, maxRows int) ([]Item, string, error) {
	id, err := ParseDeckURL(link)
	if err != nil {
		return nil, "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+id+"/", http.NoBody)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "mtgban-website/archidekt")

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("archidekt returned status %d", resp.StatusCode)
	}

	var deck deckPayload
	err = json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&deck)
	if err != nil {
		return nil, "", fmt.Errorf("decode Archidekt deck: %w", err)
	}

	return deckItems(&deck, maxRows), deck.Name, nil
}

func deckItems(deck *deckPayload, maxRows int) []Item {
	excluded := map[string]bool{}
	for _, cat := range deck.Categories {
		if !cat.IncludedInDeck && cat.Name != "Sideboard" {
			excluded[cat.Name] = true
		}
	}

	items := make([]Item, 0, len(deck.Cards))
	for _, c := range deck.Cards {
		// Archidekt files a card by its first category
		if len(c.Categories) > 0 && excluded[c.Categories[0]] {
			continue
		}
		if c.Quantity <= 0 || c.Card.UID == "" {
			continue
		}
		if maxRows > 0 && len(items) >= maxRows {
			break
		}
		items = append(items, Item{
			ScryfallID: c.Card.UID,
			Name:       c.Card.OracleCard.Name,
			Quantity:   c.Quantity,
			IsFoil:     c.Modifier == "Foil",
			IsEtched:   c.Modifier == "Etched",
		})
	}
	return items
}
