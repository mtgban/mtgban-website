package moxfield

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/hashicorp/go-cleanhttp"
)

type Item struct {
	ScryfallID string
	Quantity   int
	IsFoil     bool
	IsEtched   bool
	Condition  string
	Price      float64
	Notes      string
}

type Deck struct {
	Boards map[string]struct {
		Count int `json:"count"`
		Cards map[string]struct {
			Quantity int    `json:"quantity"`
			Finish   string `json:"finish"`
			Card     struct {
				ScryfallID string `json:"scryfall_id"`
			} `json:"card"`
		} `json:"cards"`
	} `json:"boards"`
}

func getMoxDeck(ctx context.Context, deckURL string) (*Deck, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, deckURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := cleanhttp.DefaultClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status code: %d", resp.StatusCode)
	}

	var deck Deck
	err = json.NewDecoder(resp.Body).Decode(&deck)
	if err != nil {
		return nil, err
	}

	return &deck, nil
}

// Prepare upload entries in the expected format
func prepareDecklist(deck *Deck, maxRows int) []Item {
	var items []Item
	var count int
	for _, board := range deck.Boards {
		for _, card := range board.Cards {
			if count >= maxRows {
				break
			}

			items = append(items, Item{
				ScryfallID: card.Card.ScryfallID,
				IsFoil:     card.Finish == "foil",
				IsEtched:   card.Finish == "etched",
				Quantity:   card.Quantity,
			})

			count++
		}
	}

	// Preserve some sort of ordering since boards are maps
	sort.Slice(items, func(i, j int) bool {
		return items[i].ScryfallID < items[j].ScryfallID
	})

	return items
}

type Collection struct {
	PageNumber   int `json:"pageNumber"`
	PageSize     int `json:"pageSize"`
	TotalResults int `json:"totalResults"`
	TotalPages   int `json:"totalPages"`
	Data         []struct {
		ID            string  `json:"id"`
		Quantity      int     `json:"quantity"`
		Condition     string  `json:"condition"`
		Game          string  `json:"game"`
		Finish        string  `json:"finish"`
		PurchasePrice float64 `json:"purchasePrice"`
		Notes         string  `json:"notes"`
		Card          struct {
			ScryfallID string `json:"scryfall_id"`
			Lang       string `json:"lang"`
			IsToken    bool   `json:"isToken"`
		} `json:"card,omitempty"`
	} `json:"data"`
}

func getMoxCollectionPage(ctx context.Context, collectionURL string, page int) (*Collection, error) {
	// Tweak pagiation so that the first page will only yield pagination info
	pageSize := "100"
	if page == 0 {
		pageSize = "1"
	}

	link := collectionURL + "?pageSize=" + pageSize + "&pageNumber=" + fmt.Sprint(page) + "&sortColumn=cardName&sortType=cardName&sortDirection=ascending"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := cleanhttp.DefaultClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status code: %d", resp.StatusCode)
	}

	var collection Collection
	err = json.NewDecoder(resp.Body).Decode(&collection)
	if err != nil {
		return nil, err
	}

	return &collection, nil
}

var conditionMap = map[string]string{
	"nearMint":         "NM",
	"slightlyPlayed":   "LP",
	"moderatelyPlayed": "MP",
	"heavilyPlayed":    "HP",
	"damaged":          "PO",
}

func getMoxCollection(ctx context.Context, collectionURL string, maxRows int) ([]Item, error) {
	pagination, err := getMoxCollectionPage(ctx, collectionURL, 0)
	if err != nil {
		return nil, err
	}

	var items []Item
	var count int
	for page := 1; page <= pagination.TotalResults/100+1; page++ {
		collection, err := getMoxCollectionPage(ctx, collectionURL, page)
		if err != nil {
			return nil, err
		}

		for _, card := range collection.Data {
			if count >= maxRows {
				break
			}

			if card.Game != "paper" {
				continue
			}

			items = append(items, Item{
				ScryfallID: card.Card.ScryfallID,
				IsFoil:     card.Finish == "foil",
				IsEtched:   card.Finish == "etched",
				Quantity:   card.Quantity,
				Condition:  conditionMap[card.Condition],
				Price:      card.PurchasePrice,
				Notes:      card.Notes,
			})

			count++
		}

		if count >= maxRows {
			break
		}
	}

	return items, nil
}

func Load(ctx context.Context, link string, maxRows int) ([]Item, error) {
	if strings.Contains(link, "/collection/") {
		return getMoxCollection(ctx, link, maxRows)
	}

	deck, err := getMoxDeck(ctx, link)
	if err != nil {
		return nil, err
	}

	return prepareDecklist(deck, maxRows), nil
}
