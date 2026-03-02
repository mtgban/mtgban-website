package moxfield

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/hashicorp/go-cleanhttp"
)

type Item struct {
	ScryfallID string
	Quantity   int
	IsFoil     bool
	IsEtched   bool
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

func Load(ctx context.Context, link string, maxRows int) ([]Item, error) {
	deck, err := getMoxDeck(ctx, link)
	if err != nil {
		return nil, err
	}

	return prepareDecklist(deck, maxRows), nil
}
