package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

type MoxfieldDeck struct {
	Boards map[string]MoxBoard `json:"boards"`
}

type MoxBoard struct {
	Count int
	Cards map[string]struct {
		Quantity int    `json:"quantity"`
		Finish   string `json:"finish"`
		Card     struct {
			ScryfallID string `json:"scryfall_id"`
		} `json:"card"`
	} `json:"cards"`
}

type MoxCard struct {
	ScryfallID string
	Finish     string
	Quantity   int
}

func extractDeckID(gdocURL string) (string, error) {
	// Parse the provided URL.
	parsedURL, err := url.Parse(gdocURL)
	if err != nil {
		return "", err
	}

	// Extract the deck ID from the URL.
	pathSegments := strings.Split(parsedURL.Path, "/")

	if len(pathSegments) < 2 || pathSegments[1] != "decks" {
		return "", errors.New("invalid Moxfield deck URL")
	}

	deckID := pathSegments[2]
	if deckID == "" {
		return "", errors.New("no deck ID found in URL")
	}

	return fmt.Sprintf("%s/%s", Config.Uploader.Moxfield, deckID), nil
}

func getMoxDeck(url string) (*MoxfieldDeck, error) {
	// Create request to fetch Moxfield deck data.
	resp, err := cleanhttp.DefaultClient().Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check response status code.
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status code: %d", resp.StatusCode)
	}

	// Read response body into slice.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse deck data from response body.
	var data MoxfieldDeck
	err = json.Unmarshal(body, &data)

	if err != nil {
		return nil, err
	}

	// Return deck data.
	return &data, nil
}

// Extract card details, flattening deck data into a single slice
func extractDecklist(data *MoxfieldDeck) []MoxCard {
	var cardInfoList []MoxCard
	for _, board := range data.Boards {
		for _, card := range board.Cards {
			cardInfoList = append(cardInfoList, MoxCard{
				ScryfallID: card.Card.ScryfallID,
				Finish:     card.Finish,
				Quantity:   card.Quantity,
			})
		}
	}
	return cardInfoList
}

// Prepare upload entries in the expected format
func prepareUploadEntries(MoxCards []MoxCard, maxRows int) ([]UploadEntry, error) {
	var uploadEntries []UploadEntry
	for i, detail := range MoxCards {
		if i >= maxRows {
			break
		}
		entry := UploadEntry{
			HasQuantity: true,
			Quantity:    detail.Quantity,
		}

		isfoil := detail.Finish == "foil"
		isetched := detail.Finish == "etched"
		cardId, err := mtgmatcher.MatchId(detail.ScryfallID, isfoil, isetched)
		entry.CardId = cardId
		entry.MismatchError = err

		uploadEntries = append(uploadEntries, entry)
	}
	return uploadEntries, nil
}

func loadMoxfieldDeck(gdocURL string, maxRows int) ([]UploadEntry, error) {
	moxURL, err := extractDeckID(gdocURL)
	if err != nil {
		log.Println(err)
		return nil, errors.New("invalid Moxfield deck URL")
	}
	log.Println("Querying:", moxURL)

	moxDeck, err := getMoxDeck(moxURL)
	if err != nil {
		log.Println(err)
		return nil, errors.New("failed to fetch Moxfield deck")
	}

	moxCards := extractDecklist(moxDeck)
	return prepareUploadEntries(moxCards, maxRows)
}
