package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/corpix/uarand"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

type MoxfieldDeck struct {
	Boards map[string]MoxBoard `json:"boards"`
}

type MoxBoard struct {
	Count int                `json:"count"`
	Cards map[string]MoxCard `json:"cards"`
}

type MoxCard struct {
	Quantity int    `json:"quantity"`
	Finish   string `json:"finish"`
	Card     struct {
		ScryfallID string `json:"scryfall_id"`
	} `json:"card"`
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
	client := cleanhttp.DefaultClient()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	}
	client.Transport = transport

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer undefined")
	req.Header.Set("User-Agent", uarand.GetRandom())

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read response body into slice.
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Check response status code.
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status code: %d", resp.StatusCode)
	}

	// Parse deck data from response body.
	var deck MoxfieldDeck
	err = json.Unmarshal(data, &deck)

	if err != nil {
		return nil, err
	}

	// Return deck data.
	return &deck, nil
}

// Extract card details, flattening deck data into a single slice
func extractDecklist(data *MoxfieldDeck) []MoxCard {
	var cardInfoList []MoxCard
	for _, board := range data.Boards {
		for _, card := range board.Cards {
			cardInfoList = append(cardInfoList, card)
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
		cardId, err := mtgmatcher.MatchId(detail.Card.ScryfallID, isfoil, isetched)
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

	// Preserve some sort of ordering
	sort.Slice(moxCards, func(i, j int) bool {
		uuidI := mtgmatcher.Scryfall2UUID(moxCards[i].Card.ScryfallID)
		uuidJ := mtgmatcher.Scryfall2UUID(moxCards[j].Card.ScryfallID)
		return !sortSetsAlphabeticalSet(uuidI, uuidJ)
	})

	return prepareUploadEntries(moxCards, maxRows)
}
