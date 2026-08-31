// Package cardconduit submits cards to CardConduit's estimate API.
package cardconduit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/hashicorp/go-cleanhttp"
)

const (
	// EstimateURL is the endpoint estimates are submitted to.
	EstimateURL = "https://cardconduit.com/api/v1.0/estimate"
)

// Item is one card of an estimate request.
type Item struct {
	ScryfallID string `json:"scryfall_id"`
	Condition  string `json:"condition"`
	Quantity   int    `json:"quantity"`
	Language   string `json:"language"`
	IsFoil     bool   `json:"is_foil"`
	IsEtched   bool   `json:"is_etched"`
}

// Payload is the body of an estimate request.
type Payload struct {
	Items []Item `json:"items"`
}

// Response is what the estimate endpoint answers with.
type Response struct {
	Success  bool   `json:"success"`
	Message  string `json:"message"`
	HTTPCode int    `json:"http_code"`
	Data     struct {
		Estimate struct {
			ID        string    `json:"id"`
			URL       string    `json:"url"`
			CreatedAt time.Time `json:"created_at"`
		} `json:"estimate"`
	} `json:"data"`
}

// SendEstimate forwards items to CardConduit and returns the URL the
// finished estimate can be read at.
func SendEstimate(ctx context.Context, bearer string, items []Item) (string, error) {
	var payload Payload
	payload.Items = items
	reqBytes, err := json.Marshal(&payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, EstimateURL, bytes.NewReader(reqBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := cleanhttp.DefaultClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var response Response
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return "", err
	}

	if !response.Success {
		return "", errors.New(response.Message)
	}

	return response.Data.Estimate.URL, nil
}
