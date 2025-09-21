package cardconduit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	cleanhttp "github.com/hashicorp/go-cleanhttp"
)

const (
	EstimateURL = "https://cardconduit.com/api/v1.0/estimate"
)

type Item struct {
	ScryfallID string `json:"scryfall_id"`
	Condition  string `json:"condition,omitempty"`
	Quantity   int    `json:"quantity,omitempty"`
	Language   string `json:"language,omitempty"`
	IsFoil     bool   `json:"is_foil,omitempty"`
	IsEtched   bool   `json:"is_etched,omitempty"`
}

type Payload struct {
	Items []Item `json:"items"`
}

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

// Forward items to CC and retrieve the URL containing the results
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
