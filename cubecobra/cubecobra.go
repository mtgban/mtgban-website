// Package cubecobra reads public cubes from CubeCobra's JSON API.
package cubecobra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/go-cleanhttp"
)

const apiBase = "https://cubecobra.com/cube/api/cubeJSON/"

// Item is one card row from a public CubeCobra cube.
type Item struct {
	ScryfallID string
	Name       string
	IsFoil     bool
	IsEtched   bool
}

type cubePayload struct {
	Name  string `json:"name"`
	Cards struct {
		Mainboard []cardRow `json:"mainboard"`
	} `json:"cards"`
}

type cardRow struct {
	CardID  string `json:"cardID"`
	Finish  string `json:"finish"`
	Status  string `json:"status"`
	Details struct {
		Name string `json:"name"`
	} `json:"details"`
}

// ParseCubeURL extracts the cube id from a cubecobra.com/cube/<page>/<id>
// URL, such as https://cubecobra.com/cube/overview/LSVCube, or from a
// cubecobra.com/c/<id> short link.
func ParseCubeURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("invalid CubeCobra URL")
	}
	host := strings.ToLower(u.Host)
	if host != "cubecobra.com" && host != "www.cubecobra.com" {
		return "", errors.New("invalid CubeCobra URL")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	var id string
	switch {
	case len(parts) >= 2 && parts[0] == "c":
		id = parts[1]
	case len(parts) >= 3 && parts[0] == "cube":
		id = parts[2]
	}
	// Load escapes the id, so only a dot segment could leave the API path
	if id == "" || id == "." || id == ".." {
		return "", errors.New("invalid CubeCobra cube URL")
	}
	return id, nil
}

// Load fetches a public CubeCobra cube by its URL and returns its cards plus
// the cube name. Only the mainboard is read: the maybeboard holds candidates
// and the basics board the cube's land station. Each row is one copy; rows
// marked Proxied are skipped, since a proxy is not a card worth anything.
func Load(ctx context.Context, link string, maxRows int) ([]Item, string, error) {
	id, err := ParseCubeURL(link)
	if err != nil {
		return nil, "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+url.PathEscape(id), http.NoBody)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := cleanhttp.DefaultClient().Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("cubecobra returned status %d", resp.StatusCode)
	}

	var cube cubePayload
	err = json.NewDecoder(resp.Body).Decode(&cube)
	if err != nil {
		return nil, "", fmt.Errorf("decode CubeCobra cube: %w", err)
	}

	return cubeItems(&cube, maxRows), cube.Name, nil
}

func cubeItems(cube *cubePayload, maxRows int) []Item {
	items := make([]Item, 0, len(cube.Cards.Mainboard))
	for _, c := range cube.Cards.Mainboard {
		if c.Status == "Proxied" || c.CardID == "" {
			continue
		}
		if maxRows > 0 && len(items) >= maxRows {
			break
		}
		items = append(items, Item{
			ScryfallID: c.CardID,
			Name:       c.Details.Name,
			IsFoil:     c.Finish == "Foil" || c.Finish == "Alt-foil",
			IsEtched:   c.Finish == "Etched",
		})
	}
	return items
}
