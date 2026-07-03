// Package tcgcsv is a client for tcgcsv.com, a public daily mirror and
// historical archive of TCGplayer's catalog and pricing. It exposes the
// category -> group -> products/prices hierarchy used to ingest multi-game
// prices (Lorcana first) into the tcg_prices table.
//
// Etiquette (per tcgcsv.com/faq): a descriptive User-Agent is required,
// requests are throttled, and a full sync should run at most once per 24h. Use
// LastUpdated to gate a sync so we only pull when the upstream data is newer.
package tcgcsv

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DefaultBaseURL is the tcgcsv.com origin. Endpoints hang off /tcgplayer/,
// except last-updated.txt which sits at the root.
const DefaultBaseURL = "https://tcgcsv.com"

const defaultUserAgent = "mtgban-website (+https://mtgban.com)"

// Known TCGplayer category ids, for reference and config. Magic (category 1) is
// intentionally absent: its prices are keyed by mtgjson uuid in product_prices,
// not here. Categories 21, 69, and 70 are junk per the tcgcsv FAQ and should not
// be ingested.
const (
	CategoryYuGiOh            = 2
	CategoryPokemon           = 3
	CategoryVanguard          = 16
	CategoryDragonBallSuper   = 27
	CategoryFleshAndBlood     = 62
	CategoryDigimon           = 63
	CategoryOnePiece          = 68
	CategoryLorcana           = 71
	CategoryStarWarsUnlimited = 79
	CategoryRiftbound         = 89
)

// GameConfig names a single game to ingest and the TCGplayer category it maps
// to. Adding a game is one more entry.
type GameConfig struct {
	Name       string `json:"name"`
	CategoryID int    `json:"category_id"`
}

// Config is the ingestion registry: a descriptive User-Agent and the list of
// games to pull. It is the reusable template — the ingestion jobs iterate Games.
type Config struct {
	UserAgent string       `json:"user_agent"`
	Games     []GameConfig `json:"games"`
}

// Client talks to tcgcsv.com with a shared throttle and bounded retries.
type Client struct {
	baseURL    string
	userAgent  string
	httpClient *http.Client
	throttle   time.Duration
	retryWait  time.Duration
	maxRetries int

	mu      sync.Mutex
	lastReq time.Time
}

// NewClient builds a client from cfg. A blank User-Agent falls back to a
// descriptive default; tcgcsv.com blocks generic agents.
func NewClient(cfg Config) *Client {
	ua := strings.TrimSpace(cfg.UserAgent)
	if ua == "" {
		ua = defaultUserAgent
	}
	return &Client{
		baseURL:    DefaultBaseURL,
		userAgent:  ua,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		throttle:   150 * time.Millisecond,
		retryWait:  500 * time.Millisecond,
		maxRetries: 3,
	}
}

// envelope is the common response wrapper. The prices endpoint omits totalItems,
// so we don't rely on it.
type envelope[T any] struct {
	Success bool     `json:"success"`
	Errors  []string `json:"errors"`
	Results []T      `json:"results"`
}

// Category is a game/collection on TCGplayer (e.g. 71 = Disney Lorcana).
type Category struct {
	CategoryID  int    `json:"categoryId"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	ModifiedOn  string `json:"modifiedOn"`
}

// Group is a set within a category.
type Group struct {
	GroupID        int    `json:"groupId"`
	Name           string `json:"name"`
	Abbreviation   string `json:"abbreviation"`
	IsSupplemental bool   `json:"isSupplemental"`
	PublishedOn    string `json:"publishedOn"`
	ModifiedOn     string `json:"modifiedOn"`
	CategoryID     int    `json:"categoryId"`
}

// ExtendedData is a game-specific attribute on a product (Rarity, Number, ...).
type ExtendedData struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Value       string `json:"value"`
}

// Product is a single catalog entry (a card or sealed item).
type Product struct {
	ProductID    int            `json:"productId"`
	Name         string         `json:"name"`
	CleanName    string         `json:"cleanName"`
	ImageURL     string         `json:"imageUrl"`
	CategoryID   int            `json:"categoryId"`
	GroupID      int            `json:"groupId"`
	URL          string         `json:"url"`
	ModifiedOn   string         `json:"modifiedOn"`
	ExtendedData []ExtendedData `json:"extendedData"`
}

// Extended returns the value of the named extendedData attribute (e.g.
// "Number", "Rarity"), or "" if absent.
func (p Product) Extended(name string) string {
	for _, e := range p.ExtendedData {
		if e.Name == name {
			return e.Value
		}
	}
	return ""
}

// Price is one product's price for a single printing sub-type. All price fields
// are pointers because tcgcsv reports genuine nulls (e.g. no market price yet),
// which must stay distinct from 0.
type Price struct {
	ProductID      int      `json:"productId"`
	LowPrice       *float64 `json:"lowPrice"`
	MidPrice       *float64 `json:"midPrice"`
	HighPrice      *float64 `json:"highPrice"`
	MarketPrice    *float64 `json:"marketPrice"`
	DirectLowPrice *float64 `json:"directLowPrice"`
	SubTypeName    string   `json:"subTypeName"`
}

// Categories returns every category tcgcsv mirrors.
func (c *Client) Categories(ctx context.Context) ([]Category, error) {
	return getResults[Category](ctx, c, "/tcgplayer/categories")
}

// Groups returns the sets within a category.
func (c *Client) Groups(ctx context.Context, categoryID int) ([]Group, error) {
	return getResults[Group](ctx, c, fmt.Sprintf("/tcgplayer/%d/groups", categoryID))
}

// Products returns the catalog for a group.
func (c *Client) Products(ctx context.Context, categoryID, groupID int) ([]Product, error) {
	return getResults[Product](ctx, c, fmt.Sprintf("/tcgplayer/%d/%d/products", categoryID, groupID))
}

// Prices returns the current prices for a group.
func (c *Client) Prices(ctx context.Context, categoryID, groupID int) ([]Price, error) {
	return getResults[Price](ctx, c, fmt.Sprintf("/tcgplayer/%d/%d/prices", categoryID, groupID))
}

// LastUpdated returns the timestamp of tcgcsv's most recent refresh. Callers
// gate a sync on this so we only pull when the upstream data is newer than what
// we already stored.
func (c *Client) LastUpdated(ctx context.Context) (time.Time, error) {
	body, status, err := c.do(ctx, c.baseURL+"/last-updated.txt")
	if err != nil {
		return time.Time{}, err
	}
	if status != http.StatusOK {
		return time.Time{}, fmt.Errorf("tcgcsv: last-updated -> %d: %s", status, snippet(body))
	}
	s := strings.TrimSpace(string(body))
	// e.g. "2026-06-30T20:05:27+0000" — offset has no colon.
	t, err := time.Parse("2006-01-02T15:04:05-0700", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("tcgcsv: parse last-updated %q: %w", s, err)
	}
	return t, nil
}

// getResults fetches a path and decodes the standard envelope. It is a free
// function because Go methods cannot take type parameters.
func getResults[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	body, status, err := c.do(ctx, c.baseURL+path)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("tcgcsv: %s -> %d: %s", path, status, snippet(body))
	}
	return decodeResults[T](body, path)
}

// decodeResults unmarshals an envelope and returns its results. Shared by the
// live endpoints and the historical archive reader.
func decodeResults[T any](data []byte, label string) ([]T, error) {
	var env envelope[T]
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("tcgcsv: decode %s: %w", label, err)
	}
	if !env.Success {
		return nil, fmt.Errorf("tcgcsv: %s: unsuccessful response: %v", label, env.Errors)
	}
	return env.Results, nil
}

// do issues a throttled GET, retrying transient failures (transport errors,
// 429, and 5xx) with a linear backoff bounded by maxRetries. It returns the
// body and HTTP status for any final non-retryable response; callers decide how
// to treat a non-200 (e.g. the archive reader maps 404 to "no data that day").
func (c *Client) do(ctx context.Context, url string) (body []byte, status int, err error) {
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			case <-time.After(c.retryWait * time.Duration(attempt)):
			}
		}
		c.wait()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("User-Agent", c.userAgent)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		b, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("tcgcsv: %s -> %s", url, resp.Status)
			continue
		}
		return b, resp.StatusCode, nil
	}
	return nil, 0, fmt.Errorf("tcgcsv: %s: giving up after %d attempts: %w", url, c.maxRetries+1, lastErr)
}

// wait enforces the minimum interval between requests, serializing callers so
// we stay a polite single-flight against tcgcsv.
func (c *Client) wait() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.throttle > 0 && !c.lastReq.IsZero() {
		if elapsed := time.Since(c.lastReq); elapsed < c.throttle {
			time.Sleep(c.throttle - elapsed)
		}
	}
	c.lastReq = time.Now()
}

func snippet(b []byte) string {
	const max = 200
	s := strings.TrimSpace(string(b))
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
