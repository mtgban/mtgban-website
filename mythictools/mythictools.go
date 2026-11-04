// Package mythictools reads public collection lists from Mythic Tools.
//
// The site publishes no API for this. Load reads the credentials its web
// client uses off the list's page and signs each request the way that client
// does, so a change on their side shows up as a failed upload, not bad data.
package mythictools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/mtgban/go-mtgban/mtgban"
)

const (
	siteBase = "https://mythic.tools"
	apiBase  = "https://api.mythic.tools"
)

// client gives up on a stalled Mythic Tools rather than holding the upload,
// and retries nothing, so one that is down fails at once.
var client = mtgban.NewHTTPClient(
	mtgban.WithHTTPTimeout(30*time.Second),
	mtgban.WithHTTPRetries(0),
	// Hand back a 5xx as it came, for the status check to report
	mtgban.WithHTTPErrorHandler(retryablehttp.PassthroughErrorHandler),
)

const (
	// A list page takes about 200 KB
	maxPageBody = 4 << 20
	// A full page of rows takes about 190 KB
	maxAPIBody = 8 << 20
	// What the site's own client asks for; it counts copies, not rows
	pageSize = 50
	// loadTimeout bounds a whole walk, one fetch per page: 15,000 copies is
	// 300 pages, about 150 s at the half second a page takes to arrive
	loadTimeout = 3 * time.Minute
)

// Item is one card row from a public Mythic Tools list.
type Item struct {
	ScryfallID string
	Name       string
	Quantity   int
	IsFoil     bool
	IsEtched   bool
	Condition  mtgban.Condition
}

// conditionMap folds the site's seven grades onto ours. Its importer reads
// "slightly played" as LP, "moderately played" as PL and "damaged" as P.
var conditionMap = map[string]mtgban.Condition{
	"M":  mtgban.NM,
	"NM": mtgban.NM,
	"EX": mtgban.SP,
	"G":  mtgban.SP,
	"LP": mtgban.SP,
	"PL": mtgban.MP,
	"P":  mtgban.PO,
}

type listPayload struct {
	List struct {
		Name       string `json:"name"`
		Pagination struct {
			HasNext bool `json:"has_next"`
		} `json:"pagination"`
		Cards []struct {
			ListCardID int `json:"list_card_id"`
			// cardid is the site's own id, scryfallid the one the matcher knows
			ScryfallID string `json:"scryfallid"`
			Name       string `json:"name"`
			Quantity   int    `json:"quantity"`
			Finish     string `json:"finish"`
			Condition  string `json:"condition"`
			Proxy      bool   `json:"proxy"`
		} `json:"cards"`
	} `json:"list"`
}

// session is what the list's page gives away: the numeric ids the API takes
// and the web client's credentials.
type session struct {
	userID, listID string
	apiKey, webKey string
	slug1, slug2   string
}

var (
	listIDsRE = regexp.MustCompile(`share-meta-list-(\d+)-(\d+)`)
	apiKeyRE  = regexp.MustCompile(`MYTHIC_API_KEY:"([^"]+)"`)
	webKeyRE  = regexp.MustCompile(`MYTHIC_WEB_KEY:"([^"]+)"`)
	slug1RE   = regexp.MustCompile(`SLUG_1:"([^"]+)"`)
	slug2RE   = regexp.MustCompile(`SLUG_2:"([^"]+)"`)
)

// ParseListURL extracts the user and list share ids from a
// mythic.tools/user/<user>/collection/list/<list> URL.
func ParseListURL(raw string) (string, string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", errors.New("invalid Mythic Tools URL")
	}
	host := strings.ToLower(u.Host)
	if host != "mythic.tools" && host != "www.mythic.tools" {
		return "", "", errors.New("invalid Mythic Tools URL")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 5 || parts[0] != "user" || parts[2] != "collection" || parts[3] != "list" {
		return "", "", errors.New("invalid Mythic Tools list URL")
	}
	if !isShareID(parts[1]) || !isShareID(parts[4]) {
		return "", "", errors.New("invalid Mythic Tools list URL")
	}
	return parts[1], parts[4], nil
}

// isShareID keeps the ids to the characters the site's links are made of, so
// neither one can move the page request off the list.
func isShareID(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return true
}

// Load fetches a public Mythic Tools list by its URL and returns its cards
// plus the list name. Rows marked as a proxy are skipped, since a proxy is not
// a card worth anything.
func Load(ctx context.Context, link string, maxRows int) ([]Item, string, error) {
	return load(ctx, siteBase, apiBase, link, maxRows)
}

func load(ctx context.Context, site, api, link string, maxRows int) ([]Item, string, error) {
	userShare, listShare, err := ParseListURL(link)
	if err != nil {
		return nil, "", err
	}

	// One deadline for every page, since a list can run to hundreds of them
	ctx, cancel := context.WithTimeout(ctx, loadTimeout)
	defer cancel()

	sess, err := fetchSession(ctx, site+"/user/"+userShare+"/collection/list/"+listShare)
	if err != nil {
		return nil, "", err
	}

	var items []Item
	name := listShare
	lastFirstRow := 0
	for page := 1; ; page++ {
		payload, err := fetchPage(ctx, api, sess, page)
		if err != nil {
			return nil, "", err
		}
		if payload.List.Name != "" {
			name = payload.List.Name
		}
		if len(payload.List.Cards) == 0 {
			return items, name, nil
		}
		// A page answered twice would pass its rows off as more of the list;
		// a row with no id proves nothing either way
		firstRow := payload.List.Cards[0].ListCardID
		if firstRow != 0 && firstRow == lastFirstRow {
			return nil, "", fmt.Errorf("mythic tools repeated page %d", page-1)
		}
		lastFirstRow = firstRow
		for _, c := range payload.List.Cards {
			if c.Proxy || c.Quantity <= 0 || c.ScryfallID == "" {
				continue
			}
			if maxRows > 0 && len(items) >= maxRows {
				return items, name, nil
			}
			items = append(items, Item{
				ScryfallID: c.ScryfallID,
				Name:       c.Name,
				Quantity:   c.Quantity,
				IsFoil:     c.Finish == "foil",
				IsEtched:   c.Finish == "etched",
				Condition:  conditionMap[c.Condition],
			})
		}
		if !payload.List.Pagination.HasNext {
			return items, name, nil
		}
	}
}

func fetchSession(ctx context.Context, pageURL string) (*session, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/html")
	req.Header.Set("User-Agent", "mtgban-website/mythictools")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mythic tools returned status %d", resp.StatusCode)
	}
	return parseSession(io.LimitReader(resp.Body, maxPageBody))
}

func parseSession(page io.Reader) (*session, error) {
	doc, err := goquery.NewDocumentFromReader(page)
	if err != nil {
		return nil, fmt.Errorf("read Mythic Tools page: %w", err)
	}
	scripts := doc.Find("script").Text()

	ids := listIDsRE.FindStringSubmatch(scripts)
	if ids == nil {
		return nil, errors.New("no public Mythic Tools list on this page")
	}
	sess := &session{
		userID: ids[1],
		listID: ids[2],
		apiKey: firstGroup(apiKeyRE, scripts),
		webKey: firstGroup(webKeyRE, scripts),
		slug1:  firstGroup(slug1RE, scripts),
		slug2:  firstGroup(slug2RE, scripts),
	}
	if sess.apiKey == "" || sess.webKey == "" || sess.slug1 == "" || sess.slug2 == "" {
		return nil, errors.New("no Mythic Tools credentials on this page")
	}
	return sess, nil
}

func firstGroup(re *regexp.Regexp, s string) string {
	match := re.FindStringSubmatch(s)
	if match == nil {
		return ""
	}
	return match[1]
}

// signature is the web client's request signature over a millisecond timestamp.
func (s *session) signature(timestamp string) string {
	sum := sha256.Sum256([]byte(s.slug1 + "+/" + timestamp + "." + s.webKey + "/+" + s.slug2 + "!"))
	return hex.EncodeToString(sum[:])
}

func fetchPage(ctx context.Context, api string, sess *session, page int) (*listPayload, error) {
	query := url.Values{
		"page":               {strconv.Itoa(page)},
		"limit":              {strconv.Itoa(pageSize)},
		"order_by":           {"added_at"},
		"order_direction":    {"desc"},
		"currency":           {"USD"},
		"ignore_basic_lands": {"false"},
	}
	link := api + "/user/" + sess.userID + "/list/" + sess.listID + "?" + query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, http.NoBody)
	if err != nil {
		return nil, err
	}
	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "mtgban-website/mythictools")
	req.Header.Set("x-api-key", sess.apiKey)
	req.Header.Set("x-mythic-signature", sess.signature(timestamp))
	req.Header.Set("x-mythic-timestamp", timestamp)
	req.Header.Set("x-mythic-device", "web")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mythic tools returned status %d", resp.StatusCode)
	}

	var payload listPayload
	err = json.NewDecoder(io.LimitReader(resp.Body, maxAPIBody)).Decode(&payload)
	if err != nil {
		return nil, fmt.Errorf("decode Mythic Tools list: %w", err)
	}
	return &payload, nil
}
