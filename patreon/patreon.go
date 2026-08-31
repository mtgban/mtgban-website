// Package patreon holds the OAuth client behind the site's Patreon login.
package patreon

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/go-cleanhttp"
	"golang.org/x/oauth2"
)

// AuthToken is what the OAuth token exchange answers with.
type AuthToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Expires      int    `json:"expires_in"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

// The Patreon OAuth endpoints, with the field selections the site reads.
const (
	PatreonTokenURL    = "https://www.patreon.com/api/oauth2/token"
	PatreonIdentityURL = "https://www.patreon.com/api/oauth2/v2/identity?include=memberships&fields%5Buser%5D=email,first_name,full_name,image_url,last_name,social_connections,thumb_url,url,vanity"
	PatreonMemberURL   = "https://www.patreon.com/api/oauth2/v2/members/"
	PatreonMemberOpts  = "?include=currently_entitled_tiers&fields%5Btier%5D=title"
)

// GetAuthToken exchanges an OAuth authorization code for a token.
func GetAuthToken(ctx context.Context, clientID, secret, redirectURI, code string) (*AuthToken, error) {
	if clientID == "" || secret == "" {
		return nil, errors.New("missing client or secret information")
	}

	payload := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"client_secret": {secret},
		"redirect_uri":  {redirectURI + "/auth"},
		"code":          {code},
	}.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, PatreonTokenURL, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := cleanhttp.DefaultClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tokens AuthToken
	err = json.NewDecoder(resp.Body).Decode(&tokens)
	if err != nil {
		return nil, err
	}

	return &tokens, nil
}

// Client reads the Patreon API on behalf of one logged-in user.
type Client struct {
	Client *http.Client
}

// NewPatreonClient returns a client authenticated with the given token.
func NewPatreonClient(ctx context.Context, token string) *Client {
	ts := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: token,
	})

	var client Client
	client.Client = oauth2.NewClient(ctx, ts)
	return &client
}

// UserData is the identity answer: the user and their memberships.
type UserData struct {
	Errors []struct {
		Title    string `json:"title"`
		CodeName string `json:"code_name"`
	} `json:"errors"`
	Data struct {
		Attributes struct {
			Email    string `json:"email"`
			FullName string `json:"full_name"`
		} `json:"attributes"`
		Relationships struct {
			Memberships struct {
				Data []struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				} `json:"data"`
			} `json:"memberships"`
		} `json:"relationships"`
		IDV1 string `json:"id"`
	} `json:"data"`
}

// GetUserData retrieves the current user and an id for each of their
// memberships - only what the token can see is reported.
func (c *Client) GetUserData(ctx context.Context) (*UserData, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, PatreonIdentityURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var userData UserData
	err = json.NewDecoder(resp.Body).Decode(&userData)
	if err != nil {
		return nil, err
	}

	return &userData, nil
}

// MembershipData is the membership answer: the tiers a pledge entitles.
type MembershipData struct {
	Errors []struct {
		Title    string `json:"title"`
		CodeName string `json:"code_name"`
		Detail   string `json:"detail"`
	} `json:"errors"`
	Data struct {
		Relationships struct {
			CurrentlyEntitledTiers struct {
				Data []struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				} `json:"data"`
			} `json:"currently_entitled_tiers"`
		} `json:"relationships"`
	} `json:"data"`
	Included []struct {
		Attributes struct {
			Title string `json:"title"`
		} `json:"attributes"`
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"included"`
}

// GetMembershipData retrieves the entitled tiers of one membership.
func (c *Client) GetMembershipData(ctx context.Context, userID string) (*MembershipData, error) {
	link := PatreonMemberURL + userID + PatreonMemberOpts
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var membershipData MembershipData
	err = json.NewDecoder(resp.Body).Decode(&membershipData)
	if err != nil {
		return nil, err
	}

	return &membershipData, nil
}
