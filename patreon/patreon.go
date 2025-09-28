package patreon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/go-cleanhttp"
	"golang.org/x/oauth2"
)

type AuthToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Expires      int    `json:"expires_in"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

const (
	PatreonTokenURL    = "https://www.patreon.com/api/oauth2/token"
	PatreonIdentityURL = "https://www.patreon.com/api/oauth2/v2/identity?include=memberships&fields%5Buser%5D=email,first_name,full_name,image_url,last_name,social_connections,thumb_url,url,vanity"
	PatreonMemberURL   = "https://www.patreon.com/api/oauth2/v2/members/"
	PatreonMemberOpts  = "?include=currently_entitled_tiers&fields%5Btier%5D=title"
)

func GetAuthToken(ctx context.Context, clientId, secret, redirectURI, code string) (*AuthToken, error) {
	if clientId == "" || secret == "" {
		return nil, fmt.Errorf("missing client or secret information")
	}

	payload := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientId},
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

type Client struct {
	Client *http.Client
}

func NewPatreonClient(ctx context.Context, token string) *Client {
	ts := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: token,
	})

	var client Client
	client.Client = oauth2.NewClient(ctx, ts)
	return &client
}

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
					Id   string `json:"id"`
					Type string `json:"type"`
				} `json:"data"`
			} `json:"memberships"`
		} `json:"relationships"`
		IdV1 string `json:"id"`
	} `json:"data"`
}

// Retrieve a user id for each membership of the current user
// Only what is visible through the token is actually reported
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
					Id   string `json:"id"`
					Type string `json:"type"`
				} `json:"data"`
			} `json:"currently_entitled_tiers"`
		} `json:"relationships"`
	} `json:"data"`
	Included []struct {
		Attributes struct {
			Title string `json:"title"`
		} `json:"attributes"`
		Id   string `json:"id"`
		Type string `json:"type"`
	} `json:"included"`
}

func (c *Client) GetMembershipData(ctx context.Context, userId string) (*MembershipData, error) {
	link := PatreonMemberURL + userId + PatreonMemberOpts
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
