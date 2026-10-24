// Package patreon holds the OAuth client behind the site's Patreon login.
package patreon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	PatreonIdentityURL = "https://www.patreon.com/api/oauth2/v2/identity?include=memberships&fields%5Buser%5D=email,is_email_verified,first_name,full_name,image_url,last_name,social_connections,thumb_url,url,vanity"
	PatreonMemberURL   = "https://www.patreon.com/api/oauth2/v2/members/"
	PatreonMemberOpts  = "?include=currently_entitled_tiers&fields%5Btier%5D=title"
)

// GetAuthToken exchanges an OAuth authorization code for a token; a status
// outside 2xx is a *StatusError, or the *GrantError wrapping it where the body
// names an OAuth error, and a body that does not decode ErrUnreadable.
func GetAuthToken(ctx context.Context, clientID, secret, redirectURI, code string) (*AuthToken, error) {
	if clientID == "" || secret == "" {
		return nil, errors.New("missing client or secret information")
	}

	return postToken(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"client_secret": {secret},
		"redirect_uri":  {redirectURI + "/auth"},
		"code":          {code},
	})
}

// RefreshAuthToken trades a refresh token for a new token pair. Patreon keeps
// one pair per user and client, so the answer replaces it: the access token
// and the refresh token sent are dead from then on, and so is any other copy
// of them. A refresh token Patreon does not honour is a *GrantError coded
// InvalidGrant, any other status outside 2xx a *StatusError, and a 2xx answer
// without either token ErrUnreadable.
func RefreshAuthToken(ctx context.Context, clientID, secret, refreshToken string) (*AuthToken, error) {
	if clientID == "" || secret == "" || refreshToken == "" {
		return nil, errors.New("missing client, secret or refresh token information")
	}

	tokens, err := postToken(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
		"client_secret": {secret},
	})
	if err != nil {
		return nil, err
	}
	if tokens.RefreshToken == "" {
		return nil, fmt.Errorf("%w: refresh answer without a refresh token", ErrUnreadable)
	}

	return tokens, nil
}

// postToken sends one grant to the token endpoint and reads its answer,
// typed as GetAuthToken documents.
func postToken(ctx context.Context, grant url.Values) (*AuthToken, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, PatreonTokenURL, strings.NewReader(grant.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := tokenHTTPClient(ctx).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tokens AuthToken
	err = decodeAnswer(resp, &tokens)
	var statusErr *StatusError
	if errors.As(err, &statusErr) {
		return nil, grantRefusal(statusErr)
	}
	if err != nil {
		return nil, err
	}

	if tokens.AccessToken == "" {
		return nil, fmt.Errorf("%w: token answer without an access token", ErrUnreadable)
	}

	return &tokens, nil
}

// grantRefusal is a refused token answer as the caller can tell it: a
// *GrantError when the status is 400 or 401 and the body is an object with a
// non-empty "error" string, else the *StatusError itself.
func grantRefusal(statusErr *StatusError) error {
	if statusErr.StatusCode != http.StatusBadRequest && statusErr.StatusCode != http.StatusUnauthorized {
		return statusErr
	}

	var refusal struct {
		Error string `json:"error"`
	}
	err := json.Unmarshal([]byte(statusErr.Body), &refusal)
	if err != nil || refusal.Error == "" {
		return statusErr
	}

	return &GrantError{Code: refusal.Error, Status: statusErr}
}

// tokenHTTPClient is the client the token calls go through: the one ctx
// carries under oauth2.HTTPClient, which NewPatreonClient also takes its
// transport from, else a clean one.
func tokenHTTPClient(ctx context.Context) *http.Client {
	client, ok := ctx.Value(oauth2.HTTPClient).(*http.Client)
	if ok {
		return client
	}
	return cleanhttp.DefaultClient()
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

// SocialConnection is one linked platform, as Patreon reports it.
type SocialConnection struct {
	UserID string `json:"user_id"`
}

// UserData is the identity answer: the user and their memberships.
type UserData struct {
	Errors []struct {
		Title    string `json:"title"`
		CodeName string `json:"code_name"`
	} `json:"errors"`
	Data struct {
		Attributes struct {
			Email           string `json:"email"`
			IsEmailVerified bool   `json:"is_email_verified"`
			FullName        string `json:"full_name"`
			// SocialConnections is nil when the identity request's field
			// list omits it; Discord is nil when no account is linked.
			SocialConnections *struct {
				Discord *SocialConnection `json:"discord"`
			} `json:"social_connections"`
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
// memberships - only what the token can see is reported. A status outside
// 2xx is a *StatusError, and a body that does not decode ErrUnreadable.
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
	err = decodeAnswer(resp, &userData)
	if err != nil {
		return nil, err
	}

	return &userData, nil
}

// DiscordUserID reads the linked Discord id; known is false when Patreon
// gave no answer, true when it did, even if that answer is no link. A
// non-object discord value fails the identity decode, and so the login.
func (u *UserData) DiscordUserID() (id string, known bool) {
	conns := u.Data.Attributes.SocialConnections
	if conns == nil {
		return "", false
	}
	if conns.Discord == nil {
		return "", true
	}
	return conns.Discord.UserID, true
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

// StatusError is a Patreon answer with a status outside 2xx. Its body is kept
// only as text for the log, since an edge's 502 page is not JSON.
type StatusError struct {
	StatusCode int
	// Body is the answer's first statusBodyLimit bytes
	Body string
}

// statusBodyLimit is how much of a refused answer StatusError keeps.
const statusBodyLimit = 512

func (e *StatusError) Error() string {
	return fmt.Sprintf("patreon answered %d %s: %q", e.StatusCode, http.StatusText(e.StatusCode), e.Body)
}

// InvalidGrant is the GrantError code of a refresh token Patreon does not
// honour: spent, replaced by a later refresh, or revoked.
const InvalidGrant = "invalid_grant"

// GrantError is the token endpoint refusing a grant: a 400 or 401 whose body
// is an OAuth error object. It unwraps to the answer's *StatusError.
type GrantError struct {
	// Code is the body's "error" value, such as InvalidGrant
	Code   string
	Status *StatusError
}

func (e *GrantError) Error() string {
	return fmt.Sprintf("patreon refused the grant %q: %v", e.Code, e.Status)
}

// Unwrap returns the answer's StatusError.
func (e *GrantError) Unwrap() error {
	return e.Status
}

// ErrUnreadable is a 2xx answer whose body is not the JSON asked for: cut
// short, or not JSON at all.
var ErrUnreadable = errors.New("patreon answer unreadable")

// GetMembershipData retrieves the entitled tiers of one membership; a status
// outside 2xx is a *StatusError, and a body that does not decode
// ErrUnreadable.
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
	err = decodeAnswer(resp, &membershipData)
	if err != nil {
		return nil, err
	}

	return &membershipData, nil
}

// decodeAnswer reads one Patreon answer into v: a status outside 2xx is a
// *StatusError, read before the body, which an edge serves as HTML, and a 2xx
// body that does not decode ErrUnreadable.
func decodeAnswer(resp *http.Response, v any) error {
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, statusBodyLimit))
		return &StatusError{StatusCode: resp.StatusCode, Body: string(body)}
	}

	err := json.NewDecoder(resp.Body).Decode(v)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnreadable, err)
	}

	return nil
}
