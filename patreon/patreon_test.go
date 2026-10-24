package patreon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

// identityResponse is Patreon's documented User example, in the v2 envelope,
// with invented ids; it is not a captured response. Swap in a captured body
// when one is available.
const identityResponse = `{"data":{"id":"12345678","attributes":{"email":"patron@example.com",
 "social_connections":{"deviantart":null,"discord":null,"facebook":null,"reddit":null,
 "spotify":null,"twitch":null,"twitter":null,"youtube":null},
 "is_email_verified":true,"full_name":"Patron Example"},
 "relationships":{"memberships":{"data":[{"id":"m1","type":"member"}]}}}}`

// withDiscordLinked swaps the null discord entry for a linked one.
func withDiscordLinked(body string) string {
	return strings.Replace(body, `"discord":null`, `"discord":{"user_id":"123456789012345678"}`, 1)
}

// withoutSocialConnections cuts the social_connections member (key, flat
// value and trailing comma) out of the body entirely. It applies to the
// base body only; it cuts at the first closing brace.
func withoutSocialConnections(body string) string {
	start := strings.Index(body, `"social_connections"`)
	closeBrace := strings.Index(body[start:], "}") + start
	return body[:start] + body[closeBrace+2:]
}

func TestUserDataDecodesDiscordLink(t *testing.T) {
	var u UserData
	err := json.Unmarshal([]byte(withDiscordLinked(identityResponse)), &u)
	if err != nil {
		t.Fatal(err)
	}
	id, known := u.DiscordUserID()
	if !known || id != "123456789012345678" {
		t.Fatalf("discord = %q known=%v, want 123456789012345678/true", id, known)
	}
	if u.Data.Attributes.Email != "patron@example.com" {
		t.Fatalf("email = %q, want patron@example.com", u.Data.Attributes.Email)
	}
	if !u.Data.Attributes.IsEmailVerified {
		t.Fatal("is_email_verified = false, want true")
	}
}

func TestUserDataDiscordUserIDExplicitNull(t *testing.T) {
	var u UserData
	err := json.Unmarshal([]byte(identityResponse), &u)
	if err != nil {
		t.Fatal(err)
	}
	id, known := u.DiscordUserID()
	if !known || id != "" {
		t.Fatalf("discord = %q known=%v, want empty/true", id, known)
	}
}

func TestUserDataDiscordUserIDAbsentField(t *testing.T) {
	var u UserData
	err := json.Unmarshal([]byte(withoutSocialConnections(identityResponse)), &u)
	if err != nil {
		t.Fatal(err)
	}
	id, known := u.DiscordUserID()
	if known || id != "" {
		t.Fatalf("discord = %q known=%v, want empty/false", id, known)
	}
}

// A numeric user_id fails the decode, since SocialConnection.UserID is
// a string.
func TestUserDataRejectsNumericDiscordUserID(t *testing.T) {
	body := strings.Replace(identityResponse, `"discord":null`, `"discord":{"user_id":123}`, 1)
	var u UserData
	err := json.Unmarshal([]byte(body), &u)
	if err == nil {
		t.Fatal("want an error decoding a numeric discord user_id, got nil")
	}
}

// answering is a transport that answers every request with code and body.
type answering struct {
	code int
	body string
}

func (a answering) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: a.code, Body: io.NopCloser(strings.NewReader(a.body)), Request: req}, nil
}

// A refused answer keeps the start of its body for the log, quoted, so an
// expired token, a missing scope and a deleted membership read apart.
func TestStatusErrorKeepsTheStartOfTheBody(t *testing.T) {
	scope := `{"errors":[{"code_name":"Forbidden","detail":"missing scope"}]}` + "\n"
	c := &Client{Client: &http.Client{Transport: answering{http.StatusForbidden, scope + strings.Repeat(" ", 1000)}}}
	_, err := c.GetMembershipData(context.Background(), "m1")
	var statusErr *StatusError
	if !errors.As(err, &statusErr) || len(statusErr.Body) != statusBodyLimit || !strings.HasPrefix(statusErr.Body, scope) {
		t.Fatalf("%v, want a StatusError holding the first %d bytes", err, statusBodyLimit)
	}
	if !strings.Contains(err.Error(), `missing scope\"}]}\n`) || strings.Contains(err.Error(), "\n") {
		t.Errorf("%q, want the body quoted on one line", err.Error())
	}
}

// A membership answer outside 2xx is a StatusError carrying the status, read
// before the body, which an edge serves as HTML; a 2xx body that does not
// decode is ErrUnreadable.
func TestMembershipStatusIsTyped(t *testing.T) {
	for _, tc := range []struct {
		code int
		body string
	}{
		{http.StatusBadGateway, "<html>502 Bad Gateway</html>"},
		{http.StatusNotFound, `{"errors":[{"title":"not found"}]}`},
	} {
		c := &Client{Client: &http.Client{Transport: answering{tc.code, tc.body}}}
		_, err := c.GetMembershipData(context.Background(), "m1")
		var statusErr *StatusError
		if !errors.As(err, &statusErr) || statusErr.StatusCode != tc.code {
			t.Errorf("%d: %v, want a StatusError", tc.code, err)
		}
	}
	c := &Client{Client: &http.Client{Transport: answering{http.StatusOK, `{"data":{}}`}}}
	_, err := c.GetMembershipData(context.Background(), "m1")
	if err != nil {
		t.Errorf("200: %v", err)
	}
	for _, body := range []string{`{"data":{"relat`, "<html>ok</html>"} {
		c = &Client{Client: &http.Client{Transport: answering{http.StatusOK, body}}}
		_, err = c.GetMembershipData(context.Background(), "m1")
		if !errors.Is(err, ErrUnreadable) {
			t.Errorf("200 %q: %v, want ErrUnreadable", body, err)
		}
	}
}

// fixture reads a body recorded from Patreon, with its tokens and ids
// replaced, from testdata.
func fixture(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// endpoint is a test server that answers every request with code and body,
// keeping what the last request sent.
type endpoint struct {
	server *httptest.Server
	code   int
	body   string

	method      string
	path        string
	contentType string
	form        url.Values
}

func serveAnswer(t *testing.T, code int, body string) *endpoint {
	t.Helper()
	e := &endpoint{code: code, body: body}
	e.server = httptest.NewServer(e)
	t.Cleanup(e.server.Close)
	return e
}

func (e *endpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.method = r.Method
	e.path = r.URL.Path
	e.contentType = r.Header.Get("Content-Type")
	r.ParseForm()
	e.form = r.PostForm
	w.WriteHeader(e.code)
	w.Write([]byte(e.body))
}

// via is a transport that sends every request to the test server, whatever
// address it names.
type via struct {
	server *httptest.Server
}

func (v via) RoundTrip(req *http.Request) (*http.Response, error) {
	target, err := url.Parse(v.server.URL)
	if err != nil {
		return nil, err
	}
	req = req.Clone(req.Context())
	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host
	return v.server.Client().Transport.RoundTrip(req)
}

// client is an HTTP client that reaches the test server.
func (e *endpoint) client() *http.Client {
	return &http.Client{Transport: via{e.server}}
}

// ctx is a context whose token calls reach the test server.
func (e *endpoint) ctx() context.Context {
	return context.WithValue(context.Background(), oauth2.HTTPClient, e.client())
}

// The code exchange sends the authorization_code grant to the token endpoint
// and reads every key of the recorded answer.
func TestGetAuthTokenReadsTheRecordedAnswer(t *testing.T) {
	e := serveAnswer(t, http.StatusOK, fixture(t, "token-success.json"))
	tokens, err := GetAuthToken(e.ctx(), "the-client", "the-secret", "https://mtgban.test", "the-code")
	if err != nil {
		t.Fatal(err)
	}

	want := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"the-client"},
		"client_secret": {"the-secret"},
		"redirect_uri":  {"https://mtgban.test/auth"},
		"code":          {"the-code"},
	}
	if e.method != http.MethodPost || e.path != "/api/oauth2/token" || e.contentType != "application/x-www-form-urlencoded" || e.form.Encode() != want.Encode() {
		t.Errorf("sent %s %s %q %v, want a form POST of %v to /api/oauth2/token", e.method, e.path, e.contentType, e.form, want)
	}
	if tokens.TokenType != "Bearer" || tokens.AccessToken != "redacted-access-token-xxxxxxxxxxxxxxxxxxxxx" ||
		tokens.RefreshToken != "redacted-refresh-token-xxxxxxxxxxxxxxxxxxxx" || tokens.Expires != 353103131 {
		t.Errorf("read %+v from the recorded answer", tokens)
	}
	if !strings.Contains(tokens.Scope, "identity.memberships") || !strings.Contains(tokens.Scope, "campaigns.members") {
		t.Errorf("scope = %q, want the recorded scopes", tokens.Scope)
	}
}

// A refused exchange is a StatusError even when its body is JSON, which used
// to decode into an empty AuthToken with no error; a 2xx body that is not the
// token answer, an access token missing included, is ErrUnreadable.
func TestGetAuthTokenStatusIsTyped(t *testing.T) {
	for name, tc := range map[string]struct {
		code int
		body string
	}{
		"an OAuth error body": {http.StatusUnauthorized, `{"error":"invalid_grant"}`},
		"a throttle":          {http.StatusTooManyRequests, fixture(t, "membership-throttled.json")},
		"an edge's 502":       {http.StatusBadGateway, "<html>502 Bad Gateway</html>"},
	} {
		e := serveAnswer(t, tc.code, tc.body)
		tokens, err := GetAuthToken(e.ctx(), "the-client", "the-secret", "https://mtgban.test", "the-code")
		var statusErr *StatusError
		if !errors.As(err, &statusErr) || statusErr.StatusCode != tc.code || statusErr.Body != tc.body || tokens != nil {
			t.Errorf("%s: %+v, %v, want a StatusError %d holding the body", name, tokens, err, tc.code)
		}
	}
	for _, body := range []string{`{"access_token":"a`, "<html>ok</html>", "", `{}`, `{"token_type":"Bearer","refresh_token":"r","expires_in":60}`, `{"access_token":"","refresh_token":"r"}`} {
		e := serveAnswer(t, http.StatusOK, body)
		tokens, err := GetAuthToken(e.ctx(), "the-client", "the-secret", "https://mtgban.test", "the-code")
		if !errors.Is(err, ErrUnreadable) || tokens != nil {
			t.Errorf("200 %q: %+v, %v, want ErrUnreadable", body, tokens, err)
		}
	}
}

// Missing credentials stop the exchange before a request is made.
func TestGetAuthTokenNeedsCredentials(t *testing.T) {
	e := serveAnswer(t, http.StatusOK, fixture(t, "token-success.json"))
	_, err := GetAuthToken(e.ctx(), "", "the-secret", "https://mtgban.test", "the-code")
	if err == nil || e.method != "" {
		t.Errorf("no client id: %v after a %q request, want an error and no request", err, e.method)
	}
}

// An identity answer outside 2xx is a StatusError, the recorded 401 among
// them, which used to decode into a UserData carrying its errors; a 2xx body
// that does not decode is ErrUnreadable.
func TestGetUserDataStatusIsTyped(t *testing.T) {
	for name, tc := range map[string]struct {
		code int
		body string
	}{
		"a dead token":  {http.StatusUnauthorized, fixture(t, "identity-unauthorized.json")},
		"a throttle":    {http.StatusTooManyRequests, fixture(t, "membership-throttled.json")},
		"an edge's 502": {http.StatusBadGateway, "<html>502 Bad Gateway</html>"},
	} {
		e := serveAnswer(t, tc.code, tc.body)
		c := &Client{Client: e.client()}
		userData, err := c.GetUserData(context.Background())
		var statusErr *StatusError
		if !errors.As(err, &statusErr) || statusErr.StatusCode != tc.code || statusErr.Body != tc.body || userData != nil {
			t.Errorf("%s: %+v, %v, want a StatusError %d holding the body", name, userData, err, tc.code)
		}
	}
	for _, body := range []string{`{"data":{"attrib`, "<html>ok</html>"} {
		e := serveAnswer(t, http.StatusOK, body)
		c := &Client{Client: e.client()}
		_, err := c.GetUserData(context.Background())
		if !errors.Is(err, ErrUnreadable) {
			t.Errorf("200 %q: %v, want ErrUnreadable", body, err)
		}
	}
	e := serveAnswer(t, http.StatusOK, identityResponse)
	c := &Client{Client: e.client()}
	userData, err := c.GetUserData(context.Background())
	if err != nil || userData.Data.Attributes.Email != "patron@example.com" {
		t.Errorf("200: %+v, %v, want the identity", userData, err)
	}
}

// The refresh sends the refresh_token grant to the token endpoint and reads
// every key of the recorded answer.
func TestRefreshAuthTokenReadsTheRecordedAnswer(t *testing.T) {
	e := serveAnswer(t, http.StatusOK, fixture(t, "refresh-success.json"))
	tokens, err := RefreshAuthToken(e.ctx(), "the-client", "the-secret", "the-refresh-token")
	if err != nil {
		t.Fatal(err)
	}

	want := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"the-refresh-token"},
		"client_id":     {"the-client"},
		"client_secret": {"the-secret"},
	}
	if e.method != http.MethodPost || e.path != "/api/oauth2/token" || e.contentType != "application/x-www-form-urlencoded" || e.form.Encode() != want.Encode() {
		t.Errorf("sent %s %s %q %v, want a form POST of %v to /api/oauth2/token", e.method, e.path, e.contentType, e.form, want)
	}
	if tokens.TokenType != "Bearer" || tokens.AccessToken != "redacted-rotated-access-token" ||
		tokens.RefreshToken != "redacted-rotated-refresh-token" || tokens.Expires != 353103063 {
		t.Errorf("read %+v from the recorded answer", tokens)
	}
	if !strings.Contains(tokens.Scope, "identity.memberships") || !strings.Contains(tokens.Scope, "campaigns.members") {
		t.Errorf("scope = %q, want the recorded scopes", tokens.Scope)
	}
}

// A spent refresh token is a GrantError coded invalid_grant, on the 401 that
// was recorded and on the RFC's 400, and the StatusError under it is still
// there to find, however far the error is wrapped.
func TestRefreshAuthTokenInvalidGrant(t *testing.T) {
	body := fixture(t, "refresh-invalid-grant.json")
	for _, code := range []int{http.StatusUnauthorized, http.StatusBadRequest} {
		e := serveAnswer(t, code, body)
		tokens, err := RefreshAuthToken(e.ctx(), "the-client", "the-secret", "the-refresh-token")
		wrapped := fmt.Errorf("renew: %w", err)
		var grantErr *GrantError
		if !errors.As(wrapped, &grantErr) || grantErr.Code != InvalidGrant || tokens != nil {
			t.Errorf("%d: %+v, %v, want a GrantError coded %q", code, tokens, err, InvalidGrant)
			continue
		}
		var statusErr *StatusError
		if !errors.As(wrapped, &statusErr) || statusErr.StatusCode != code || statusErr.Body != body {
			t.Errorf("%d: %v, want the StatusError under the GrantError", code, err)
		}
		if !strings.Contains(err.Error(), `"invalid_grant"`) || !strings.Contains(err.Error(), http.StatusText(code)) {
			t.Errorf("%d: %q, want the code and the status in the message", code, err.Error())
		}
	}
}

// Every other refusal stays a plain StatusError: the recorded dead-token and
// throttle answers, an OAuth error under another status, and a 400 or 401
// whose body is not an object with an error string.
func TestRefreshAuthTokenOtherRefusalsAreStatusErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		code int
		body string
	}{
		"a JSON:API 401":        {http.StatusUnauthorized, fixture(t, "identity-unauthorized.json")},
		"a throttle":            {http.StatusTooManyRequests, fixture(t, "membership-throttled.json")},
		"invalid_grant on 403":  {http.StatusForbidden, `{"error":"invalid_grant"}`},
		"an OAuth error on 500": {http.StatusInternalServerError, `{"error":"server_error"}`},
		"an edge's 502":         {http.StatusBadGateway, "<html>502 Bad Gateway</html>"},
		"a 503":                 {http.StatusServiceUnavailable, ""},
		"an empty error":        {http.StatusBadRequest, `{"error":""}`},
		"an error list":         {http.StatusBadRequest, `{"error":["invalid_grant"]}`},
		"an HTML 400":           {http.StatusBadRequest, "<html>400</html>"},
		"an empty 401":          {http.StatusUnauthorized, ""},
	} {
		e := serveAnswer(t, tc.code, tc.body)
		tokens, err := RefreshAuthToken(e.ctx(), "the-client", "the-secret", "the-refresh-token")
		var statusErr *StatusError
		var grantErr *GrantError
		if !errors.As(err, &statusErr) || statusErr.StatusCode != tc.code || statusErr.Body != tc.body || tokens != nil {
			t.Errorf("%s: %+v, %v, want a StatusError %d holding the body", name, tokens, err, tc.code)
		}
		if errors.As(err, &grantErr) {
			t.Errorf("%s: %v, want no GrantError", name, err)
		}
	}
}

// A 2xx answer that is not a token pair is never a success: cut short, not
// JSON, empty, or missing either token.
func TestRefreshAuthTokenUnreadableAnswers(t *testing.T) {
	for name, body := range map[string]string{
		"cut short":              `{"access_token":"a`,
		"html":                   "<html>ok</html>",
		"nothing":                "",
		"an empty object":        `{}`,
		"no refresh token":       `{"token_type":"Bearer","access_token":"a","expires_in":60}`,
		"no access token":        `{"token_type":"Bearer","refresh_token":"r","expires_in":60}`,
		"an empty access token":  `{"access_token":"","refresh_token":"r"}`,
		"an empty refresh token": `{"access_token":"a","refresh_token":""}`,
	} {
		e := serveAnswer(t, http.StatusOK, body)
		tokens, err := RefreshAuthToken(e.ctx(), "the-client", "the-secret", "the-refresh-token")
		var statusErr *StatusError
		if !errors.Is(err, ErrUnreadable) || errors.As(err, &statusErr) || tokens != nil {
			t.Errorf("%s: %+v, %v, want ErrUnreadable", name, tokens, err)
		}
	}
}

// failing is a transport that never reaches Patreon.
type failing struct {
	err error
}

func (f failing) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, f.err
}

// A request that never gets an answer is neither a refusal nor an unreadable
// answer, and the cause stays in the chain.
func TestRefreshAuthTokenTransportErrors(t *testing.T) {
	errNoRoute := errors.New("no route to host")
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Transport: failing{errNoRoute}})
	tokens, err := RefreshAuthToken(ctx, "the-client", "the-secret", "the-refresh-token")
	var statusErr *StatusError
	if !errors.Is(err, errNoRoute) || errors.As(err, &statusErr) || errors.Is(err, ErrUnreadable) || tokens != nil {
		t.Errorf("%+v, %v, want the transport's error", tokens, err)
	}

	e := serveAnswer(t, http.StatusOK, fixture(t, "refresh-success.json"))
	ctx, cancel := context.WithCancel(e.ctx())
	cancel()
	_, err = RefreshAuthToken(ctx, "the-client", "the-secret", "the-refresh-token")
	if !errors.Is(err, context.Canceled) || e.method != "" {
		t.Errorf("%v after a %q request, want context.Canceled and no request", err, e.method)
	}
}

// Without a client, secret or refresh token no request is made.
func TestRefreshAuthTokenNeedsCredentials(t *testing.T) {
	e := serveAnswer(t, http.StatusOK, fixture(t, "refresh-success.json"))
	for name, args := range map[string][3]string{
		"no client":        {"", "the-secret", "the-refresh-token"},
		"no secret":        {"the-client", "", "the-refresh-token"},
		"no refresh token": {"the-client", "the-secret", ""},
	} {
		_, err := RefreshAuthToken(e.ctx(), args[0], args[1], args[2])
		if err == nil || e.method != "" {
			t.Errorf("%s: %v after a %q request, want an error and no request", name, err, e.method)
		}
	}
}

// The code exchange refuses with the same typing, a GrantError over its
// StatusError.
func TestGetAuthTokenOAuthErrorIsAGrantError(t *testing.T) {
	e := serveAnswer(t, http.StatusBadRequest, `{"error":"invalid_grant"}`)
	_, err := GetAuthToken(e.ctx(), "the-client", "the-secret", "https://mtgban.test", "the-code")
	var grantErr *GrantError
	var statusErr *StatusError
	if !errors.As(err, &grantErr) || grantErr.Code != InvalidGrant || !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusBadRequest {
		t.Errorf("%v, want a GrantError over a StatusError 400", err)
	}
}
