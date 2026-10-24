package patreon

import (
	"context"
	"encoding/json"
	"errors"
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
