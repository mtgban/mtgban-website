package patreon

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
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
