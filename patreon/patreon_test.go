package patreon

import (
	"encoding/json"
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
