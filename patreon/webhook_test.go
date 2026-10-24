package patreon

import (
	"os"
	"strings"
	"testing"
)

// The signature is the hex HMAC-MD5 of the body: RFC 2202's test case 2, whose
// answer no test here computes.
func TestWebhookSignatureIsHMACMD5(t *testing.T) {
	const vector = "750c783e6ab0b503eaa86e310a5db738"
	body := []byte("what do ya want for nothing?")
	if WebhookSignature("Jefe", body) != vector {
		t.Errorf("the signer gives %s, want RFC 2202's %s", WebhookSignature("Jefe", body), vector)
	}
	if !WebhookSigned("Jefe", body, vector) {
		t.Error("the HMAC-MD5 of RFC 2202's second case does not verify")
	}
	if !WebhookSigned("Jefe", body, strings.ToUpper(vector)) {
		t.Error("the same signature in capitals does not verify")
	}
	for name, header := range map[string]string{"cut short": vector[:30], "empty": "", "under another key": WebhookSignature("Jefa", body), "of another body": WebhookSignature("Jefe", []byte("{}"))} {
		if WebhookSigned("Jefe", body, header) {
			t.Errorf("a signature %s verifies", name)
		}
	}
}

// The member's email is all a delivery gives up, lowercased and trimmed; a
// body with none, or no body, gives nothing.
func TestWebhookEmail(t *testing.T) {
	for _, name := range []string{"webhook-pledge-update.json", "webhook-pledge-delete.json"} {
		body, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if got := WebhookEmail(body); got != "patron@example.com" {
			t.Errorf("%s: email %q, want patron@example.com", name, got)
		}
	}
	for name, body := range map[string]string{
		"capitals and spaces": `{"data":{"attributes":{"email":"  Patron@Example.COM "}}}`,
	} {
		if got := WebhookEmail([]byte(body)); got != "patron@example.com" {
			t.Errorf("%s: email %q, want patron@example.com", name, got)
		}
	}
	for name, body := range map[string]string{
		"no email":              `{"data":{"attributes":{"patron_status":"active_patron"}}}`,
		"email elsewhere":       `{"included":[{"attributes":{"email":"patron@example.com"}}]}`,
		"email not a string":    `{"data":{"attributes":{"email":7}}}`,
		"not json":              `<html>`,
		"empty":                 ``,
		"blank email":           `{"data":{"attributes":{"email":"   "}}}`,
		"data not an object":    `{"data":[]}`,
		"attributes not object": `{"data":{"attributes":"x"}}`,
	} {
		if got := WebhookEmail([]byte(body)); got != "" {
			t.Errorf("%s: email %q, want none", name, got)
		}
	}
}
