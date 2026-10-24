package patreon

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// WebhookSignature is the hex HMAC-MD5 of a webhook delivery's body under the
// webhook's secret, what Patreon sends in X-Patreon-Signature. MD5 is what
// Patreon computes (SHA-1 and SHA-256 do not match what it sends), which is the
// only reason it is here and the one place the site uses it.
func WebhookSignature(secret string, body []byte) string {
	mac := hmac.New(md5.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// WebhookSigned says whether header is the signature of body under secret,
// comparing in constant time.
func WebhookSigned(secret string, body []byte, header string) bool {
	return hmac.Equal([]byte(WebhookSignature(secret, body)), []byte(strings.ToLower(header)))
}

// WebhookEmail is the member's email in a webhook delivery's body, lowercased
// and trimmed as a login's is, or empty when the body does not carry one. The
// body's own account of the pledge is not read: the renewal asks Patreon.
func WebhookEmail(body []byte) string {
	var delivery struct {
		Data struct {
			Attributes struct {
				Email string `json:"email"`
			} `json:"attributes"`
		} `json:"data"`
	}
	err := json.Unmarshal(body, &delivery)
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(delivery.Data.Attributes.Email))
}
