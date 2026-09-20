// Package apihandoff is the signed token a game site hands to the API
// gateway when a Patreon user starts a trial or signs in. The website mints
// it, the gateway imports this package to verify it, and TestGolden freezes
// the bytes so neither side can drift.
package apihandoff

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Purposes a token can carry.
const (
	PurposeTrial = "trial"
	PurposeLogin = "login"
)

// TTL is how long a minted token stays valid.
const TTL = 5 * time.Minute

// ErrInvalid covers a malformed, forged, expired, or unknown-purpose token alike.
var ErrInvalid = errors.New("apihandoff: invalid or expired token")

// Claims is what the token says about the Patreon user.
type Claims struct {
	Email   string
	Name    string
	Purpose string
	Expires time.Time
}

// Mint signs c with secret. Expires is kept to the second.
func Mint(secret []byte, c Claims) string {
	v := url.Values{}
	v.Set("email", c.Email)
	v.Set("name", c.Name)
	v.Set("purpose", c.Purpose)
	v.Set("exp", strconv.FormatInt(c.Expires.Unix(), 10))
	body := base64.RawURLEncoding.EncodeToString([]byte(v.Encode()))
	return body + "." + sign(secret, body)
}

// Verify checks the signature and expiry and returns the claims.
func Verify(secret []byte, token string, now time.Time) (Claims, error) {
	body, sig, ok := strings.Cut(token, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(sign(secret, body))) {
		return Claims{}, ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return Claims{}, ErrInvalid
	}
	v, err := url.ParseQuery(string(raw))
	if err != nil {
		return Claims{}, ErrInvalid
	}
	exp, err := strconv.ParseInt(v.Get("exp"), 10, 64)
	if err != nil || !now.Before(time.Unix(exp, 0)) {
		return Claims{}, ErrInvalid
	}
	c := Claims{Email: v.Get("email"), Name: v.Get("name"), Purpose: v.Get("purpose"), Expires: time.Unix(exp, 0).UTC()}
	if c.Email == "" || (c.Purpose != PurposeTrial && c.Purpose != PurposeLogin) {
		return Claims{}, ErrInvalid
	}
	return c, nil
}

func sign(secret []byte, body string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
