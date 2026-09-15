// Package apisig implements the signed query blob the BAN price API accepts
// as ?sig=. The website mints and verifies it; the API gateway mints it.
package apisig

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"net/url"
	"strconv"
)

// DefaultLink is the constant host baked into every production payload.
const DefaultLink = "http://www.mtgban.com"

// Claims are the values packed into a signature.
type Claims struct {
	// API is the store scope: a preset such as ALL_ACCESS or a store list.
	API string
	// Fields holds the optional signed fields present, e.g. APImode, UserEmail.
	Fields url.Values
	// Expires is a unix timestamp in seconds; zero means the blob never expires.
	Expires int64
}

// Sign returns the base64 HMAC-SHA1 of data under secret.
func Sign(secret, data []byte) string {
	h := hmac.New(sha1.New, secret)
	h.Write(data)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// values returns the query values that are signed: API, every non-empty
// field, and Expires when set. Encode sorts keys, which fixes the order.
func (c Claims) values() url.Values {
	v := url.Values{}
	v.Set("API", c.API)
	for key, vals := range c.Fields {
		if len(vals) > 0 && vals[0] != "" {
			v.Set(key, vals[0])
		}
	}
	if c.Expires != 0 {
		v.Set("Expires", strconv.FormatInt(c.Expires, 10))
	}
	return v
}

// expiresString is the Expires field as the payload spells it: empty when unset.
func (c Claims) expiresString() string {
	if c.Expires == 0 {
		return ""
	}
	return strconv.FormatInt(c.Expires, 10)
}

// Payload is the exact byte string that gets signed.
func Payload(method, link string, c Claims) string {
	return method + c.expiresString() + link + c.values().Encode()
}
