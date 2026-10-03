package alerts

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"
)

// TokenKind is the kind of link a signed token authorizes.
type TokenKind string

// TokenConfirm and TokenUnsubscribe are the token kinds minted for mail links.
const (
	TokenConfirm     TokenKind = "confirm"
	TokenUnsubscribe TokenKind = "unsubscribe"
)

// Token is the payload signed into a confirm or unsubscribe link.
type Token struct {
	Kind     TokenKind
	UserHash string
	Address  string
	Expires  time.Time
}

// ErrBadToken and ErrTokenExpired are VerifyToken's failures.
var (
	ErrBadToken     = errors.New("alerts: bad token")
	ErrTokenExpired = errors.New("alerts: token expired")
)

func tokenPayload(t Token) string {
	exp := int64(0)
	if !t.Expires.IsZero() {
		exp = t.Expires.Unix()
	}
	return strings.Join([]string{string(t.Kind), t.UserHash, strings.ToLower(t.Address), strconv.FormatInt(exp, 10)}, "|")
}

// MintToken signs a confirm or unsubscribe link with BAN_SECRET's HMAC.
func MintToken(secret []byte, t Token) string {
	payload := tokenPayload(t)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// VerifyToken checks signature, shape, kind, then expiry.
func VerifyToken(secret []byte, s string, now time.Time) (Token, error) {
	body, sig, ok := strings.Cut(s, ".")
	if !ok {
		return Token{}, ErrBadToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return Token{}, ErrBadToken
	}
	want, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return Token{}, ErrBadToken
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(raw)
	if !hmac.Equal(mac.Sum(nil), want) {
		return Token{}, ErrBadToken
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 4 {
		return Token{}, ErrBadToken
	}
	if TokenKind(parts[0]) != TokenConfirm && TokenKind(parts[0]) != TokenUnsubscribe {
		return Token{}, ErrBadToken
	}
	exp, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return Token{}, ErrBadToken
	}
	t := Token{Kind: TokenKind(parts[0]), UserHash: parts[1], Address: parts[2]}
	if exp != 0 {
		t.Expires = time.Unix(exp, 0).UTC()
		if now.After(t.Expires) {
			return Token{}, ErrTokenExpired
		}
	}
	return t, nil
}
