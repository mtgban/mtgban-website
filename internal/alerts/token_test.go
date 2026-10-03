package alerts

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func TestTokenRoundTripAndTamper(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	tok := Token{Kind: TokenConfirm, UserHash: "u1", Address: "ann@example.com", Expires: now.Add(24 * time.Hour)}
	s := MintToken(secret, tok)
	got, err := VerifyToken(secret, s, now)
	if err != nil || got != tok {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := VerifyToken(secret, s, now.Add(25*time.Hour)); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expiry: %v", err)
	}
	if _, err := VerifyToken([]byte("other-secret-other-secret-other!"), s, now); !errors.Is(err, ErrBadToken) {
		t.Errorf("wrong secret: %v", err)
	}
	flipped := s[:len(s)-2] + "AA"
	if _, err := VerifyToken(secret, flipped, now); !errors.Is(err, ErrBadToken) {
		t.Errorf("tamper: %v", err)
	}
	u := MintToken(secret, Token{Kind: TokenUnsubscribe, UserHash: "u1"})
	if got, err := VerifyToken(secret, u, now.Add(1000*24*time.Hour)); err != nil || got.Kind != TokenUnsubscribe || !got.Expires.IsZero() {
		t.Errorf("unsubscribe never expires: %+v %v", got, err)
	}
	if _, err := VerifyToken(secret, "", now); !errors.Is(err, ErrBadToken) {
		t.Error("empty token accepted")
	}
	badKind := Token{Kind: TokenKind("other"), UserHash: "u1", Expires: now.Add(-1 * time.Hour)}
	badKindToken := MintToken(secret, badKind)
	if _, err := VerifyToken(secret, badKindToken, now); !errors.Is(err, ErrBadToken) {
		t.Errorf("unknown kind with past expiry: %v", err)
	}
	extraPayload := "confirm|u1|ann@example.com|0|extra"
	extraMac := hmac.New(sha256.New, secret)
	extraMac.Write([]byte(extraPayload))
	extraToken := base64.RawURLEncoding.EncodeToString([]byte(extraPayload)) + "." + base64.RawURLEncoding.EncodeToString(extraMac.Sum(nil))
	if _, err := VerifyToken(secret, extraToken, now); !errors.Is(err, ErrBadToken) {
		t.Errorf("extra field: %v", err)
	}
}

// No secret mints no token, as the verify side accepts none without one.
func TestMintTokenRefusesAnEmptySecret(t *testing.T) {
	if got := MintToken(nil, Token{Kind: TokenUnsubscribe, UserHash: "u1"}); got != "" {
		t.Fatalf("minted %q without a secret", got)
	}
}
