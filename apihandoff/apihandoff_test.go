package apihandoff

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var (
	goldenSecret = []byte("handoff-test-secret")
	goldenClaims = Claims{Email: "ann@example.com", Name: "Ann Example", Purpose: PurposeTrial, Game: "magic", Nonce: "golden-nonce", Expires: time.Unix(1789000000, 0).UTC()}
	// Recorded once; the gateway verifies tokens this package minted, so the bytes are frozen.
	goldenToken = "ZW1haWw9YW5uJTQwZXhhbXBsZS5jb20mZXhwPTE3ODkwMDAwMDAmZ2FtZT1tYWdpYyZuYW1lPUFubitFeGFtcGxlJm5vbmNlPWdvbGRlbi1ub25jZSZwdXJwb3NlPXRyaWFs.0sTFy_pUeWndT-5Ooi-kF7330LxrqOwnjyFvyl6ma-U"
	before      = time.Unix(1788999999, 0)
)

func TestGolden(t *testing.T) {
	if got := Mint(goldenSecret, goldenClaims); got != goldenToken {
		t.Fatalf("mint changed the token format:\n got %s\nwant %s", got, goldenToken)
	}
	got, err := Verify(goldenSecret, goldenToken, before)
	if err != nil {
		t.Fatal(err)
	}
	if got != goldenClaims {
		t.Errorf("got %+v want %+v", got, goldenClaims)
	}
}

func TestVerifyRejects(t *testing.T) {
	tampered := goldenToken[:len(goldenToken)-1] + "A"
	if tampered == goldenToken {
		tampered = goldenToken[:len(goldenToken)-1] + "B"
	}
	cases := map[string]struct {
		secret []byte
		token  string
		now    time.Time
	}{
		"wrong secret": {[]byte("other"), goldenToken, before},
		"tampered":     {goldenSecret, tampered, before},
		"expired":      {goldenSecret, goldenToken, goldenClaims.Expires},
		"no dot":       {goldenSecret, strings.ReplaceAll(goldenToken, ".", ""), before},
		"empty":        {goldenSecret, "", before},
		"bad purpose":  {goldenSecret, Mint(goldenSecret, Claims{Email: "a@b.c", Game: "pokemon", Purpose: "admin", Nonce: "n", Expires: goldenClaims.Expires}), before},
		"no email":     {goldenSecret, Mint(goldenSecret, Claims{Game: "pokemon", Purpose: PurposeLogin, Nonce: "n", Expires: goldenClaims.Expires}), before},
		"no nonce":     {goldenSecret, Mint(goldenSecret, Claims{Email: "a@b.c", Game: "pokemon", Purpose: PurposeLogin, Nonce: "", Expires: goldenClaims.Expires}), before},
	}
	for name, tc := range cases {
		if _, err := Verify(tc.secret, tc.token, tc.now); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

func TestRoundTripLogin(t *testing.T) {
	now := time.Now()
	c := Claims{Email: "Bob@Example.com", Name: "Bob", Game: "pokemon", Purpose: PurposeLogin, Nonce: "round-trip-nonce", Expires: now.Add(TTL).Truncate(time.Second).UTC()}
	got, err := Verify([]byte("s"), Mint([]byte("s"), c), now)
	if err != nil || got != c {
		t.Fatalf("got %+v, %v; want %+v", got, err, c)
	}
}

func TestGameReadsTheClaimWithoutVerifying(t *testing.T) {
	if got := Game(goldenToken); got != "magic" {
		t.Errorf("game %q", got)
	}
	if got := Game("not-a-token"); got != "" {
		t.Errorf("garbage yields %q", got)
	}
	noGame := Mint(goldenSecret, Claims{Email: "a@b.c", Purpose: PurposeLogin, Nonce: "n", Expires: time.Unix(1789000000, 0)})
	if _, err := Verify(goldenSecret, noGame, time.Unix(1788999999, 0)); err == nil {
		t.Error("a token naming no game verified")
	}
}
