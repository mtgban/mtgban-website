package main

import "testing"

// Golden vectors for the API signature format. The gateway repo mints
// signatures the game backends verify, so these bytes must never change.
const (
	goldenSecret = "golden-secret"

	// GET + Expires + DefaultServerURL + url.Values.Encode() of
	// API, APImode, Expires, UserEmail (sorted by key by Encode).
	goldenDataWithExpiry = "GET1800000000http://www.mtgban.comAPI=BASE_ACCESS&APImode=retail%2Cbuylist&Expires=1800000000&UserEmail=golden%40example.com"
	goldenSigWithExpiry  = "u/Ep9NoOIBriYtarJXp5WYSlkQM="

	goldenDataNoExpiry = "GEThttp://www.mtgban.comAPI=ALL_ACCESS&APImode=all&UserEmail=golden%40example.com"
	goldenSigNoExpiry  = "MmcFVf0N2PrK3o8zk9O5YdDqz4g="
)

func TestAPISignatureGolden(t *testing.T) {
	cases := []struct {
		name, data, want string
	}{
		{"with expiry", goldenDataWithExpiry, goldenSigWithExpiry},
		{"no expiry", goldenDataNoExpiry, goldenSigNoExpiry},
	}
	for _, c := range cases {
		got := signHMACSHA1Base64([]byte(goldenSecret), []byte(c.data))
		if got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}
