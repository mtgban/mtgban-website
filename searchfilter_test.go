package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

func TestFormatFilter(t *testing.T) {
	skip := FilterCardFuncs["format"]
	if skip == nil {
		t.Fatal("format filter is not registered")
	}

	co := &mtgmatcher.CardObject{}
	co.Legalities = map[string]string{
		"standard": "Legal",
		"vintage":  "Restricted",
		"modern":   "Banned",
	}

	tests := []struct {
		name     string
		formats  []string
		wantSkip bool
	}{
		{"legal is kept", []string{"standard"}, false},
		{"restricted is kept", []string{"vintage"}, false},
		{"banned is skipped", []string{"modern"}, true},
		{"absent format is skipped", []string{"legacy"}, true},
		{"any legal format keeps the card", []string{"modern", "standard"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := skip(tt.formats, co); got != tt.wantSkip {
				t.Errorf("skip = %v, want %v", got, tt.wantSkip)
			}
		})
	}
}

func TestFixupFormatNG(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"Standard", []string{"standard"}},
		{"edh", []string{"commander"}},
		{"pdh", []string{"paupercommander"}},
		{"modern, legacy", []string{"modern", "legacy"}},
		{"", nil},
	}
	for _, tt := range tests {
		got := fixupFormatNG(tt.in)
		if len(got) != len(tt.want) {
			t.Errorf("fixupFormatNG(%q) = %v, want %v", tt.in, got, tt.want)
			continue
		}
		for i := range tt.want {
			if got[i] != tt.want[i] {
				t.Errorf("fixupFormatNG(%q)[%d] = %q, want %q", tt.in, i, got[i], tt.want[i])
			}
		}
	}
}
