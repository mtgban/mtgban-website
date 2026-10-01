package main

import (
	"testing"

	"github.com/mtgban/mtgban-website/internal/access"
	"github.com/mtgban/mtgban-website/userstate"
)

func TestIndexGrantsFirstDuplicateWins(t *testing.T) {
	grants := []access.Grant{{Email: "dup@example.com", Tier: "First"}, {Email: "dup@example.com", Tier: "Second"}}
	grant, found := indexGrants(grants).find(userstate.HashEmail("dup@example.com"))
	if !found || grant.Tier != "First" {
		t.Fatalf("grant = %+v found=%v, want Tier=First", grant, found)
	}
}
