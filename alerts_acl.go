package main

import (
	"net/url"

	"github.com/mtgban/mtgban-website/internal/access"
	"github.com/mtgban/mtgban-website/userstate"
)

// grantIndex maps hashed grant emails to grants, built once per use.
type grantIndex map[string]access.Grant

// indexGrants keys each grant by HashEmail of its own email.
// A duplicate email keeps the first grant, matching the old linear scan.
func indexGrants(grants []access.Grant) grantIndex {
	idx := make(grantIndex, len(grants))
	for _, grant := range grants {
		h := userstate.HashEmail(grant.Email)
		_, found := idx[h]
		if found {
			continue
		}
		idx[h] = grant
	}
	return idx
}

// find returns the grant for a user hash, if any.
func (g grantIndex) find(userHash string) (access.Grant, bool) {
	grant, ok := g[userHash]
	return grant, ok
}

// aclValuesIn is a tier's ACL values against table, with overrides on top.
func aclValuesIn(table access.Table, tier string, overrides map[string]map[string]string) url.Values {
	v := valuesForTierIn(table, tier)
	applyACL(v, overrides)
	return v
}
