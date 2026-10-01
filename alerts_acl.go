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

// aclValuesWith picks a user's grant from idx, then builds its ACL values.
// A grant's own tier wins over the stored one, same as Auth.
func aclValuesWith(table access.Table, idx grantIndex, userHash, tier string) url.Values {
	grant, found := idx.find(userHash)
	if !found {
		return aclValuesIn(table, tier, nil)
	}
	base := tier
	if grant.Tier != "" {
		base = grant.Tier
	}
	return aclValuesIn(table, base, grant.Overrides)
}

// alertContactAllowedIn is alertContactAllowed's testable core.
func alertContactAllowedIn(table access.Table, tier string, overrides map[string]map[string]string) bool {
	return allowanceFromValues(aclValuesIn(table, tier, overrides)) > 0
}

// alertContactAllowed says whether tier, with a grant's own overrides on
// top, grants alerts at all.
func alertContactAllowed(tier string, overrides map[string]map[string]string) bool {
	return alertContactAllowedIn(ACL(), tier, overrides)
}
