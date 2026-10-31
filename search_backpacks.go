package main

import (
	"context"
	"log"
	"maps"
	"strings"

	"github.com/mtgban/go-mtgban/matcher"

	"github.com/mtgban/mtgban-website/userstate"
)

// backpackNameKey is how an on: value names a backpack: its name lowered,
// without the quotes and commas a filter value cannot carry.
func backpackNameKey(name string) string {
	return strings.TrimSpace(strings.ToLower(backpackNameMarks.Replace(name)))
}

var backpackNameMarks = strings.NewReplacer(`"`, "", ",", "")

// backpackMembers maps each on: value naming one of packs to the cards it
// holds: a backpack's name, and "backpack" for all of them unless a
// backpack is called that.
func backpackMembers(packs []userstate.Backpack) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	all := map[string]bool{}
	for _, pack := range packs {
		key := backpackNameKey(pack.Name)
		if out[key] == nil {
			out[key] = map[string]bool{}
		}
		for _, id := range pack.Cards {
			out[key][id] = true
			all[id] = true
		}
	}
	if out["backpack"] == nil {
		out["backpack"] = all
	}
	return out
}

// resolveBackpacks fills the config's on: filters naming the reader's
// backpacks with the cards in them, as last synced. A backpack's name wins
// over a list of the site's own. A filter naming backpacks alone becomes a
// pool, which seeds the search and answers no cards when the backpacks are
// empty. The sealed tab never answers with a single. An in: sub-search
// resolves the same way. It returns the backpacks it read, by on: value.
func resolveBackpacks(ctx context.Context, sig string, b *matcher.Backend, config *SearchConfig) map[string]map[string]bool {
	if UserStateDB == nil || !namesAList(config.CardFilters) {
		return nil
	}
	email := GetParamFromSig(sig, "UserEmail")
	if email == "" {
		return nil
	}
	backpacks, err := UserStateDB.GetBackpacks(ctx, userstate.HashEmail(userStateIdentity(email)))
	if err != nil {
		log.Printf("search: reading the backpacks failed: %v", err)
		return nil
	}
	packs := backpackMembers(backpacks)
	applyBackpacks(b, config, packs)
	return packs
}

// applyBackpacks is resolveBackpacks with the reader's backpacks read.
func applyBackpacks(b *matcher.Backend, config *SearchConfig, packs map[string]map[string]bool) {
	filters := config.CardFilters
	for i := range filters {
		if filters[i].Pool != nil {
			applyBackpacks(b, filters[i].Pool, packs)
		}
		if filters[i].Name != "on" {
			continue
		}
		var rest []string
		var members map[string]bool
		for _, value := range filters[i].Values {
			cards, found := packs[value]
			if !found {
				rest = append(rest, value)
				continue
			}
			if members == nil {
				members = map[string]bool{}
			}
			maps.Copy(members, cards)
		}
		if members == nil {
			continue
		}
		if config.SearchMode == "sealed" {
			maps.DeleteFunc(members, func(uuid string, _ bool) bool {
				co, err := b.GetUUID(uuid)
				return err != nil || !co.Sealed
			})
		}
		filters[i].Values = rest
		filters[i].Members = members
		if len(rest) == 0 {
			filters[i].Name = "pool"
		}
	}
}

// namesAList says filters hold an on: filter, in an in: sub-search too.
func namesAList(filters []FilterElem) bool {
	for i := range filters {
		if filters[i].Name == "on" || (filters[i].Pool != nil && namesAList(filters[i].Pool.CardFilters)) {
			return true
		}
	}
	return false
}
