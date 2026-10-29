package main

import (
	"maps"
	"slices"
	"strings"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// rekeyFilters reads a filter whose key does not take its value under the
// key that does: "is:plst" names no tag, "s:plst" names The List. A filter
// is rekeyed when it keeps none of the cards the rest of the query finds,
// or answers them as it does a value naming nothing. Every other key the
// parser takes with the same operation is tried, shorter keys first and
// reverse alphabetically at one length, so that s: wins over its alias e:.
// A key stands in only where it parses into a card filter and reads each
// comma-separated value whole, as one value that keeps cards and answers
// differently than a value naming nothing: ci:modern reads six colour
// letters and never stands in. name is what the query searches by name and
// pinned the scope bar's filters; the cards are looked up once for every
// key.
//
// The page is public, so the work is bounded: a query with more than
// maxRekeyFilters filters is not rekeyed, nor a filter of more than
// maxRekeyValues values, and the cards walked come to one card pool at
// most.
func rekeyFilters(ds *datastore, name, filters []string, pinned []FilterElem, sealed bool) ([]string, bool) {
	if len(filters) > maxRekeyFilters {
		return filters, false
	}
	budget := len(ds.backend.UUIDs)

	keys := slices.Collect(maps.Keys(FilterOperations))
	slices.SortFunc(keys, func(a, b string) int {
		if len(a) != len(b) {
			return len(a) - len(b)
		}
		return strings.Compare(b, a)
	})

	out := slices.Clone(filters)
	var rekeyed bool
	for i, filter := range filters {
		index := strings.IndexAny(filter, ":<>")
		if index == -1 {
			continue
		}
		key, op, value := strings.ToLower(filter[:index]), filter[index:index+1], filter[index+1:]
		negate := strings.HasPrefix(key, "-")
		key = strings.TrimPrefix(key, "-")
		if FilterOperations[key] == nil || strings.Count(value, ",") >= maxRekeyValues {
			continue
		}

		others := append(slices.Clone(name), slices.Delete(slices.Clone(filters), i, i+1)...)
		config := parseSearchPage(ds, strings.Join(others, " "), sealed, nil, nil, nil)
		applySearchScope(&config, pinned)
		if sealed {
			config.SearchMode = "sealed"
		}
		rest, err := searchAndFilter(ds, config)
		if err != nil || len(rest) == 0 {
			continue
		}
		if len(rest) > budget {
			break
		}
		budget -= len(rest)

		// not: is a negated is:, so the sign is read off what the
		// filter parses into rather than off its spelling.
		var tried []FilterElem
		var typed *rekeyPart
		elem, ok := cardFilterOf(ds, filter, sealed)
		if ok {
			tried = append(tried, elem)
			negate = elem.Negate
			typed = newRekeyPart(ds, elem, filter[:index+1], sealed)
		}
		prefix := ""
		if negate {
			prefix = "-"
		}
		var candidates []rekeyCandidate
		for _, key := range keys {
			if !slices.Contains(FilterOperations[key], op) {
				continue
			}
			token := prefix + key + op + value
			elem, ok := cardFilterOf(ds, token, sealed)
			if !ok || elem.Negate != negate || slices.ContainsFunc(tried, elem.sameAs) {
				continue
			}
			tried = append(tried, elem)
			candidate, ok := newRekeyCandidate(ds, prefix+key+op, value, sealed)
			if ok {
				candidate.token = token
				candidates = append(candidates, candidate)
			}
		}

		for _, cardID := range rest {
			co, err := ds.backend.GetUUID(cardID)
			if err != nil {
				continue
			}
			if typed != nil {
				typed.try(ds.backend, co)
				if !typed.failed() {
					break
				}
			}
			for j := range candidates {
				for k := range candidates[j].parts {
					candidates[j].parts[k].try(ds.backend, co)
				}
			}
		}
		if typed != nil && !typed.failed() {
			continue
		}
		for _, c := range candidates {
			if !slices.ContainsFunc(c.parts, rekeyPart.failed) {
				out[i] = c.token
				rekeyed = true
				break
			}
		}
	}
	return out, rekeyed
}

// maxRekeyFilters is how many filters a query may carry, and
// maxRekeyValues how many comma-separated values a filter may, and still
// be rekeyed.
const (
	maxRekeyFilters = 3
	maxRekeyValues  = 3
)

// rekeyCandidate is one key a filter's value is tried under, one part per
// comma-separated value.
type rekeyCandidate struct {
	token string
	parts []rekeyPart
}

// newRekeyCandidate parses each value under key, which carries its sign
// and operation, and fails where one does not parse into a card filter of
// one value.
func newRekeyCandidate(ds *datastore, key, value string, sealed bool) (rekeyCandidate, bool) {
	var c rekeyCandidate
	for _, part := range strings.Split(value, ",") {
		elem, ok := cardFilterOf(ds, key+part, sealed)
		if !ok || len(elem.Values) != 1 {
			return c, false
		}
		c.parts = append(c.parts, *newRekeyPart(ds, elem, key, sealed))
	}
	return c, true
}

// newRekeyPart pairs the filter a value parsed into with the one
// nonsenseValue parses into under the same key. A key that takes no
// nonsense, as s: drops a set that is not one, reads its value.
func newRekeyPart(ds *datastore, elem FilterElem, key string, sealed bool) *rekeyPart {
	p := &rekeyPart{filter: []FilterElem{elem}}
	nonsense, ok := cardFilterOf(ds, key+nonsenseValue, sealed)
	if ok {
		p.nonsense = []FilterElem{nonsense}
	} else {
		p.readsValue = true
	}
	return p
}

// rekeyPart is one value a key is tried with, and what it did to the
// cards the rest of the query finds: whether it kept one, and whether it
// answered one differently than nonsenseValue does.
type rekeyPart struct {
	filter   []FilterElem
	nonsense []FilterElem

	keeps, readsValue bool
}

func (p *rekeyPart) try(b *mtgmatcher.Backend, co *mtgmatcher.CardObject) {
	if !p.failed() {
		return
	}
	skip := shouldSkipCard(b, co, p.filter)
	p.keeps = p.keeps || !skip
	if !p.readsValue && skip != shouldSkipCard(b, co, p.nonsense) {
		p.readsValue = true
	}
}

func (p rekeyPart) failed() bool {
	return !p.keeps || !p.readsValue
}

// nonsenseValue is a filter value that names nothing, to tell a key that
// reads its value from one that answers the same whatever it is given.
const nonsenseValue = "zzqxzzqx"

// cardFilterOf is the one card filter a filter token parses into, if that
// is all it parses into.
func cardFilterOf(ds *datastore, token string, sealed bool) (FilterElem, bool) {
	config := parseSearchPage(ds, token, sealed, nil, nil, nil)
	plain := parseSearchPage(ds, "", sealed, nil, nil, nil)
	if len(config.CardFilters) != 1 || config.CleanQuery != "" || config.SearchMode != plain.SearchMode {
		return FilterElem{}, false
	}
	return config.CardFilters[0], true
}

// sameAs reports whether two filters ask the same of a card.
func (f FilterElem) sameAs(other FilterElem) bool {
	return f.Name == other.Name && f.Negate == other.Negate && slices.Equal(f.Values, other.Values)
}
