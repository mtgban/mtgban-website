package main

import (
	"maps"
	"slices"
	"strings"

	"github.com/mtgban/go-mtgban/matcher"
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
// letters and never stands in, nor does a key matching by pattern, which
// a short value matches by chance. A filter whose own key reads its value
// somewhere is left as typed: c:r keeps no Counterspell, but it is no typo.
// Neither is a comparison, nor a filter that parses into no card filter,
// region:jp or sort:chrono, unless it is a store filter naming no store.
// name is what the query searches by name and pinned the scope bar's
// filters; the cards are looked up once for every key.
//
// The page is public, so the work is bounded: a query with more than
// maxRekeyFilters filters is not rekeyed, nor a filter of more than
// maxRekeyValues values. The query is searched once, without the filters
// tried, and the cards it finds are walked once: what the rest of the
// query finds for a filter is the cards every other filter tried keeps.
// A walk of the datastore follows for each filter a key stands in for.
func rekeyFilters(ds *datastore, name, filters []string, pinned []FilterElem, sealed bool) ([]string, bool) {
	if len(filters) > maxRekeyFilters {
		return filters, false
	}

	keys := slices.Collect(maps.Keys(FilterOperations))
	slices.SortFunc(keys, func(a, b string) int {
		if len(a) != len(b) {
			return len(a) - len(b)
		}
		return strings.Compare(b, a)
	})

	others := slices.Clone(name)
	var tries []rekeyTry
	for i, filter := range filters {
		index := strings.IndexAny(filter, ":<>")
		if index == -1 {
			others = append(others, filter)
			continue
		}
		key, op, value := strings.ToLower(filter[:index]), filter[index:index+1], filter[index+1:]
		negate := strings.HasPrefix(key, "-")
		key = strings.TrimPrefix(key, "-")
		if FilterOperations[key] == nil || op != ":" || strings.Count(value, ",") >= maxRekeyValues {
			others = append(others, filter)
			continue
		}
		// A filter that is no card filter reads its value its own way,
		// region:jp or sort:chrono, and stays as typed; a store filter
		// naming no store is the one read under another key.
		elem, ok := cardFilterOf(ds, filter, sealed)
		store := key == "store" || key == "seller" || key == "vendor"
		if !ok && (!store || namesStores(value)) {
			others = append(others, filter)
			continue
		}

		// not: is a negated is:, so the sign is read off what the
		// filter parses into rather than off its spelling.
		t := rekeyTry{index: i, key: filter[:index+1]}
		var tried []FilterElem
		if ok {
			tried = append(tried, elem)
			negate = elem.Negate
			t.typed = newRekeyPart(ds, elem, t.key, sealed)
		}
		prefix := ""
		if negate {
			prefix = "-"
		}
		for _, key := range keys {
			if !slices.Contains(FilterOperations[key], op) {
				continue
			}
			token := prefix + key + op + value
			elem, ok := cardFilterOf(ds, token, sealed)
			if !ok || elem.Regexp != nil || elem.Negate != negate || slices.ContainsFunc(tried, elem.sameAs) {
				continue
			}
			tried = append(tried, elem)
			candidate, ok := newRekeyCandidate(ds, prefix+key+op, value, sealed)
			if ok {
				candidate.token = token
				t.candidates = append(t.candidates, candidate)
			}
		}
		tries = append(tries, t)
	}
	if len(tries) == 0 {
		return filters, false
	}

	config := parseSearchPage(ds, strings.Join(others, " "), sealed, nil, nil, nil)
	applySearchScope(&config, pinned)
	if sealed {
		config.SearchMode = "sealed"
	}
	found, err := searchAndFilter(ds, config)
	if err != nil {
		return filters, false
	}
	for _, cardID := range found {
		co, err := ds.backend.GetUUID(cardID)
		if err != nil {
			continue
		}
		// A card is in a filter's rest when no other filter tried drops
		// it; a store filter drops no card.
		dropped, by := 0, 0
		for j, t := range tries {
			if t.typed != nil && shouldSkipCard(ds.backend, co, t.typed.filter) {
				dropped, by = dropped+1, j
			}
		}
		for j := range tries {
			if dropped == 0 || (dropped == 1 && by == j) {
				tries[j].try(ds.backend, co)
			}
		}
	}

	out := slices.Clone(filters)
	var rekeyed bool
	for _, t := range tries {
		if t.typed != nil && !t.typed.failed() {
			continue
		}
		for _, c := range t.candidates {
			if slices.ContainsFunc(c.parts, rekeyPart.failed) {
				continue
			}
			// Asked only of a filter some key would stand in for: the
			// walk covers the whole datastore when the value names nothing.
			if t.typed == nil || !readsAnywhere(ds, t.typed.filter[0], t.key, sealed) {
				out[t.index] = c.token
				rekeyed = true
			}
			break
		}
	}
	return out, rekeyed
}

// rekeyTry is one filter rekeyFilters reads anew: where it sits in the
// query, its key as typed, what it parses into if it is a card filter,
// and the keys its value is tried under.
type rekeyTry struct {
	index      int
	key        string
	typed      *rekeyPart
	candidates []rekeyCandidate
}

// try reads a card the rest of the query finds, past the filter as typed
// once that reads its value.
func (t *rekeyTry) try(b *matcher.Backend, co *matcher.CardObject) {
	if t.typed != nil {
		t.typed.try(b, co)
		if !t.typed.failed() {
			return
		}
	}
	for j := range t.candidates {
		for k := range t.candidates[j].parts {
			t.candidates[j].parts[k].try(b, co)
		}
	}
}

// readsAnywhere reports whether a filter keeps a card somewhere in the
// datastore and reads its value there, as a filter naming nothing does not.
func readsAnywhere(ds *datastore, elem FilterElem, key string, sealed bool) bool {
	p := newRekeyPart(ds, elem, key, sealed)
	for _, co := range ds.backend.UUIDs {
		p.try(ds.backend, co)
		if !p.failed() {
			return true
		}
	}
	return false
}

// namesStores reports whether every comma-separated value names a loaded
// store, by shorthand or by name, read past an option the way the parser
// reads store:empty:ck.
func namesStores(value string) bool {
	subCodes := strings.Split(value, ":")
	if len(subCodes) > 1 {
		value = subCodes[1]
	}
	idx := currentStoreIndex()
	for _, store := range fixupStoreCodeNG(value) {
		_, seller := idx.sellerFold[store]
		_, vendor := idx.vendorFold[store]
		if !seller && !vendor {
			return false
		}
	}
	return true
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

func (p *rekeyPart) try(b *matcher.Backend, co *matcher.CardObject) {
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
