package imgmirror

import (
	"net/url"
	"sort"
)

// Card is what the crawler needs to know about one printing.
type Card struct {
	URL     string
	SetCode string
	Sealed  bool
}

// NeedFetch returns the uuids missing from the state or whose source URL
// changed, sorted for deterministic runs.
func NeedFetch(state State, want map[string]Card) []string {
	var out []string
	for uuid, card := range want {
		prev, found := state[uuid]
		if !found || prev.Source != card.URL {
			out = append(out, uuid)
		}
	}
	sort.Strings(out)
	return out
}

// SetDigests groups the already fetched wanted uuids by set code.
func SetDigests(state State, want map[string]Card) map[string]map[string]string {
	out := map[string]map[string]string{}
	for uuid, card := range want {
		entry, found := state[uuid]
		if !found {
			continue
		}
		m := out[card.SetCode]
		if m == nil {
			m = map[string]string{}
			out[card.SetCode] = m
		}
		m[uuid] = entry.Digest
	}
	return out
}

// BundlesToRebuild returns the set codes whose membership or digests no
// longer match the manifest, sorted.
func BundlesToRebuild(m Manifest, setDigests map[string]map[string]string) []string {
	var out []string
	for code, digests := range setDigests {
		if m[code].Hash != BundleHash(digests) {
			out = append(out, code)
		}
	}
	sort.Strings(out)
	return out
}

// Domains counts the wanted image URLs per source host.
func Domains(want map[string]Card) map[string]int {
	out := map[string]int{}
	for _, card := range want {
		u, err := url.Parse(card.URL)
		if err != nil {
			continue
		}
		out[u.Host]++
	}
	return out
}
