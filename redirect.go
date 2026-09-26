package main

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

func Redirect(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/go/")
	fields := strings.Split(path, "/")

	if len(fields) == 2 || len(fields) == 3 {
		kind := fields[0]
		store := fields[len(fields)-2]
		hash := fields[len(fields)-1]

		// Default to retail in short mode
		if kind == store {
			kind = "r"
		}

		// Look up the hash: mtgjson, scryfall, and tcgproductid in order
		co, err := backend().GetUUID(hash)
		if err != nil {
			co, err = backend().GetUUID(externalUUID(backend(), hash))
			if err != nil {
				http.NotFound(w, r)
				return
			}
		}

		if kind == "r" || kind == "i" {
			inv, err := findSellerInventory(store)
			if err != nil {
				inv, err = findSellerInventoryByName(store, co.Sealed)
				if err != nil {
					http.NotFound(w, r)
					return
				}
			}

			entries := inv[co.UUID]
			for _, entry := range entries {
				http.Redirect(w, r, entry.URL, http.StatusFound)
				return
			}
		} else if kind == "b" {
			bl, err := findVendorBuylist(store)
			if err != nil {
				bl, err = findVendorBuylistByName(store, co.Sealed)
				if err != nil {
					http.NotFound(w, r)
					return
				}
			}

			entries := bl[co.UUID]
			for _, entry := range entries {
				http.Redirect(w, r, entry.URL, http.StatusFound)
				return
			}
		}
	}

	http.NotFound(w, r)
}

// printingsAt returns the cards a set files under a number, as printed.
func printingsAt(b *mtgmatcher.Backend, set, number string) []mtgmatcher.Card {
	edition, err := b.GetSet(set)
	if err != nil {
		return nil
	}
	var cards []mtgmatcher.Card
	for _, card := range edition.Cards {
		if strings.EqualFold(card.Number, number) {
			cards = append(cards, card)
		}
	}
	return cards
}

// openingName returns the name a query for a number should open with, or ""
// where the number should stand alone.
//
// The name is a label for the reader, but the search reads it as a filter too,
// so it goes in only where the number already named one card. High Seas files
// both "Marlynn // Treasure Island" and "Marlynn // Arrows Back" under
// SEA083//SEA247, and either name in front drops the other. Magic files one
// name per number throughout; 1,337 numbers over six other games do not.
func openingName(cards []mtgmatcher.Card) string {
	if len(cards) == 0 {
		return ""
	}
	// Folded, the way printingsAt already reads the numbers: a set that
	// files one card under two spellings of its name - Yu-Gi-Oh has six,
	// Elemental HERO beside Elemental Hero - has still named one card, and
	// either spelling finds both rows.
	for _, card := range cards[1:] {
		if !strings.EqualFold(card.Name, cards[0].Name) {
			return ""
		}
	}
	return cards[0].Name
}

// namesFinish reports whether a word names a finish of one of the cards. It is
// how the third part of a card path is told from the card name scryfall puts
// in the same position, and it asks with the filter the query would run, over
// the printings the path already names - so a word this route accepts is a
// word the search answers. A name answers to nothing: spelled the way finishes
// are spelled, "another-round" is "anotherround", which no printing is sold
// as.
func namesFinish(b *mtgmatcher.Backend, cards []mtgmatcher.Card, word string) bool {
	values := fixupFinishNG(word)
	for _, card := range cards {
		// A set carries one card object per printing, in its plain finish;
		// f:foil is answered by a sibling of that one rather than by it.
		for _, id := range b.FinishSiblings(card.UUID) {
			co, err := b.GetUUID(id)
			if err != nil {
				continue
			}
			if !cardFilterFinish(values, co) {
				return true
			}
		}
	}

	return false
}

// CardRedirect maps scryfall's /card/<set>/<number>[/<finish>] URLs onto a
// search for the same printing. Path parts are optional from the right.
//
// Invariants the code alone does not show:
//   - the third segment is a finish only when namesFinish says so (so a card
//     literally named Foil still works via /card/uma/55/foil)
//   - hand off to search rather than resolve here, so missing finishes land
//     on the whole family and bad set/number spellings fail as a search
//   - match numbers with cns: (as-printed) so stars/daggers distinguish twins
func CardRedirect(w http.ResponseWriter, r *http.Request) {
	// Split the path as it was written rather than as it decodes, so a slash
	// inside a part stays inside it: Flesh and Blood numbers a double-faced
	// card WTR040//WTR039, which travels as %2F%2F and would otherwise arrive
	// as two parts and read as the first alone. nginx hands the request URI
	// over untouched where proxy_pass names an upstream and no path, which is
	// how this site is served.
	//
	// Only the trailing slashes go: a leading one is an empty set code, and
	// trimming it would promote the number into its place.
	path := strings.TrimRight(strings.TrimPrefix(r.URL.EscapedPath(), "/card/"), "/")
	fields := strings.Split(path, "/")
	for i := range fields {
		decoded, err := url.PathUnescape(fields[i])
		if err != nil {
			continue
		}
		fields[i] = decoded
	}

	// Each part narrows what the one before it asked for, and a path that
	// stops early stops narrowing: a set alone is that set, and nothing at all
	// is the search itself. None of the three is an error, so none of them is
	// a 404 - what is left of the address is still a question this site
	// answers.
	var query string
	set := fields[0]
	if set != "" {
		query = "s:" + set

		if len(fields) > 1 && fields[1] != "" {
			number := fields[1]
			query += " cns:" + number

			cards := printingsAt(backend(), set, number)
			name := openingName(cards)
			if name != "" {
				query = name + " " + query
			}
			if len(fields) > 2 && namesFinish(backend(), cards, fields[2]) {
				query += " f:" + fields[2]
			}
		}
	}

	v := r.URL.Query()
	if query != "" {
		v.Set("q", query)
	}
	r.URL.RawQuery = v.Encode()
	r.URL.Path = "/search"

	http.Redirect(w, r, r.URL.String(), http.StatusFound)
}

// sealedSlugSeparators is every run of characters a slug does not keep.
var sealedSlugSeparators = regexp.MustCompile(`[^a-z0-9]+`)

// sealedSlug spells a product's name the way a path can carry it: lowercase,
// letters and digits only, one hyphen between words. Lossy on purpose - the
// name is recovered by slugging every product in the set the same way and
// matching, not by reversing this. No two products in a set slug alike
// (4,185 products across 342 sets, none), which is what lets the slug stand
// in for the name at all.
func sealedSlug(name string) string {
	return strings.Trim(sealedSlugSeparators.ReplaceAllString(strings.ToLower(name), "-"), "-")
}

// sealedProductBySlug finds the product in a set that a slug names, or nil.
func sealedProductBySlug(b *mtgmatcher.Backend, setCode, slug string) *mtgmatcher.SealedProduct {
	set, err := b.GetSet(strings.ToUpper(setCode))
	if err != nil || slug == "" {
		return nil
	}
	for i := range set.SealedProduct {
		if sealedSlug(set.SealedProduct[i].Name) == slug {
			return &set.SealedProduct[i]
		}
	}
	return nil
}

// SealedRedirect answers /sealed/<set>/<slug> for a product, the way
// CardRedirect answers /card/<set>/<number> for a printing: a link short
// enough to paste, resolved into the search the sealed tab already runs.
//
// Every part is optional from the right, and each part narrows the one before
// it: /sealed/<set> is that set's products, and /sealed is the tab itself. A
// slug that names no product in the set is searched for as the words it is
// made of, so it fails as a search that says so rather than as a dead link.
func SealedRedirect(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimRight(strings.TrimPrefix(r.URL.Path, "/sealed/"), "/")
	fields := strings.Split(path, "/")

	var query string
	set := fields[0]
	if set != "" {
		query = "s:" + set

		if len(fields) > 1 && fields[1] != "" {
			slug := fields[1]
			product := sealedProductBySlug(backend(), set, slug)
			if product != nil {
				query = product.Name
			} else {
				query += " " + strings.ReplaceAll(slug, "-", " ")
			}
		}
	}

	v := r.URL.Query()
	if query != "" {
		v.Set("q", query)
	}
	r.URL.RawQuery = v.Encode()
	r.URL.Path = "/sealed"

	http.Redirect(w, r, r.URL.String(), http.StatusFound)
}

func RandomSearch(w http.ResponseWriter, r *http.Request) {
	uuid := randomUUID(backend(), false)

	v := r.URL.Query()
	v.Set("q", uuid)
	r.URL.RawQuery = v.Encode()
	r.URL.Path = "/search"

	http.Redirect(w, r, r.URL.String(), http.StatusFound)
}

func RandomSealedSearch(w http.ResponseWriter, r *http.Request) {
	uuid := randomUUID(backend(), true)

	v := r.URL.Query()
	v.Set("q", uuid)
	r.URL.RawQuery = v.Encode()
	r.URL.Path = "/sealed"

	http.Redirect(w, r, r.URL.String(), http.StatusFound)
}
