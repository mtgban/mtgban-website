package main

import (
	"net/http"
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
		co, err := mtgmatcher.GetUUID(hash)
		if err != nil {
			co, err = mtgmatcher.GetUUID(externalUUID(hash))
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

// namesFinish reports whether a word names a finish of the printing at set and
// number. It is how the third part of a card path is told from the card name
// scryfall puts in the same position, and it asks with the filter the query
// would run, over the printings the path already names - so a word this route
// accepts is a word the search answers. A name answers to nothing: spelled the
// way finishes are spelled, "another-round" is "anotherround", which no
// printing is sold as.
func namesFinish(set, number, word string) bool {
	edition, err := mtgmatcher.GetSet(set)
	if err != nil {
		return false
	}

	values := fixupFinishNG(word)
	for _, card := range edition.Cards {
		if !strings.EqualFold(card.Number, number) {
			continue
		}
		// A set carries one card object per printing, in its plain finish;
		// f:foil is answered by a sibling of that one rather than by it.
		for _, id := range mtgmatcher.FinishSiblings(card.UUID) {
			co, err := mtgmatcher.GetUUID(id)
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

// CardRedirect answers the URL shape scryfall.com uses for a printing,
// /card/<set>/<number>, so a link copied from there reaches the same card
// here: swap the host, keep the path.
//
// Every part is optional from the right. /card/<set> is the set, and /card is
// the search - a path that names less asks for more, rather than for nothing.
//
// The third part is a finish, and scryfall fills it with the card's name, so
// it is taken as a finish only when it names one - see namesFinish. Anything
// past it is scryfall's too, a language or a tracking parameter, and names no
// printing either.
//
// A finish wins that position whatever else the word is, so scryfall's link
// for the card named Foil, /card/uma/55/foil, lands on the foil printing of
// it. The position means one thing wherever it is read, and the card entire is
// the same link without the word.
//
// The printing is handed to the search rather than resolved here, which is
// what makes the whole finish family land on one page when no finish is asked
// for: a number names one printing, and this site prices its foil and its
// nonfoil separately. It also means a set code scryfall spells differently, or
// a number this game writes another way, fails as a search that says so rather
// than as a dead link.
//
// The number is matched as printed, with cns: rather than cn:. Scryfall writes
// it the way the card does, stars and daggers included, and those are exactly
// what tells two printings of one number apart: 4ED 107 is Thoughtlace and
// 107† is Drudge Skeletons, and cn: answers both.
func CardRedirect(w http.ResponseWriter, r *http.Request) {
	// Only the trailing slashes go: a leading one is an empty set code, and
	// trimming it would promote the number into its place.
	path := strings.TrimRight(strings.TrimPrefix(r.URL.Path, "/card/"), "/")
	fields := strings.Split(path, "/")

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

			if len(fields) > 2 && namesFinish(set, number, fields[2]) {
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

func RandomSearch(w http.ResponseWriter, r *http.Request) {
	uuid := randomUUID(false)

	v := r.URL.Query()
	v.Set("q", uuid)
	r.URL.RawQuery = v.Encode()
	r.URL.Path = "/search"

	http.Redirect(w, r, r.URL.String(), http.StatusFound)
}

func RandomSealedSearch(w http.ResponseWriter, r *http.Request) {
	uuid := randomUUID(true)

	v := r.URL.Query()
	v.Set("q", uuid)
	r.URL.RawQuery = v.Encode()
	r.URL.Path = "/sealed"

	http.Redirect(w, r, r.URL.String(), http.StatusFound)
}
