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

		if kind == "r" || kind == "i" {
			inv, err := findSellerInventory(store)
			if err != nil {
				http.NotFound(w, r)
				return
			}

			// Look up the hash: mtgjson, scryfall, and tcgproductid in order
			entries, found := inv[hash]
			if !found {
				entries, found = inv[mtgmatcher.Scryfall2UUID(hash)]
				if !found {
					entries = inv[mtgmatcher.Tcg2UUID(hash)]
				}
			}

			for _, entry := range entries {
				http.Redirect(w, r, entry.URL, http.StatusFound)
				return
			}
		} else if kind == "b" {
			bl, err := findVendorBuylist(store)
			if err != nil {
				http.NotFound(w, r)
				return
			}

			// Look up the hash: mtgjson, scryfall, and tcgproductid in order
			entries, found := bl[hash]
			if !found {
				entries, found = bl[mtgmatcher.Scryfall2UUID(hash)]
				if !found {
					entries = bl[mtgmatcher.Tcg2UUID(hash)]
				}
			}

			for _, entry := range entries {
				http.Redirect(w, r, entry.URL, http.StatusFound)
				return
			}
		}
	}

	http.NotFound(w, r)
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
