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
			co, err = mtgmatcher.GetUUID(mtgmatcher.Scryfall2UUID(hash))
			if err != nil {
				co, err = mtgmatcher.GetUUID(mtgmatcher.Tcg2UUID(hash))
				if err != nil {
					http.NotFound(w, r)
					return
				}
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
