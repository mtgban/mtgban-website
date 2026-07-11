package main

import (
	"net/http"
	"os"
)

// ServeServiceWorker serves sw.js with the build hash injected so the
// script bytes change on every deploy and the update check fires.
func ServeServiceWorker(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile("sw.js")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write([]byte("self.__BUILD = '" + BuildCommit + "';\n"))
	w.Write(data)
}
