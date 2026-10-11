package main

import (
	"net/http"
	"os"
)

// ServeServiceWorker serves sw.js with the build hash injected so the
// script bytes change on every deploy and the update check fires. In dev, or
// a build without a commit, it also sets self.__DEV, which keeps the cache
// from shadowing files the server sends no-store.
func ServeServiceWorker(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile("sw.js")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write([]byte("self.__BUILD = '" + assetHash() + "';\n"))
	if DevMode || BuildCommit == "" {
		w.Write([]byte("self.__DEV = true;\n"))
	}
	w.Write(data)
}
