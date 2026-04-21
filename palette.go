package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
)

// PaletteCardMeta returns metadata (printings, rarities, colors, types)
// for a card name, used by the chip-based filter builder.
func PaletteCardMeta(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Write([]byte(`{"error":"not implemented"}`))
}

// PaletteSets returns all known set codes with display metadata.
func PaletteSets(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write([]byte(`[]`))
}

// PaletteStores returns seller and vendor shorthand lists.
func PaletteStores(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=600")
	w.Write([]byte(`{"sellers":[],"vendors":[]}`))
}

// Placeholder - later tasks will implement JSON-serializable targets.
var (
	paletteSetsCache     []byte
	paletteSetsCacheMu   sync.RWMutex
	paletteStoresCacheMu sync.RWMutex
)

// unused import guard - later tasks will use json/strings/sync
var _ = json.Marshal
var _ = strings.ToLower
