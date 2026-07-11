package offlineapi

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"hash/fnv"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

type catalogCard struct {
	Name     string   `json:"n"`
	Number   string   `json:"num,omitempty"`
	Rarity   string   `json:"r,omitempty"`
	SetCode  string   `json:"set"`
	Foil     bool     `json:"f,omitempty"`
	Etched   bool     `json:"e,omitempty"`
	Sealed   bool     `json:"s,omitempty"`
	Products []string `json:"p,omitempty"`
}

type catalogSet struct {
	Name    string `json:"n"`
	Keyrune string `json:"k,omitempty"`
	Date    string `json:"d,omitempty"`
}

type catalogStore struct {
	Name    string `json:"n"`
	Country string `json:"c,omitempty"`
	Sealed  bool   `json:"s,omitempty"`
	Index   bool   `json:"i,omitempty"`
	Buylist bool   `json:"b,omitempty"`
}

type catalogCache struct {
	version string
	gz      []byte
}

// refreshCatalog rebuilds the gzipped catalog document from the current
// mtgmatcher datastore and scraper list.
func (s *Service) refreshCatalog() {
	cards := map[string]catalogCard{}
	for _, uuid := range mtgmatcher.GetUUIDs() {
		co, err := mtgmatcher.GetUUID(uuid)
		if err != nil {
			continue
		}
		cards[uuid] = catalogCard{
			Name:     co.Name,
			Number:   co.Number,
			Rarity:   co.Rarity,
			SetCode:  co.SetCode,
			Foil:     co.Foil,
			Etched:   co.Etched,
			Sealed:   co.Sealed,
			Products: s.deps.CardObjectSources(co),
		}
	}

	sets := map[string]catalogSet{}
	for _, code := range mtgmatcher.GetAllSets() {
		set, err := mtgmatcher.GetSet(code)
		if err != nil {
			continue
		}
		sets[code] = catalogSet{
			Name:    set.Name,
			Keyrune: strings.ToLower(set.KeyruneCode),
			Date:    set.ReleaseDate,
		}
	}

	retailBlock := s.deps.RetailBlockList()
	buylistBlock := s.deps.BuylistBlockList()

	stores := map[string]catalogStore{}
	for _, seller := range s.deps.Sellers() {
		info := seller.Info()
		if slices.Contains(retailBlock, info.Shorthand) {
			continue
		}
		stores[info.Shorthand] = catalogStore{
			Name:    s.deps.ScraperName(info.Shorthand),
			Country: info.CountryFlag,
			Sealed:  info.SealedMode,
			Index:   info.MetadataOnly,
		}
	}
	for _, vendor := range s.deps.Vendors() {
		info := vendor.Info()
		if slices.Contains(buylistBlock, info.Shorthand) {
			continue
		}
		entry, found := stores[info.Shorthand]
		if !found {
			entry = catalogStore{
				Name:    s.deps.ScraperName(info.Shorthand),
				Country: info.CountryFlag,
				Sealed:  info.SealedMode,
				Index:   info.MetadataOnly,
			}
		}
		entry.Buylist = true
		stores[info.Shorthand] = entry
	}

	doc := map[string]any{"sets": sets, "cards": cards, "stores": stores}
	raw, err := json.Marshal(doc)
	if err != nil {
		log.Println("offline: catalog marshal failed:", err)
		return
	}

	h := fnv.New64a()
	h.Write(raw)
	version := strconv.FormatUint(h.Sum64(), 16)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte(`{"version":"` + version + `",`))
	gz.Write(raw[1:])
	if err := gz.Close(); err != nil {
		log.Println("offline: catalog gzip failed:", err)
		return
	}

	s.catalog.Store(&catalogCache{version: version, gz: buf.Bytes()})
	log.Printf("offline: catalog rebuilt, %d cards, %d sets, %d stores, %d KiB gz", len(cards), len(sets), len(stores), buf.Len()/1024)
}

func (s *Service) catalogVersion() string {
	c := s.catalog.Load()
	if c == nil {
		return ""
	}
	return c.version
}

// serveCatalog serves the cached gzipped catalog with ETag support.
func (s *Service) serveCatalog(w http.ResponseWriter, r *http.Request) {
	c := s.catalog.Load()
	if c == nil {
		http.Error(w, "catalog not ready", http.StatusServiceUnavailable)
		return
	}
	etag := `"` + c.version + `"`
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "private, max-age=3600")
	w.Write(c.gz)
}
