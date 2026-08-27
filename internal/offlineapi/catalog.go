package offlineapi

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"hash/fnv"
	"log"
	"net/http"
	"path"
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
	Image    string   `json:"i,omitempty"`
}

// imageKey is the key the mirror filed this card's image under, and so what
// the client looks for in a downloaded bundle.
//
// Magic and every other game disagree on what that is. Magic's mirror keys on
// the scryfall id, which is what its image URL is named for, and there are
// 120k objects filed that way. Every other game is mirrored out of mtgban's
// own datastore and keyed on the card's uuid, because those URLs are their
// CDN's own filenames and name nothing the rest of the system knows.
func imageKey(co *mtgmatcher.CardObject, magic bool) string {
	if co.Images["full"] == "" {
		return ""
	}
	if !magic {
		if co.Sealed {
			return "p-" + co.UUID
		}
		return basePrintingID(co.UUID)
	}
	base := path.Base(co.Images["full"])
	base = strings.TrimSuffix(base, ".jpg")
	if base == "" || base == "." || base == "/" {
		return ""
	}
	if co.Sealed {
		return "p-" + co.SetCode + "-" + base
	}
	return base
}

// basePrintingID strips the finish suffix off a datastore uuid.
//
// A printing's finishes are uuids of their own — Lorcana files 1854 and
// 1854_f, Riftbound ogn-066-298_nonfoil and ..._foil — and they all share one
// image, which the mirror stores once under the printing's id. This is the
// trim that finds it, and the mirror documents the same rule from its side.
//
// It is not a tidying detail. Riftbound's base id is not in the uuid map at
// all, only its finishes are, so every one of its cards needs this; without it
// the game resolves no images whatsoever.
func basePrintingID(uuid string) string {
	if i := strings.LastIndex(uuid, "_"); i > 0 {
		return uuid[:i]
	}
	return uuid
}

// newCatalogCard builds a catalog entry from a card object and its store list.
func newCatalogCard(co *mtgmatcher.CardObject, products []string, magic bool) catalogCard {
	return catalogCard{
		Name:     co.Name,
		Number:   co.Number,
		Rarity:   co.Rarity,
		SetCode:  co.SetCode,
		Foil:     co.Foil,
		Etched:   co.Etched,
		Sealed:   co.Sealed,
		Products: products,
		Image:    imageKey(co, magic),
	}
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
	magic := s.magicImageKeys()
	addCard := func(uuid string) {
		co, err := mtgmatcher.GetUUID(uuid)
		if err != nil {
			return
		}
		cards[uuid] = newCatalogCard(co, s.deps.CardObjectSources(co), magic)
	}
	for _, uuid := range mtgmatcher.GetUUIDs() {
		addCard(uuid)
	}
	for _, uuid := range mtgmatcher.GetSealedUUIDs() {
		addCard(uuid)
	}

	// The store list is allowed to be empty - the scrapers land after the
	// datastore - but a catalog with no cards is not a catalog. Storing one
	// would answer sync requests with an empty world instead of saying the
	// server is not ready yet.
	if len(cards) == 0 {
		log.Println("offline: no cards loaded, catalog not rebuilt")
		return
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
