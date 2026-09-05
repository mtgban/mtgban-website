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
	"time"

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
// Every game keys on an identifier the card carries, never on anything about
// the url its artwork happens to live at. Which identifier differs: Magic is
// mirrored from MTGJSON crossed with Scryfall's bulk data and keyed on the
// scryfall id, while every other game is mirrored out of mtgban's own
// datastore and keyed on the card's uuid there.
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
	if co.Sealed {
		// TCGplayer names a product image for its own product id, so this
		// reads the identifier rather than that url for the same reason the
		// single below does, not because they ever disagree.
		id := co.Identifiers["tcgplayerProductId"]
		if id == "" {
			return ""
		}
		return "p-" + co.SetCode + "-" + id
	}
	return co.Identifiers["scryfallId"]
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

// catalogFragments holds the catalog's datastore half, already marshalled.
// Cards and sets are derived from the datastore alone, so they only change
// when it is replaced, while the store list changes with every scraper
// reload - and a reload is what asks for a refresh.
type catalogFragments struct {
	source time.Time
	cards  []byte
	sets   []byte
	nCards int
	nSets  int
}

// buildCatalogFragments marshals the cards and sets of the current
// datastore. Returns nil when the datastore holds no cards.
func (s *Service) buildCatalogFragments(source time.Time) (*catalogFragments, error) {
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
		return nil, nil
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

	rawCards, err := json.Marshal(cards)
	if err != nil {
		return nil, err
	}
	rawSets, err := json.Marshal(sets)
	if err != nil {
		return nil, err
	}

	return &catalogFragments{
		source: source,
		cards:  rawCards,
		sets:   rawSets,
		nCards: len(cards),
		nSets:  len(sets),
	}, nil
}

// refreshCatalog rebuilds the gzipped catalog document from the current
// mtgmatcher datastore and scraper list. Only the store list is rebuilt
// per call: the cards and sets are reused until the datastore is replaced.
func (s *Service) refreshCatalog() {
	source := time.Time{}
	if s.deps.LastDatastoreUpdate != nil {
		source = s.deps.LastDatastoreUpdate()
	}

	frags := s.fragments
	if frags == nil || !frags.source.Equal(source) {
		next, err := s.buildCatalogFragments(source)
		if err != nil {
			log.Println("offline: catalog marshal failed:", err)
			return
		}
		if next == nil {
			log.Println("offline: no cards loaded, catalog not rebuilt")
			return
		}
		s.fragments = next
		frags = next
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

	rawStores, err := json.Marshal(stores)
	if err != nil {
		log.Println("offline: catalog marshal failed:", err)
		return
	}

	// The document these pieces make is what used to be marshalled whole,
	// key order included: encoding/json sorts a map's keys, so cards, sets
	// and stores come out in the order written here. Hashing the pieces
	// rather than a joined copy keeps the version the same as before for
	// the same content, without building the whole 37MB again.
	parts := [][]byte{
		[]byte(`{"cards":`), frags.cards,
		[]byte(`,"sets":`), frags.sets,
		[]byte(`,"stores":`), rawStores,
		[]byte(`}`),
	}

	h := fnv.New64a()
	for _, part := range parts {
		h.Write(part)
	}
	version := strconv.FormatUint(h.Sum64(), 16)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte(`{"version":"` + version + `",`))
	// Everything but the opening brace the version now stands in for
	parts[0] = parts[0][1:]
	for _, part := range parts {
		gz.Write(part)
	}
	if err := gz.Close(); err != nil {
		log.Println("offline: catalog gzip failed:", err)
		return
	}

	s.catalog.Store(&catalogCache{version: version, gz: buf.Bytes()})
	log.Printf("offline: catalog rebuilt, %d cards, %d sets, %d stores, %d KiB gz", frags.nCards, frags.nSets, len(stores), buf.Len()/1024)
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
