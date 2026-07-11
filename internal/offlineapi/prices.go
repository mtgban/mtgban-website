package offlineapi

import (
	"compress/gzip"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/mtgban/mtgban-website/internal/offline"
)

// enabledStores intersects the optional stores param with every
// non-blocklisted scraper, mirroring PriceAPI's ALL_ACCESS branch.
func (s *Service) enabledStores(r *http.Request) []string {
	all := s.deps.EnabledStores()
	filter := r.FormValue("stores")
	if filter == "" {
		return all
	}
	var out []string
	for _, shorthand := range strings.Split(filter, ",") {
		if slices.Contains(all, shorthand) {
			out = append(out, shorthand)
		}
	}
	return out
}

// servePrices builds, watermarks, and streams one set's payload.
func (s *Service) servePrices(w http.ResponseWriter, r *http.Request, email, rest string) {
	setCode := strings.TrimSuffix(rest, ".bin")
	canonCode, err := s.deps.CanonicalSetCode(setCode)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	setCode = canonCode

	stores := s.enabledStores(r)

	payload, err := s.deps.BuildSetPayload(setCode, stores)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Override snapshot from manifest store if available.
	if sv, found := s.manifestStore.Get().Sets[setCode]; found {
		if t, err := time.Parse(time.RFC3339, sv.Version); err == nil {
			payload.Snapshot = t
		}
	}

	secret := s.deps.WatermarkSecret()
	if len(secret) == 0 {
		log.Println("offline: BAN_SECRET empty, watermark not attributable")
	}
	offline.Watermark(secret, email, payload)

	data, err := offline.Encode(payload)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Cache-Control", "private, no-store")
	gz := gzip.NewWriter(w)
	gz.Write(data)
	gz.Close()
}
