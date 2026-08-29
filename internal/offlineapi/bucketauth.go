package offlineapi

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// bucketAuthValidity is how long an issued download authorization lasts. A
// sync of the whole corpus runs for tens of minutes and a client may pause and
// resume it, so the token has to outlive a single sitting; a day means a
// revoked account keeps access until at most tomorrow, which is the trade.
// B2 caps download authorizations at seven days.
const bucketAuthValidity = 24 * time.Hour

// bucketAuth is what a client needs to read the mirrored image tree itself.
// Base is the URL every object hangs off; Token authorizes the prefix.
type bucketAuth struct {
	Base    string `json:"base"`
	Token   string `json:"token"`
	Expires string `json:"expires"`
}

// serveBucketAuth issues a time-limited authorization for the image tree, so
// image bytes travel from the bucket to the client without passing through
// this server. It is the one image-related thing still served here, and it is
// a credential rather than data: never cached, never shared.
func (s *Service) serveBucketAuth(w http.ResponseWriter, r *http.Request) {
	if s.deps.ImagesDownloadAuth == nil {
		http.NotFound(w, r)
		return
	}
	base, token, expires, err := s.deps.ImagesDownloadAuth(r.Context(), bucketAuthValidity)
	if err != nil {
		log.Println("offline: image download authorization failed:", err)
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	json.NewEncoder(w).Encode(bucketAuth{
		Base:    base,
		Token:   token,
		Expires: expires.UTC().Format(time.RFC3339),
	})
}
