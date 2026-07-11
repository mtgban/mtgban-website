// Package imgmirror holds the pure logic of the offline image mirror:
// manifest and state types, bundle hashing, crawl planning, zip building,
// and per domain rate limiting.
package imgmirror

import (
	"hash/fnv"
	"net/url"
	"path"
	"sort"
	"strconv"
)

// ImageInfo is one set's entry in images-manifest.json.
type ImageInfo struct {
	Hash  string `json:"h"`
	Count int    `json:"n"`
	Bytes int64  `json:"b"`
}

// Manifest is the images-manifest.json document, keyed by set code.
type Manifest map[string]ImageInfo

// StateEntry records one mirrored image in mirror-state.json.
type StateEntry struct {
	Digest    string `json:"digest"`
	FetchedAt string `json:"fetchedAt"`
	Source    string `json:"source"`
	// Ext is "jpg" when cwebp was unavailable and the original was stored.
	Ext string `json:"ext,omitempty"`
}

// State is the mirror-state.json document, keyed by uuid.
type State map[string]StateEntry

// EntryName returns the stored object name for a uuid.
func (e StateEntry) EntryName(uuid string) string {
	if e.Ext == "jpg" {
		return uuid + ".jpg"
	}
	return uuid + ".webp"
}

// BundleHash hashes sorted "uuid digest" lines with fnv64a, hex encoded.
func BundleHash(digests map[string]string) string {
	uuids := make([]string, 0, len(digests))
	for id := range digests {
		uuids = append(uuids, id)
	}
	sort.Strings(uuids)

	h := fnv.New64a()
	for _, id := range uuids {
		h.Write([]byte(id))
		h.Write([]byte{' '})
		h.Write([]byte(digests[id]))
		h.Write([]byte{'\n'})
	}
	return strconv.FormatUint(h.Sum64(), 16)
}

// JoinPath appends elements to a bucket base path, preserving the scheme
// and host of remote bases. One letter schemes are Windows drive paths.
func JoinPath(base string, elems ...string) string {
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || len(u.Scheme) == 1 {
		return path.Join(append([]string{base}, elems...)...)
	}
	u.Path = path.Join(append([]string{u.Path}, elems...)...)
	return u.String()
}
