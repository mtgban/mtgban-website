package imgmirror

import (
	"archive/zip"
	"bytes"
	"sort"
	"time"
)

// BundleEntry is one file to place in a bundle zip.
type BundleEntry struct {
	Name string
	Data []byte
}

// BuildBundle writes a deterministic uncompressed zip of the entries.
func BuildBundle(entries []BundleEntry) ([]byte, error) {
	sorted := make([]BundleEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, entry := range sorted {
		w, err := zw.CreateHeader(&zip.FileHeader{
			Name:     entry.Name,
			Method:   zip.Store,
			Modified: time.Unix(0, 0).UTC(),
		})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(entry.Data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
