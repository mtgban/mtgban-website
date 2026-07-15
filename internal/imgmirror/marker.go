package imgmirror

import (
	"context"
	"encoding/json"
	"time"

	"github.com/mtgban/simplecloud"
)

const markerName = "mirror-backfill-complete.json"

// Marker records that a full, successful, unfiltered mirror run completed.
type Marker struct {
	CompletedAt string `json:"completed_at"`
	Images      int    `json:"images"`
}

// ReadMarker reports the marker and whether it exists; transient bucket
// errors are returned, never treated as absence.
func ReadMarker(ctx context.Context, bucket simplecloud.Reader, base string) (Marker, bool, error) {
	var m Marker
	reader, err := simplecloud.InitReader(ctx, bucket, JoinPath(base, markerName))
	if err != nil {
		if isNotExist(err) {
			return m, false, nil
		}
		return m, false, err
	}
	defer reader.Close()
	// B2 opens lazily, so a missing object surfaces here on first read.
	if err := json.NewDecoder(reader).Decode(&m); err != nil {
		if isNotExist(err) {
			return m, false, nil
		}
		return m, false, err
	}
	return m, true, nil
}

// WriteMarker stamps the marker with the current time and corpus size.
func WriteMarker(ctx context.Context, bucket simplecloud.Writer, base string, images int) error {
	return saveBucketJSON(ctx, bucket, base, markerName, Marker{
		CompletedAt: time.Now().UTC().Format(time.RFC3339),
		Images:      images,
	})
}
