package tcgcsv

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bodgit/sevenzip"
)

// ArchiveEpoch is the earliest date tcgcsv has a daily price archive for.
// Backfill starts here by default.
var ArchiveEpoch = time.Date(2024, 2, 8, 0, 0, 0, 0, time.UTC)

// FetchPriceArchive downloads and decodes the daily price archive for date.
// The archive (a .ppmd.7z holding every category's prices for that day) is
// decoded in memory; only entries whose category is in wantCategories are read
// and decompressed (pass an empty map to take all). Results are grouped by
// category id.
//
// found is false when tcgcsv has no archive for date (HTTP 404), which the
// caller should treat as "skip this day", not an error.
func (c *Client) FetchPriceArchive(ctx context.Context, date time.Time, wantCategories map[int]bool) (byCategory map[int][]Price, found bool, err error) {
	url := fmt.Sprintf("%s/archive/tcgplayer/prices-%s.ppmd.7z", c.baseURL, date.Format("2006-01-02"))
	body, status, err := c.do(ctx, url)
	if err != nil {
		return nil, false, err
	}
	if status == http.StatusNotFound {
		return nil, false, nil
	}
	if status != http.StatusOK {
		return nil, false, fmt.Errorf("tcgcsv: %s -> %d: %s", url, status, snippet(body))
	}

	zr, err := sevenzip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, false, fmt.Errorf("tcgcsv: open archive %s: %w", url, err)
	}

	byCategory = make(map[int][]Price)
	for _, entry := range zr.File {
		cat, ok := categoryFromArchivePath(entry.Name)
		if !ok {
			continue
		}
		if len(wantCategories) > 0 && !wantCategories[cat] {
			continue
		}
		prices, err := readArchivePrices(entry)
		if err != nil {
			return nil, false, err
		}
		byCategory[cat] = append(byCategory[cat], prices...)
	}
	return byCategory, true, nil
}

func readArchivePrices(entry *sevenzip.File) ([]Price, error) {
	rc, err := entry.Open()
	if err != nil {
		return nil, fmt.Errorf("tcgcsv: open %s: %w", entry.Name, err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("tcgcsv: read %s: %w", entry.Name, err)
	}
	return decodeResults[Price](data, entry.Name)
}

// categoryFromArchivePath parses the category id out of an archive entry path
// like "2024-02-08/71/17690/prices". It returns ok=false for any other path
// (directory markers, unexpected names, etc.).
func categoryFromArchivePath(name string) (int, bool) {
	parts := strings.Split(name, "/")
	if len(parts) != 4 || parts[3] != "prices" {
		return 0, false
	}
	cat, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, false
	}
	return cat, true
}
