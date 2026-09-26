package tcgcsv

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ArchiveEpoch is the earliest date tcgcsv has a daily price archive for.
// Backfill starts here by default.
var ArchiveEpoch = time.Date(2024, 2, 8, 0, 0, 0, 0, time.UTC)

// ErrArchiveUnavailable reports that tcgcsv is not serving the price archive at
// all: every date under /archive/ answers 403 with a notice, not just the one
// asked for. It is withdrawn, not gone -- tcgcsv says it still records prices
// and means to publish them again -- so the archive reader stays put and starts
// working the moment the 403 stops. Callers match on this to fall back to the
// live snapshot instead of asking for hundreds more dates that will all refuse.
var ErrArchiveUnavailable = errors.New("tcgcsv: the daily price archive is not being served")

// ErrArchiveTooling reports that no 7z binary was found. Like
// ErrArchiveUnavailable it says nothing about the date asked for, so a caller
// looping over days should stop on it rather than count it as one bad day.
var ErrArchiveTooling = errors.New("tcgcsv: no 7z binary")

// sevenZipBinaries are the 7z CLIs we accept, in order of preference. The
// archives use solid PPMd compression, which pure-Go 7z readers do not reliably
// decode (they fail on solid blocks), so extraction shells out to p7zip.
var sevenZipBinaries = []string{"7z", "7za", "7zr"}

func find7z() (string, error) {
	for _, name := range sevenZipBinaries {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("%w found (looked for %s); install p7zip", ErrArchiveTooling, strings.Join(sevenZipBinaries, ", "))
}

// FetchPriceArchive downloads the daily price archive for date, extracts it with
// the 7z CLI, and returns prices grouped by category. Only the categories in
// wantCategories are unpacked (pass an empty map to take all).
//
// found is false when tcgcsv has no archive for date (HTTP 404), which the
// caller should treat as "skip this day", not an error. A 403 is the different,
// whole-archive answer and comes back as ErrArchiveUnavailable.
func (c *Client) FetchPriceArchive(ctx context.Context, date time.Time, wantCategories map[int]bool) (byCategory map[int][]Price, found bool, err error) {
	dateStr := date.Format("2006-01-02")
	url := fmt.Sprintf("%s/archive/tcgplayer/prices-%s.ppmd.7z", c.baseURL, dateStr)
	body, status, err := c.do(ctx, url, archiveTimeout)
	if err != nil {
		return nil, false, err
	}
	if status == http.StatusNotFound {
		return nil, false, nil
	}
	// The withdrawal notice is served as the 403 body and says what happened and
	// why, so carry it through instead of paraphrasing it.
	if status == http.StatusForbidden {
		return nil, false, fmt.Errorf("%w: %s: %s", ErrArchiveUnavailable, url, snippet(body))
	}
	if status != http.StatusOK {
		return nil, false, fmt.Errorf("tcgcsv: %s -> %d: %s", url, status, snippet(body))
	}

	// Looked up after the fetch, not before: a run that only learns the archive
	// is withdrawn needs no extractor, and demanding one first would hide that
	// answer behind a missing dependency.
	bin, err := find7z()
	if err != nil {
		return nil, false, err
	}

	tmpDir, err := os.MkdirTemp("", "tcgcsv-archive-")
	if err != nil {
		return nil, false, err
	}
	defer os.RemoveAll(tmpDir)

	archivePath := filepath.Join(tmpDir, "prices.7z")
	if err := os.WriteFile(archivePath, body, 0o600); err != nil {
		return nil, false, err
	}
	extractDir := filepath.Join(tmpDir, "x")
	// 7z only creates the output directory when it extracts at least one file.
	// When the include filter matches nothing (a category that didn't exist yet
	// that day) it exits 0 without ever creating extractDir, and the WalkDir
	// below would then fail on the missing root. Create it up front so a
	// zero-match extraction is walked as an empty tree instead of erroring.
	if err := os.MkdirAll(extractDir, 0o700); err != nil {
		return nil, false, err
	}

	// Include only the wanted categories' subtrees (e.g. "2024-04-21/71/*"). An
	// empty want set extracts the whole archive. A pattern that matches nothing
	// (a game that didn't exist yet that day) is not an error: 7z extracts zero
	// files and the walk below simply finds none.
	var includes []string
	for cat := range wantCategories {
		includes = append(includes, fmt.Sprintf("%s/%d/*", dateStr, cat))
	}
	if err := extract7z(ctx, bin, archivePath, extractDir, includes); err != nil {
		return nil, false, fmt.Errorf("tcgcsv: extract %s: %w", url, err)
	}

	byCategory = make(map[int][]Price)
	walkErr := filepath.WalkDir(extractDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(extractDir, path)
		if err != nil {
			return err
		}
		cat, ok := categoryFromArchivePath(filepath.ToSlash(rel))
		if !ok {
			return nil
		}
		if len(wantCategories) > 0 && !wantCategories[cat] {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		prices, err := decodeResults[Price](data, rel)
		if err != nil {
			return err
		}
		byCategory[cat] = append(byCategory[cat], prices...)
		return nil
	})
	if walkErr != nil {
		return nil, false, fmt.Errorf("tcgcsv: read archive %s: %w", url, walkErr)
	}
	return byCategory, true, nil
}

func extract7z(ctx context.Context, bin, archivePath, destDir string, includes []string) error {
	// x: extract with full paths, -y: assume yes, -bd: no progress indicator,
	// -o<dir>: output directory (no space after -o).
	args := []string{"x", "-y", "-bd", "-o" + destDir, archivePath}
	args = append(args, includes...)
	cmd := exec.CommandContext(ctx, bin, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w: %s", filepath.Base(bin), err, snippet(out))
	}
	return nil
}

// categoryFromArchivePath parses the category id out of an archive entry path
// like "2024-02-08/71/17690/prices". It returns ok=false for any other path.
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
