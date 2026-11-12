package embed

import (
	"strconv"
	"strings"
	"time"

	"github.com/mtgban/go-mtgban/matcher"
)

// SharePreview is a shared upload list's link preview.
type SharePreview struct {
	Title       string
	Description string
	ImageURL    string
}

// UploadShare previews a shared upload list from its rows' ids and
// quantities: its mode as the title, its copies and expiry as the
// description, and its first card's picture. Ids the datastore cannot place
// are left out; with none placed, it is empty.
func UploadShare(backend *matcher.Backend, ids, qtys []string, buylist bool, expires time.Time) SharePreview {
	var out SharePreview
	var singleCopies, sealedCopies int
	for i, id := range ids {
		co, err := backend.GetUUID(id)
		if err != nil {
			continue
		}
		qty := 1
		if i < len(qtys) {
			n, err := strconv.Atoi(qtys[i])
			if err == nil && n > 0 {
				qty = n
			}
		}
		if co.Sealed {
			sealedCopies += qty
		} else {
			singleCopies += qty
		}
		if out.ImageURL == "" {
			out.ImageURL = co.Images["full"]
		}
	}
	if singleCopies+sealedCopies == 0 {
		return SharePreview{}
	}

	out.Title = "Shared retail list"
	if buylist {
		out.Title = "Shared buylist"
	}
	out.Description = size(singleCopies, sealedCopies) + ". Link expires " +
		expires.UTC().Format("Jan 2") + "."
	return out
}

// size counts cards and sealed products, naming only the kinds present.
func size(singles, sealed int) string {
	var parts []string
	if singles > 0 {
		parts = append(parts, plural(singles, "card", "cards"))
	}
	if sealed > 0 {
		parts = append(parts, plural(sealed, "sealed product", "sealed products"))
	}
	return strings.Join(parts, " and ")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}
