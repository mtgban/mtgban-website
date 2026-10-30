package main

import (
	"bufio"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/mtgban-website/timeseries"
)

// variantMapRow joins the alias the archive files a card under to its matcher id.
type variantMapRow struct {
	Alias    timeseries.MagicVariant
	MtgbanID string
}

// variantMapRows lists every card and sealed product, sorted by matcher id,
// and counts the ids the backend could not resolve.
func variantMapRows(b *matcher.Backend) ([]variantMapRow, int) {
	ids := slices.Concat(b.GetUUIDs(), b.GetSealedUUIDs())
	rows := make([]variantMapRow, 0, len(ids))
	skipped := 0
	for _, id := range ids {
		co, err := b.GetUUID(id)
		if err != nil {
			skipped++
			continue
		}
		alias := magicVariant(co)
		alias.MtgjsonUUID = timeseries.NormalizeUUID(alias.MtgjsonUUID)
		alias.Language = *timeseries.NormalizeLanguage(&alias.Language)
		rows = append(rows, variantMapRow{Alias: alias, MtgbanID: co.UUID})
	}
	slices.SortFunc(rows, func(a, b variantMapRow) int {
		return strings.Compare(a.MtgbanID, b.MtgbanID)
	})
	return rows, skipped
}

func tf(v bool) string {
	if v {
		return "t"
	}
	return "f"
}

// writeVariantMap writes the rows as a TSV with a header line.
func writeVariantMap(w io.Writer, rows []variantMapRow) error {
	bw := bufio.NewWriter(w)
	if _, err := bw.WriteString("mtgjson_uuid\tis_foil\tis_etched\tis_alt\tlanguage\tmtgban_id\n"); err != nil {
		return err
	}
	for _, r := range rows {
		a := r.Alias
		line := a.MtgjsonUUID + "\t" + tf(a.IsFoil) + "\t" + tf(a.IsEtched) + "\t" + tf(a.IsAlt) + "\t" + a.Language + "\t" + r.MtgbanID + "\n"
		if _, err := bw.WriteString(line); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// serveVariantMap streams the variant map as a download.
func serveVariantMap(w http.ResponseWriter, b *matcher.Backend) {
	w.Header().Set("Content-Type", "text/tab-separated-values")
	w.Header().Set("Content-Disposition", "attachment; filename=variant_map.tsv")
	rows, skipped := variantMapRows(b)
	if skipped > 0 {
		LogPages["Admin"].Println("variant map: skipped", skipped, "ids the backend could not resolve")
	}
	if err := writeVariantMap(w, rows); err != nil {
		LogPages["Admin"].Println("variant map: write error:", err)
	}
}
