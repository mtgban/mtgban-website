package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/tcgplayer"
)

// salesPaneMaxIDs is the most cards one /data/sales/ request draws: a
// search page's worth.
const salesPaneMaxIDs = 100

// SalesPaneAPI draws the Buyers column's Sales pane for each card id in the
// path, comma-separated, from the recent orders in memory: the page's
// first switch to Sales fetches them in one request. The answer maps each id
// to its pane's markup, the same table on a phone's Cards as on desktop.
func (s *site) SalesPaneAPI(w http.ResponseWriter, r *http.Request) {
	if !canSeeSales(verifiedSignature(r)) {
		errorResponse(w, http.StatusForbidden, "no access to recent sales")
		return
	}
	idsParam := strings.TrimPrefix(r.URL.Path, "/data/sales/")
	if idsParam == "" {
		errorResponse(w, http.StatusBadRequest, "missing ids")
		return
	}

	t, err := salesPaneTemplate()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "cannot draw the sales")
		return
	}
	b := s.backend()
	p := s.prices()
	recent := recentSalesStore.Snapshot()
	panes := map[string]string{}
	for _, cardID := range strings.Split(idsParam, ",") {
		cardID = strings.TrimSpace(cardID)
		_, found := panes[cardID]
		if cardID == "" || found {
			continue
		}
		if len(panes) == salesPaneMaxIDs {
			break
		}
		orders, _ := recent.For(cardID)
		groups := orders.Groups()
		for i := range groups {
			groups[i].Link = salesLink(b, p, cardID, mtgban.Condition(groups[i].Grade))
		}
		var buf bytes.Buffer
		err := t.ExecuteTemplate(&buf, "sales-pane", groups)
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, "cannot draw the sales")
			return
		}
		panes[cardID] = buf.String()
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	json.NewEncoder(w).Encode(panes)
}

// salesLink is TCGplayer's page for the card in its printing and the given
// condition, "" for a card with no product id. The orders are English only.
func salesLink(b *matcher.Backend, p *prices, cardID string, condition mtgban.Condition) string {
	co, err := b.GetUUID(cardID)
	if err != nil {
		return ""
	}
	productID, err := strconv.Atoi(findTCGproductID(b, p, cardID))
	if err != nil {
		return ""
	}
	return tcgplayer.GenerateProductURL(productID, salesPrinting(co), Affiliates().Codes["TCG"], condition, "English", false)
}

// salesPrinting is the printing TCGplayer lists a card under, "" for a sealed
// product. Magic's finishes past the plain two are all its "Foil".
func salesPrinting(co *matcher.CardObject) string {
	if co.Sealed {
		return ""
	}
	for _, finish := range matcher.Finishes {
		if finish.Slug == co.Finish {
			return finish.TCGplayer
		}
	}
	if co.Foil || co.Etched {
		return "Foil"
	}
	return ""
}
