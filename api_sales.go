package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// salesPaneMaxIDs is the most cards one /data/sales/ request draws: a
// search page's worth.
const salesPaneMaxIDs = 100

// SalesPaneAPI draws the Buyers column's Sales pane for each card id in the
// path, comma-separated, from the recent orders in memory: the page's
// first switch to Sales fetches them in one request. The answer maps each id
// to its pane's markup, the phone's for a phone.
func (s *site) SalesPaneAPI(w http.ResponseWriter, r *http.Request) {
	if verifiedSignature(r) == "" && !(DevMode && !SigCheck) {
		errorResponse(w, http.StatusUnauthorized, "log in to see recent sales")
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
	name := "sales-pane"
	if isMobileRequest(r) {
		name = "m-sales-pane"
	}

	recent := recentSalesStore.Snapshot()
	now := time.Now()
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
		var buf bytes.Buffer
		err := t.ExecuteTemplate(&buf, name, orders.Groups(now))
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
