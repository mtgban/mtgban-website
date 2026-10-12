package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The ids are the path's last segment, comma separated, as the chart's are.
func TestBatchPricesReadsTheIdsFromThePath(t *testing.T) {
	skipWithoutDatastore(t)
	uuids := somePlainCardUUIDs(t, 2)
	registerTestSeller(t, "ZZPRICES", uuids)
	registerTestVendor(t, "ZZPRICES", uuids)

	rec := httptest.NewRecorder()
	testSite.BatchPricesAPI(rec, httptest.NewRequest(http.MethodGet, "/data/prices/"+strings.Join(uuids, ","), nil))
	var got map[string]PriceResult
	err := json.Unmarshal(rec.Body.Bytes(), &got)
	if err != nil {
		t.Fatalf("%d %q: %v", rec.Code, rec.Body.String(), err)
	}
	for _, uuid := range uuids {
		if got[uuid].SellPrice == nil || got[uuid].BuyPrice == nil {
			t.Errorf("%s: %+v, want both prices", uuid, got[uuid])
		}
	}

	rec = httptest.NewRecorder()
	testSite.BatchPricesAPI(rec, httptest.NewRequest(http.MethodGet, "/data/prices/", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("no ids: %d, want 400", rec.Code)
	}
}
