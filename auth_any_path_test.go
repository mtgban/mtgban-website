package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// A path that only begins an open sub-page's link is not that sub-page:
// "/open-" used to pass as "/open-sub", and so skip the signature.
func TestAnyTierMatchesWholePaths(t *testing.T) {
	const marker = "ANY-BODY"
	handler := anyTierNav(t, marker)

	for _, path := range []string{"/open-"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if strings.Contains(rec.Body.String(), marker) {
			t.Errorf("%s served without a signature", path)
		}
	}
}
