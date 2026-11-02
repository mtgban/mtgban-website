package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// The Uploader transfer of a search that fills the result cap reaches the
// Uploader: past 10,000 values Go's form parser hands back an empty form, and
// the signing middleware, parsing first, drops the error.
func TestSearchUploadTransferReachesUploader(t *testing.T) {
	skipWithoutDatastore(t)
	withSigMode(t, true, false)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	for _, page := range []string{"Search", "Upload"} {
		if LogPages[page] == nil {
			LogPages[page] = log.New(io.Discard, "", 0)
			defer delete(LogPages, page)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/search?q="+url.QueryEscape("t:creature"), nil)
	w := httptest.NewRecorder()
	testSite.Search(w, req)
	if !strings.Contains(w.Body.String(), TooManyMessage) {
		t.Skip("t:creature does not fill the result cap in this datastore")
	}

	form := url.Values{"mode": {"false"}}
	for _, m := range regexp.MustCompile(`name="hashes" value="([^"]+)"`).FindAllStringSubmatch(w.Body.String(), -1) {
		form.Add("hashes", m[1])
	}
	if len(form["hashes"]) != MaxUploadTransfer {
		t.Fatalf("the transfer carries %d results, want %d", len(form["hashes"]), MaxUploadTransfer)
	}

	post := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	enforceSigning(testSite, http.HandlerFunc(testSite.Upload)).ServeHTTP(w, post)
	if strings.Contains(w.Body.String(), "No card list arrived") {
		t.Fatal("the Uploader received no list")
	}
	if !strings.Contains(w.Body.String(), form["hashes"][0]) {
		t.Errorf("the Uploader does not list %s, the first result", form["hashes"][0])
	}
}
