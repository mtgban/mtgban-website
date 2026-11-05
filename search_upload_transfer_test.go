package main

import (
	"fmt"
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
	if !strings.Contains(w.Body.String(), TransferCutMessage) {
		t.Errorf("the page does not say the transfer stops at %d results", MaxUploadTransfer)
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

// The notice that the transfer and the export stop short names the number
// they stop at.
func TestTransferCutMessageNamesTheCap(t *testing.T) {
	n := fmt.Sprintf("%d,%03d", MaxUploadTransfer/1000, MaxUploadTransfer%1000)
	if !strings.Contains(TransferCutMessage, " "+n+" ") {
		t.Errorf("%q does not name %s", TransferCutMessage, n)
	}
	if MaxAPISearchResults != MaxUploadTransfer {
		t.Errorf("the export stops at %d, the transfer at %d", MaxAPISearchResults, MaxUploadTransfer)
	}
}

// A search below the transfer's cap raises no notice about it.
func TestSearchUnderTheTransferCapSaysNothing(t *testing.T) {
	skipWithoutDatastore(t)
	withSigMode(t, true, false)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		defer delete(LogPages, "Search")
	}

	req := httptest.NewRequest(http.MethodGet, "/search?q="+url.QueryEscape("s:M10"), nil)
	w := httptest.NewRecorder()
	testSite.Search(w, req)
	if !strings.Contains(w.Body.String(), `name="hashes"`) {
		t.Skip("s:M10 finds nothing in this datastore")
	}
	if strings.Contains(w.Body.String(), TransferCutMessage) {
		t.Error("a search of one set says its transfer is cut")
	}
}
