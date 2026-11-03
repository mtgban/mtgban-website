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

// The Uploader transfer of a search that finds more results than it takes
// reaches the Uploader, and the page says it takes the first ones: past
// 10,000 values Go's form parser hands back an empty form, and the signing
// middleware, parsing first, drops the error.
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
	form := url.Values{"mode": {"false"}}
	for _, m := range regexp.MustCompile(`name="hashes" value="([^"]+)"`).FindAllStringSubmatch(w.Body.String(), -1) {
		form.Add("hashes", m[1])
	}
	if len(form["hashes"]) < MaxUploadTransfer {
		t.Skipf("t:creature finds %d results in this datastore, under the transfer's %d", len(form["hashes"]), MaxUploadTransfer)
	}
	if len(form["hashes"]) != MaxUploadTransfer {
		t.Fatalf("the transfer carries %d results, want %d", len(form["hashes"]), MaxUploadTransfer)
	}
	for _, label := range []string{"Export", "Upload"} {
		want := fmt.Sprintf(`sidebar-compact-cut" title="First %d results">%s<`, MaxUploadTransfer, label)
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("the %s label does not say it takes the first %d results", label, MaxUploadTransfer)
		}
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
