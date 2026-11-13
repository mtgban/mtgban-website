package main

import (
	"fmt"
	"html"
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

	// Post what the browser would: every hidden input of the sidebar form, to its action.
	sidebar := regexp.MustCompile(`(?s)<form action="([^"]*)" method="post" style="display:contents">(.*?)</form>`).FindStringSubmatch(w.Body.String())
	if sidebar == nil {
		t.Fatal("the page has no sidebar Upload form")
	}
	action := html.UnescapeString(sidebar[1])
	if action != "/upload?from=search_sidebar" {
		t.Errorf("the sidebar form posts to %q", action)
	}
	form := url.Values{}
	inputs := regexp.MustCompile(`<input[^>]*type="hidden"[^>]*>`).FindAllString(sidebar[2], -1)
	attr := regexp.MustCompile(`\s(name|value)="([^"]*)"`)
	for _, in := range inputs {
		kv := map[string]string{}
		for _, m := range attr.FindAllStringSubmatch(in, -1) {
			kv[m[1]] = html.UnescapeString(m[2])
		}
		form.Add(kv["name"], kv["value"])
	}
	if len(form["hashes"]) != MaxUploadTransfer {
		t.Fatalf("the transfer carries %d results, want %d", len(form["hashes"]), MaxUploadTransfer)
	}
	if len(inputs) != MaxUploadTransfer+1 || len(form["mode"]) != 1 {
		t.Fatalf("the form posts %d values, want the %d results and the mode", len(inputs), MaxUploadTransfer)
	}
	if !strings.Contains(w.Body.String(), TransferCutMessage) {
		t.Errorf("the page does not say the transfer stops at %d results", MaxUploadTransfer)
	}

	post := httptest.NewRequest(http.MethodPost, action, strings.NewReader(form.Encode()))
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
