package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// probeHash is the asset cache-buster, the git commit, which differs between
// two builds of the same page.
var probeHash = regexp.MustCompile(`hash=[0-9a-f]+`)

// TestSearchRenderProbe digests the search page for a corpus of requests
// into the file SEARCH_PROBE_OUT names, so two builds of the handler can be
// compared byte for byte; without the variable it does nothing. Stores have
// to be loaded for the digests to say anything about offers.
func TestSearchRenderProbe(t *testing.T) {
	out := os.Getenv("SEARCH_PROBE_OUT")
	if out == "" {
		t.Skip("SEARCH_PROBE_OUT unset")
	}
	skipWithoutDatastore(t)
	readyToRender(t)

	// A query, then any further parameters after an ampersand.
	queries := []string{
		"r:mythic", "r:mythic&sort=retail", "r:mythic&p=3", "r:mythic&sort=buylist&p=2",
		"s:MH2", "s:MH2&sort=retail", "s:MH2&sort=buylist", "s:MH2&p=2", "s:MH2&sort=alpha&p=2",
		"t:creature s:NEO", "cn>300 s:MH2", "s:MH2 price>5", "s:MH2 buy_price>2",
		"s:MH2 store:ck", "s:MH2 -store:ck", "s:MH2 vendor:ck", "s:MH2 seller:tcglow", "s:MH2 skip:index",
		"s:MH2 cond:NM", "Lightning Bolt", "Lightning Bolt&sort=retail", "Counterspell s:7ED",
		"Collector Booster Box s:MH2", "s:MH2&ps=25&p=2",
	}
	cookies := map[string]string{
		"": "", "skipEmpty": "SearchMiscOpts=skipEmpty", "stores": "SearchListingPriority=stores",
		"factors": "SearchStoreFactors=CK:10:20",
	}

	digests := map[string]string{}
	for _, path := range []string{"/search", "/sealed"} {
		for _, q := range queries {
			query, params, _ := strings.Cut(q, "&")
			target := path + "?q=" + url.QueryEscape(query)
			if params != "" {
				target += "&" + params
			}
			for name, cookie := range cookies {
				// Twice, so a page the same build renders two ways is
				// told apart from one the builds render differently.
				var bodies [2][]byte
				for i := range bodies {
					req := httptest.NewRequest(http.MethodGet, target, nil)
					if cookie != "" {
						req.Header.Set("Cookie", cookie)
					}
					rec := httptest.NewRecorder()
					testSite.Search(rec, req)
					if rec.Code != http.StatusOK {
						t.Fatalf("%s answered %d", target, rec.Code)
					}
					bodies[i] = probeHash.ReplaceAll(rec.Body.Bytes(), nil)
				}
				key := target + " " + name
				sum := sha256.Sum256(bodies[0])
				digests[key] = hex.EncodeToString(sum[:])
				if string(bodies[0]) != string(bodies[1]) {
					digests[key] = "unstable"
					if dir := os.Getenv("SEARCH_PROBE_BODIES"); dir != "" {
						stem := filepath.Join(dir, url.PathEscape(key))
						os.WriteFile(stem+".a.html", bodies[0], 0o644)
						os.WriteFile(stem+".b.html", bodies[1], 0o644)
					}
				}
			}
		}
	}

	data, err := json.MarshalIndent(digests, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
