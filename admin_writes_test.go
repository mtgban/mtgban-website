package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/internal/sessionstore"
)

// adminSavingFields are the form fields an admin editor or form saves from,
// each with a value its editor refuses, so that reading it leaves a warning
// and saves nothing.
var adminSavingFields = map[string]string{
	"textArea":               "not json",
	"checkpointsTextArea":    "not json",
	"aclTextArea":            "not json",
	"affiliatesTextArea":     "not json",
	"datasetsTextArea":       "not json",
	"infrastructureTextArea": "not json",
	"keyOverridesTextArea":   "not json",
	"grantEmail":             "not-an-email",
	"revokeEmail":            "nobody@example.invalid",
}

// runAdminEditors runs every editor and form the admin page saves from on r.
func runAdminEditors(r *http.Request) PageVars {
	var pv PageVars
	adminConfigEditor(r, &pv)
	adminCheckpointsEditor(r, &pv)
	adminACLEditor(r, &pv)
	adminAffiliatesEditor(r, &pv)
	adminDatasetsEditor(r, &pv)
	adminInfrastructureEditor(r, &pv)
	testSite.adminKeyOverrides(r, nil, &pv)
	adminGrantAdd(r, &pv)
	adminGrantRevoke(r, &pv)
	return pv
}

func postForm(target string, form url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// An editor reads what it saves from a POST's body: the same field in a
// link's query string, which a page on another site can send an admin to,
// reaches no editor.
func TestAdminEditorsSaveOnlyFromAPostBody(t *testing.T) {
	withConfigCopy(t)
	for field, value := range adminSavingFields {
		form := url.Values{field: {value}}

		pv := runAdminEditors(postForm("/admin", form))
		if pv.WarningMessage == "" {
			t.Errorf("%s: a POST did not reach its editor", field)
		}

		pv = runAdminEditors(httptest.NewRequest(http.MethodGet, "/admin?"+form.Encode(), nil))
		if pv.WarningMessage != "" {
			t.Errorf("%s: a GET reached its editor: %s", field, pv.WarningMessage)
		}

		pv = runAdminEditors(postForm("/admin?"+form.Encode(), nil))
		if pv.WarningMessage != "" {
			t.Errorf("%s: a POST's query string reached its editor: %s", field, pv.WarningMessage)
		}
	}
}

// Removing a session store and minting an API key both write, so a link
// naming them renders the page and does neither.
func TestAdminLinksDoNotRemoveStoresOrMintKeys(t *testing.T) {
	keepScrapers(t)
	withSigMode(t, true, false)

	_, err := Sessions.Publish(backend(), sessionstore.Retail, sessionInfo("ZZS"), []UploadEntry{{CardID: "uuid-a", OriginalPrice: 1}})
	if err != nil {
		t.Fatalf("publishing: %s", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/admin?removestore=ZZS&kind=retail", nil)
	rec := httptest.NewRecorder()
	testSite.Admin(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("a removestore link answered %d, want the page", rec.Code)
	}
	_, err = findSellerInventory("ZZS")
	if err != nil {
		t.Error("a removestore link removed ZZS")
	}

	// Both users already hold a secret, so even a minted key writes nothing.
	const user = "ops@example.com"
	withAPIUserSecret(t, user, goldenSecret)
	withAPIUserSecret(t, DefaultAPIDemoUser, goldenSecret)
	for _, tool := range []string{"newKey&user=" + user + "&duration=30", "demokey"} {
		req = httptest.NewRequest(http.MethodGet, "/admin?page=tools&tool="+tool, nil)
		req.Host = "mtgban.com"
		rec = httptest.NewRecorder()
		testSite.Admin(rec, req)
		if rec.Code != http.StatusOK || rec.Header().Get("Location") != "" {
			t.Errorf("a %s link answered %d to %q, want the page", tool, rec.Code, rec.Header().Get("Location"))
		}
	}
}

// A POST the browser marks as from another site, or whose Origin is not this
// site's own, scheme and public host behind the proxy included, is refused
// before any editor reads it; this site's own, a dev box's, or none passes.
func TestAdminRefusesCrossSitePosts(t *testing.T) {
	withSigMode(t, true, false)
	withConfigCopy(t)

	for _, c := range []struct {
		host, forwardedHost, origin, fetchSite string
		want                                   int
	}{
		{"mtgban.com", "", "https://evil.example", "", http.StatusForbidden},
		{"mtgban.com", "", "https://mtgban.com.evil.example", "", http.StatusForbidden},
		{"mtgban.com", "", "http://mtgban.com", "", http.StatusForbidden},
		{"mtgban.com", "", "null", "", http.StatusForbidden},
		{"mtgban.com", "", "", "cross-site", http.StatusForbidden},
		{"mtgban.com", "", "https://mtgban.com", "same-site", http.StatusForbidden},
		{"mtgban.com", "", "https://mtgban.com", "", http.StatusOK},
		{"mtgban.com", "", "https://mtgban.com", "same-origin", http.StatusOK},
		{"mtg.ban.cards", "", "https://mtg.ban.cards", "", http.StatusOK},
		{"mtg.ban.cards", "", "https://www.mtgban.com", "", http.StatusForbidden},
		{"mtg.ban.cards", "", "https://ban.cards.evil.example", "", http.StatusForbidden},
		// Behind a proxy that names its upstream as Host
		{"backend:8080", "mtgban.com", "https://mtgban.com", "", http.StatusOK},
		{"127.0.0.1:8080", "", "http://127.0.0.1:8080", "", http.StatusOK},
		{"127.0.0.1:8080", "", "http://evil.example", "", http.StatusForbidden},
		{"127.0.0.1:8080", "", "null", "", http.StatusForbidden},
		{"mtgban.com", "", "", "", http.StatusOK},
	} {
		req := postForm("/admin?page=acl", url.Values{"aclTextArea": {"not json"}})
		req.Host = c.host
		req.Header.Set("X-Forwarded-Proto", "https")
		if c.forwardedHost != "" {
			req.Header.Set("X-Forwarded-Host", c.forwardedHost)
		}
		if c.origin != "" {
			req.Header.Set("Origin", c.origin)
		}
		if c.fetchSite != "" {
			req.Header.Set("Sec-Fetch-Site", c.fetchSite)
		}
		rec := httptest.NewRecorder()
		testSite.Admin(rec, req)
		if rec.Code != c.want {
			t.Errorf("host %q origin %q fetch %q: status %d, want %d", c.host, c.origin, c.fetchSite, rec.Code, c.want)
		}
		if c.want == http.StatusOK && !strings.Contains(rec.Body.String(), "Access table not saved") {
			t.Errorf("host %q origin %q: the editor did not read the POST", c.host, c.origin)
		}
	}
}
