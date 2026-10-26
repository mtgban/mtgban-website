package main

import (
	"encoding/base64"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/simplecloud"
)

func TestAdminToolsLinkTheGatewayAdmin(t *testing.T) {
	savedDev, savedSig, savedCfg := DevMode, SigCheck, Config().APIGateway
	t.Cleanup(func() { DevMode, SigCheck, Config().APIGateway = savedDev, savedSig, savedCfg })
	DevMode, SigCheck = true, false
	Config().APIGateway = APIGatewayConfig{URL: "https://api.example", Games: []mtgmatcher.Game{"magic"}}
	req := httptest.NewRequest(http.MethodGet, "/admin?page=tools", nil)
	req.Host = "mtgban.com"
	rec := httptest.NewRecorder()
	testSite.Admin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `href="https://api.example/admin"`) {
		t.Error("tools page does not link the gateway admin")
	}
	if !strings.Contains(body, `value="demokey"`) {
		t.Error("tools page does not offer the demo key")
	}
}

func TestAdminDemoKeyExpiresForTheDemoUser(t *testing.T) {
	withSigMode(t, true, false)

	withAPIUserSecret(t, DefaultAPIDemoUser, goldenSecret)

	// A blank user is the demo user, from the button and the form alike.
	for _, form := range []url.Values{{"tool": {"demokey"}}, {"tool": {"newKey"}, "user": {""}, "duration": {"30"}}} {
		tool := form.Get("tool")
		rec := httptest.NewRecorder()
		testSite.Admin(rec, adminRequest(http.MethodPost, form))
		key := mintedKey(t, rec)
		blob, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			t.Fatalf("%s did not mint a key: %q", tool, key)
		}
		claims, err := url.ParseQuery(string(blob))
		if err != nil {
			t.Fatal(err)
		}
		if claims.Get("Expires") == "" {
			t.Errorf("the demo key is permanent: %v", claims)
		}
		if !strings.Contains(string(blob), url.QueryEscape(DefaultAPIDemoUser)) {
			t.Errorf("the demo key is not the demo user's: %v", claims)
		}
	}
}

func TestAdminNewKeyDefaultsABlankDuration(t *testing.T) {
	withSigMode(t, true, false)

	const user = "ops@example.com"
	withAPIUserSecret(t, user, goldenSecret)

	rec := httptest.NewRecorder()
	testSite.Admin(rec, adminRequest(http.MethodPost, url.Values{"tool": {"newKey"}, "user": {user}, "duration": {""}}))
	key := mintedKey(t, rec)
	blob, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		t.Fatalf("minted key is not base64: %v", err)
	}
	claims, err := url.ParseQuery(string(blob))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Get("Expires") == "" {
		t.Errorf("a blank duration minted a permanent key: %v", claims)
	}
}

// mintedKey is the API key a newKey or demokey POST answered with. It is
// on the page itself, never in a redirect's URL, and the page is not cached.
func mintedKey(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Code != http.StatusOK || rec.Header().Get("Location") != "" {
		t.Fatalf("answered %d to %q, want the page", rec.Code, rec.Header().Get("Location"))
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control %q, want no-store", cc)
	}
	m := regexp.MustCompile(`New key: <input value="([^"]*)"`).FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatal("no key on the page")
	}
	return html.UnescapeString(m[1])
}

// adminRequest is method to the admin page from this site, with form in a
// POST's body or a GET's query string.
func adminRequest(method string, form url.Values) *http.Request {
	var req *http.Request
	if method == http.MethodGet {
		req = httptest.NewRequest(method, "/admin?"+form.Encode(), nil)
	} else {
		req = httptest.NewRequest(method, "/admin", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Host = "mtgban.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	return req
}

// withInertAdminTools gives the admin tools a site and a config on which
// running each one leaves a message and changes nothing: every file they
// read is missing, a stash is already running, no tcgcsv ingest is set up,
// and a restart is counted rather than made. The count is returned.
func withInertAdminTools(t *testing.T) (*site, *atomic.Int32) {
	t.Helper()
	withSigMode(t, true, false)
	withAPIUserSecret(t, DefaultAPIDemoUser, goldenSecret)
	withAPIUserSecret(t, "ops@example.com", goldenSecret)

	dir := t.TempDir()
	Config().Game = "lorcana"
	Config().sourcePath = filepath.Join(dir, "config.json")
	Config().DatastorePath = filepath.Join(dir, "datastore.json.xz")
	Config().TimeseriesConfig.CheckpointsPath = filepath.Join(dir, "checkpoints.json")

	savedConfigBucket, savedDataBucket, savedTCGCSV := ConfigBucket, DataBucket, TCGCSVService
	savedStashing, savedRestart := stashingInProgress.Load(), restartServer
	restarts := &atomic.Int32{}
	ConfigBucket, DataBucket, TCGCSVService = &simplecloud.FileBucket{}, &simplecloud.FileBucket{}, nil
	stashingInProgress.Store(true)
	restartServer = func() { restarts.Add(1) }

	s := newSite()
	t.Cleanup(func() {
		for deadline := time.Now().Add(10 * time.Second); s.reloads.Status().Running && time.Now().Before(deadline); {
			time.Sleep(10 * time.Millisecond)
		}
		ConfigBucket, DataBucket, TCGCSVService = savedConfigBucket, savedDataBucket, savedTCGCSV
		stashingInProgress.Store(savedStashing)
		restartServer = savedRestart
	})
	return s, restarts
}

// Every admin action that changes state - a restart, a reload, a dispatch,
// a stash, an ingest, a new key - runs only from a same-site POST's body, so
// a link an admin is sent to cannot start one.
func TestAdminActionsRunOnlyFromASameSitePost(t *testing.T) {
	s, restarts := withInertAdminTools(t)

	actions := []struct {
		form      url.Values
		key, want string
	}{
		{url.Values{"tool": {"datastore"}}, "msg", "Reloading the datastore"},
		{url.Values{"tool": {"config"}}, "msg", "Failed to reload config"},
		{url.Values{"tool": {"checkpoints"}}, "msg", "checkpoints"},
		{url.Values{"tool": {"snapshot"}}, "msg", "Stashing is already in progress"},
		{url.Values{"tool": {"tcgcsv"}}, "msg", "Ingesting latest TCGCSV prices"},
		{url.Values{"tool": {"server"}}, "msg", "Restarting the server"},
		{url.Values{"tool": {"newKey"}, "user": {"ops@example.com"}, "duration": {"30"}}, "", "New key: "},
		{url.Values{"tool": {"demokey"}}, "", "New key: "},
		{url.Values{"refresh": {"zz-unknown"}}, "msg", "zz-unknown not found"},
		{url.Values{"reload": {"zz-unknown"}, "table": {"retail"}, "tag": {"ZZ"}}, "msg", "reload of zz-unknown error"},
	}

	for _, action := range actions {
		name := action.form.Encode()

		rec := httptest.NewRecorder()
		s.Admin(rec, adminRequest(http.MethodGet, action.form))
		if rec.Code != http.StatusOK || rec.Header().Get("Location") != "" {
			t.Errorf("%s: a GET answered %d to %q, want the page", name, rec.Code, rec.Header().Get("Location"))
		}

		req := httptest.NewRequest(http.MethodPost, "/admin?"+action.form.Encode(), strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Host = "mtgban.com"
		rec = httptest.NewRecorder()
		s.Admin(rec, req)
		if rec.Code != http.StatusOK || rec.Header().Get("Location") != "" {
			t.Errorf("%s: a POST's query string answered %d to %q, want the page", name, rec.Code, rec.Header().Get("Location"))
		}

		req = adminRequest(http.MethodPost, action.form)
		req.Header.Set("Origin", "https://evil.example")
		rec = httptest.NewRecorder()
		s.Admin(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: a cross-site POST answered %d, want 403", name, rec.Code)
		}
	}
	if restarts.Load() != 0 || !s.reloads.Status().StartedAt.IsZero() {
		t.Fatalf("a link restarted the server %d times or reloaded the datastore: %+v", restarts.Load(), s.reloads.Status())
	}

	for _, action := range actions {
		req := adminRequest(http.MethodPost, action.form)
		req.Header.Set("Origin", "https://mtgban.com")
		rec := httptest.NewRecorder()
		s.Admin(rec, req)
		// No key: the result is on the page the POST answers
		if action.key == "" {
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), action.want) {
				t.Errorf("%s: a same-site POST answered %d without %q on the page", action.form.Encode(), rec.Code, action.want)
			}
			continue
		}
		loc, err := url.Parse(rec.Header().Get("Location"))
		if rec.Code != http.StatusFound || err != nil {
			t.Errorf("%s: a same-site POST answered %d to %q, want a redirect", action.form.Encode(), rec.Code, rec.Header().Get("Location"))
			continue
		}
		if !strings.Contains(loc.Query().Get(action.key), action.want) {
			t.Errorf("%s: redirected to %q, want %s to say %q", action.form.Encode(), loc, action.key, action.want)
		}
	}
	for deadline := time.Now().Add(5 * time.Second); restarts.Load() == 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if restarts.Load() != 1 || s.reloads.Status().StartedAt.IsZero() {
		t.Errorf("the POSTs restarted the server %d times, want 1, or did not reload the datastore", restarts.Load())
	}

	// A POST with no Origin at all, as curl sends, is this site's own, and
	// so is one from any host whose Origin names it, a dev box included.
	rec := httptest.NewRecorder()
	s.Admin(rec, adminRequest(http.MethodPost, url.Values{"tool": {"snapshot"}}))
	if rec.Code != http.StatusFound {
		t.Errorf("a POST without an Origin answered %d, want a redirect", rec.Code)
	}
	dev := adminRequest(http.MethodPost, url.Values{"tool": {"snapshot"}})
	dev.Host = "127.0.0.1:8080"
	dev.Header.Set("Origin", "http://127.0.0.1:8080")
	rec = httptest.NewRecorder()
	s.Admin(rec, dev)
	if rec.Code != http.StatusFound {
		t.Errorf("a same-host POST on a dev box answered %d, want a redirect", rec.Code)
	}
	// The browser's own word on where the form came from settles it.
	fetched := adminRequest(http.MethodPost, url.Values{"tool": {"snapshot"}})
	fetched.Header.Set("Sec-Fetch-Site", "cross-site")
	rec = httptest.NewRecorder()
	s.Admin(rec, fetched)
	if rec.Code != http.StatusForbidden {
		t.Errorf("a POST the browser calls cross-site answered %d, want 403", rec.Code)
	}
	// Without it, Origin is read against the public host behind the proxy,
	// scheme included.
	proxied := adminRequest(http.MethodPost, url.Values{"tool": {"snapshot"}})
	proxied.Host = "backend:8080"
	proxied.Header.Set("X-Forwarded-Host", "mtgban.com")
	proxied.Header.Set("X-Forwarded-Proto", "https")
	proxied.Header.Set("Origin", "https://mtgban.com")
	rec = httptest.NewRecorder()
	s.Admin(rec, proxied)
	if rec.Code != http.StatusFound {
		t.Errorf("a same-site POST behind the proxy answered %d, want a redirect", rec.Code)
	}
	plain := adminRequest(http.MethodPost, url.Values{"tool": {"snapshot"}})
	plain.Header.Set("X-Forwarded-Proto", "https")
	plain.Header.Set("Origin", "http://mtgban.com")
	rec = httptest.NewRecorder()
	s.Admin(rec, plain)
	if rec.Code != http.StatusForbidden {
		t.Errorf("a POST from the plain-http page answered %d, want 403", rec.Code)
	}
}

// The views and the invite link change nothing, so a GET still reaches them.
func TestAdminViewsAnswerAGet(t *testing.T) {
	s, _ := withInertAdminTools(t)

	for _, c := range []struct {
		query, want string
	}{
		{"page=tools", `name="tool" value="server"`},
		{"msg=hello+admin", "hello admin"},
		{"logs=zz-unknown", "zz-unknown not found"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/admin?"+c.query, nil)
		req.Host = "mtgban.com"
		rec := httptest.NewRecorder()
		s.Admin(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), c.want) {
			t.Errorf("%s: status %d, want the page with %s", c.query, rec.Code, c.want)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/admin?tool=invite&tier=Free&duration=7", nil)
	req.Host = "mtgban.com"
	rec := httptest.NewRecorder()
	s.Admin(rec, req)
	loc, err := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || err != nil || loc.Query().Get("html") != "invite" || !strings.Contains(loc.Query().Get("msg"), "/?sig=") {
		t.Errorf("an invite GET answered %d to %q, want the invite link", rec.Code, rec.Header().Get("Location"))
	}
}

// The server actions are buttons posting a form, on both layouts, and none
// is a link.
func TestAdminServerActionsPost(t *testing.T) {
	for _, mobile := range []bool{false, true} {
		out := renderPage(t, "admin.html", mobile, PageVars{UserNav: &NavElem{Short: "b"}})
		if strings.Contains(out, `href="?tool=`) {
			t.Errorf("mobile %v: a server action is still a link", mobile)
		}
		for _, tool := range []string{"datastore", "config", "checkpoints", "snapshot", "tcgcsv", "server", "newKey", "demokey"} {
			if !strings.Contains(out, `name="tool" value="`+tool+`"`) {
				t.Errorf("mobile %v: no %s button or field", mobile, tool)
			}
		}
		if strings.Count(out, `method="POST" action="admin"`)+strings.Count(out, `action="admin" method="POST"`) < 3 {
			t.Errorf("mobile %v: the server actions and key forms do not all post", mobile)
		}
	}
}
