package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGenPageNavLabelsThePage(t *testing.T) {
	withSigMode(t, true, false)
	for _, c := range []struct{ target, tab, want string }{
		{"/", "Home", "home"},
		{"/search?q=bolt", "Search", "search"},
		{"/newspaper?page=syp", "Newspaper", "newspaper/syp"},
		{"/offline", "Offline", "offline"},
		{"/newspaper", "Error", ""},
		{"/wp-login.php", "Home", "other"},
	} {
		r := httptest.NewRequest(http.MethodGet, c.target, nil)
		pv := genPageNav(testSite, r, c.tab, "")
		if pv.MetricsPage != c.want {
			t.Errorf("%s as %s: MetricsPage = %q, want %q", c.target, c.tab, pv.MetricsPage, c.want)
		}
		if want := pageLabel(r.URL.Path, r.FormValue("page")); c.tab != "Error" && pv.MetricsPage != want {
			t.Errorf("%s: MetricsPage %q differs from the page hit's label %q", c.target, pv.MetricsPage, want)
		}
	}
	if got := genPageNav(testSite, nil, "Home", "").MetricsPage; got != "" {
		t.Errorf("no request: MetricsPage = %q, want empty", got)
	}
}

func TestGenPageNavSwitchesMetricsWithTheCounter(t *testing.T) {
	withSigMode(t, true, false)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if genPageNav(testSite, r, "Home", "").MetricsOn {
		t.Error("MetricsOn with no counter")
	}
	withFeatureCounter(t)
	if !genPageNav(testSite, r, "Home", "").MetricsOn {
		t.Error("MetricsOn is false with a counter running")
	}
}

// Each base hands the script its flag before loading it, deferred.
func TestEveryBaseLoadsMetrics(t *testing.T) {
	for _, c := range []struct {
		tmpl   string
		mobile bool
	}{{"search.html", false}, {"home.html", false}, {"search.html", true}, {"home.html", true}} {
		pv := PageVars{UserNav: &NavElem{Short: "b"}, Hash: "abc", MetricsVars: MetricsVars{MetricsOn: true, MetricsPage: "search"}}
		page := renderPage(t, c.tmpl, c.mobile, pv)
		flag := strings.Index(page, `window.BAN_METRICS = {on: true, page: "search", build: "abc"};`)
		tag := strings.Index(page, `<script type="text/javascript" src="/js/metrics.js?hash=abc" defer></script>`)
		if flag < 0 || tag < 0 || flag > tag {
			t.Errorf("%s (mobile=%v): flag at %d, script at %d", c.tmpl, c.mobile, flag, tag)
		}
		if strings.Count(page, `src="/js/metrics.js?`) != 1 {
			t.Errorf("%s (mobile=%v): metrics.js is not loaded exactly once", c.tmpl, c.mobile)
		}
		pv.MetricsOn = false
		if off := renderPage(t, c.tmpl, c.mobile, pv); !strings.Contains(off, `window.BAN_METRICS = {on: false, page: "search", build: "abc"};`) {
			t.Errorf("%s (mobile=%v): the switch does not render off", c.tmpl, c.mobile)
		}
	}
}

// The label reaches the script through JS string escaping, never raw.
func TestMetricsPageIsEscapedInTheScript(t *testing.T) {
	const label = `a"b</script><b>`
	u := func(hex string) string { return `\` + "u00" + hex }
	want := `window.BAN_METRICS = {on: true, page: "a` + u("22") + "b" + u("3c") + `\/script` + u("3e") + u("3c") + "b" + u("3e") + `", build: "abc"};`
	for _, c := range []struct {
		tmpl   string
		mobile bool
	}{{"search.html", false}, {"home.html", false}, {"search.html", true}} {
		pv := PageVars{UserNav: &NavElem{Short: "b"}, Hash: "abc", MetricsVars: MetricsVars{MetricsOn: true, MetricsPage: label}}
		page := renderPage(t, c.tmpl, c.mobile, pv)
		if strings.Contains(page, label) {
			t.Errorf("%s (mobile=%v): the label is printed unescaped", c.tmpl, c.mobile)
		}
		if !strings.Contains(page, want) {
			t.Errorf("%s (mobile=%v): want %s", c.tmpl, c.mobile, want)
		}
	}
}

// No load is reported for a page that shows an error or sits in the chart's iframe.
func TestMetricsPageIsEmptyWhereNoPageWasShown(t *testing.T) {
	const empty = `window.BAN_METRICS = {on: true, page: "", build: "abc"};`
	const home = `window.BAN_METRICS = {on: true, page: "home", build: "abc"};`
	base := PageVars{UserNav: &NavElem{Short: "b"}, Hash: "abc", MetricsVars: MetricsVars{MetricsOn: true, MetricsPage: "home"}}
	withError, inModal := base, base
	withError.ErrorMessage = "Your session has expired"
	inModal.ModalMode = true
	for _, c := range []struct {
		name, tmpl string
		mobile     bool
		pv         PageVars
		want       string
	}{
		{"an error on base.html", "search.html", false, withError, empty},
		{"an error on the phone base", "search.html", true, withError, empty},
		{"an error on the landing page", "home.html", false, withError, empty},
		{"the landing page", "home.html", false, base, home},
		{"the iframe on base.html", "search.html", false, inModal, empty},
		{"the iframe on the landing page", "home.html", false, inModal, empty},
	} {
		if page := renderPage(t, c.tmpl, c.mobile, c.pv); !strings.Contains(page, c.want) {
			t.Errorf("%s: want %s", c.name, c.want)
		}
	}
}

// The shell is fetched with no cookies and still carries the instance's switch.
func TestOfflineShellCarriesTheMetricsFlag(t *testing.T) {
	withSigMode(t, true, false)
	withFeatureCounter(t)
	for _, mobile := range []bool{false, true} {
		r := httptest.NewRequest(http.MethodGet, "/offline", nil)
		if mobile {
			r.AddCookie(&http.Cookie{Name: "MobileView", Value: "true"})
		}
		w := httptest.NewRecorder()
		testSite.OfflinePage(w, r)
		body := w.Body.String()
		if !strings.Contains(body, `window.BAN_METRICS = {on: true, page: "offline", build: "`) || !strings.Contains(body, `src="/js/metrics.js?`) {
			t.Errorf("mobile=%v: the offline shell does not carry the metrics flag and script", mobile)
		}
	}
}
