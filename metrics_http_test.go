package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/observability"
)

// The price routes are labelled by the function the gateway shares.
func TestPriceRoutesTakeTheirLabelFromAPIFamily(t *testing.T) {
	for _, pattern := range []string{
		"/api/mtgban/search/", "/api/mtgban/", "/api/v2/search/", "/api/v2/history/",
		"/api/v2/newspaper/", "/api/v2/", "/api/load/", "/api/load/datastore",
	} {
		want := observability.APIFamily(pattern)
		if want == "other" {
			t.Fatalf("APIFamily does not know %s", pattern)
		}
		if got := routeLabel(pattern, pattern+"anything"); got != want {
			t.Errorf("routeLabel(%q) = %q, want %q", pattern, got, want)
		}
	}
	route := metricValidators(nil).Route
	for _, family := range observability.APIFamilies() {
		if !route(family) {
			t.Errorf("the Route check refuses the family %q", family)
		}
	}
}

func TestDurationBucket(t *testing.T) {
	for _, c := range []struct {
		d    time.Duration
		want string
	}{
		{-time.Second, "<50ms"},
		{0, "<50ms"},
		{50*time.Millisecond - 1, "<50ms"},
		{50 * time.Millisecond, "<200ms"},
		{200*time.Millisecond - 1, "<200ms"},
		{200 * time.Millisecond, "<1s"},
		{time.Second - 1, "<1s"},
		{time.Second, "<5s"},
		{5*time.Second - 1, "<5s"},
		{5 * time.Second, "5s+"},
		{10 * time.Minute, "5s+"},
	} {
		if got := durationBucket(c.d); got != c.want {
			t.Errorf("durationBucket(%v) = %q, want %q", c.d, got, c.want)
		}
	}
	// Every bucket is a value the registry allows for http.duration.
	n, _ := observability.Lookup("http.duration")
	for _, d := range []time.Duration{0, 50 * time.Millisecond, 200 * time.Millisecond, time.Second, 5 * time.Second} {
		if !slices.Contains(n.Enum, durationBucket(d)) {
			t.Errorf("http.duration does not allow %q", durationBucket(d))
		}
	}
}

// An API route's status row carries the dimensions the route set.
func TestStatusRowsCarryTheRoutesDims(t *testing.T) {
	rows := withFeatureCounter(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/", func(w http.ResponseWriter, r *http.Request) {
		withMetricDims(r, observability.Dims{Instance: "test", Tier: "api", Device: "api", Signed: true})
	})
	statusWrapper(mux, mux).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v2/retail/all.json", nil))
	got := find(rows.rows(), "http.status")
	if len(got) != 1 {
		t.Fatalf("http.status rows = %+v, want one", got)
	}
	if g := got[0]; g.Scope != "api.v2" || g.Value != "2xx" || g.Device != "api" || g.Tier != "api" || !g.Signed {
		t.Errorf("http.status row = %+v, want api.v2/2xx with the route's dims", g)
	}
}

func TestStatusWrapperCountsStatusAndDuration(t *testing.T) {
	rows := withFeatureCounter(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	h := statusWrapper(mux, mux)

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	got := rows.rows()

	status := map[string]string{}
	for _, row := range find(got, "http.status") {
		if row.N != 1 {
			t.Errorf("http.status row %+v, want n 1", row)
		}
		status[row.Scope] = row.Value
	}
	if len(status) != 2 || status["healthz"] != "5xx" || status["home"] != "2xx" {
		t.Errorf("http.status = %v, want healthz 5xx and home 2xx", status)
	}
	n, _ := observability.Lookup("http.duration")
	scopes := map[string]bool{}
	for _, row := range find(got, "http.duration") {
		if !slices.Contains(n.Enum, row.Value) {
			t.Errorf("http.duration row %+v has a value outside the buckets", row)
		}
		scopes[row.Scope] = true
	}
	if len(scopes) != 2 || !scopes["healthz"] || !scopes["home"] {
		t.Errorf("http.duration scopes = %v, want healthz and home", scopes)
	}
	if rejected := find(got, "metrics.rejected"); len(rejected) != 0 {
		t.Errorf("metrics.rejected rows = %+v, want none", rejected)
	}
}

// A response that writes nothing is a 200; an informational status is not the answer.
func TestStatusWrapperClassesUnwrittenAndInformational(t *testing.T) {
	rows := withFeatureCounter(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusEarlyHints)
		w.WriteHeader(http.StatusNotFound)
	})
	h := statusWrapper(mux, mux)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth", nil))
	got := rows.rows()
	status := map[string]string{}
	for _, row := range find(got, "http.status") {
		status[row.Scope] = row.Value
	}
	if len(status) != 2 || status["healthz"] != "2xx" || status["auth"] != "4xx" {
		t.Errorf("http.status = %v, want healthz 2xx and auth 4xx", status)
	}
	if rejected := find(got, "metrics.rejected"); len(rejected) != 0 {
		t.Errorf("metrics.rejected rows = %+v, want none", rejected)
	}
}

func TestUnknownPathsShareOneLabel(t *testing.T) {
	rows := withFeatureCounter(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/known/", func(http.ResponseWriter, *http.Request) {})
	h := statusWrapper(mux, mux)
	for i := range 500 {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, fmt.Sprintf("/known/%d", i), nil))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, fmt.Sprintf("/debug/x%d", i), nil))
	}
	scopes := map[string]int64{}
	for _, row := range find(rows.rows(), "http.status") {
		scopes[row.Scope] += row.N
	}
	if len(scopes) != 2 || scopes["other"] != 500 || scopes["debug"] != 500 {
		t.Errorf("http.status scopes = %v, want other and debug with 500 each", scopes)
	}
}

func TestRouteLabel(t *testing.T) {
	for _, c := range []struct{ pattern, path, want string }{
		{"/healthz", "/healthz", "healthz"},
		{"/css/", "/css/main.css", "static"},
		{"/api/v2/history/", "/api/v2/history/abc", "api.v2.history"},
		{"/api/mtgban/search/", "/api/mtgban/search/retail/lightning bolt", "api.v1.search"},
		{"/api/suggest", "/api/suggest", "api.suggest"},
		{"", "/debug/pprof/heap", "debug"},
		{"/never-registered", "/never-registered", "other"},
		{"", "/anything", "other"},
		{"/", "/", "home"},
		{"/", "/wp-login.php", "other"},
		{"/data/", "/data/chart/abc", "data.chart"},
		{"/data/", "/data/prices/", "data.prices"},
		{"/data/", "/data/nope", "data"},
		{"/data/", "/data/chart", "data"},
		{"/search", "/search", "search"},
		{"/search/shared", "/search/shared", "search/shared"},
		{"/newspaper?page=syp", "/newspaper", "newspaper"},
		{"/sets", "/sets", "sets"},
		{"/api-plans", "/api-plans", "api-plans"},
		{"/api-trial", "/api-trial", "api-trial"},
		{"/search/settings-values", "/search/settings-values", "settings.values"},
		{"/arbit/settings-values", "/arbit/settings-values", "settings.values"},
		{"/screener/settings-values", "/screener/settings-values", "other"}, // no settings tab
		{"/upload/handoff", "/upload/handoff", "upload/handoff"},
	} {
		if got := routeLabel(c.pattern, c.path); got != c.want {
			t.Errorf("routeLabel(%q, %q) = %q, want %q", c.pattern, c.path, got, c.want)
		}
	}
}

func TestStatusWriterKeepsReadFromAndUnwrap(t *testing.T) {
	rows := withFeatureCounter(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/css/", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := w.(io.ReaderFrom); !ok {
			t.Error("the wrapped writer is not an io.ReaderFrom")
		}
		// Hidden behind a bare Reader, its WriteTo cannot take over from w's ReadFrom.
		if _, err := io.Copy(w, struct{ io.Reader }{strings.NewReader("x")}); err != nil {
			t.Errorf("io.Copy through the wrapped writer: %v", err)
		}
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("Flush through the wrapped writer: %v", err)
		}
	})
	rec := httptest.NewRecorder()
	statusWrapper(mux, mux).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/css/main.css", nil))
	if !rec.Flushed {
		t.Error("the flush did not reach the recorder")
	}
	if rec.Body.String() != "x" {
		t.Errorf("body = %q, want x", rec.Body.String())
	}
	if got := find(rows.rows(), "http.status"); len(got) != 1 || got[0].Value != "2xx" {
		t.Errorf("http.status rows = %+v, want one 2xx", got)
	}
}

// A panic is counted as a server error and goes on to the caller unchanged.
func TestStatusWrapperCountsAPanic(t *testing.T) {
	rows := withFeatureCounter(t)
	boom := errors.New("boom")
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(http.ResponseWriter, *http.Request) { panic(boom) })
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		statusWrapper(mux, mux).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
	}()
	if recovered != boom {
		t.Errorf("recovered %v, want the handler's own panic value", recovered)
	}
	got := rows.rows()
	if status := find(got, "http.status"); len(status) != 1 || status[0].Scope != "healthz" || status[0].Value != "5xx" {
		t.Errorf("http.status rows = %+v, want one healthz 5xx", status)
	}
	if duration := find(got, "http.duration"); len(duration) != 1 {
		t.Errorf("http.duration rows = %+v, want one", duration)
	}
}

// With no counter the handler gets the server's own writer.
func TestStatusWrapperWithNoCounterPassesThrough(t *testing.T) {
	prev := FeatureCounter
	t.Cleanup(func() { FeatureCounter = prev })
	FeatureCounter = nil

	rec := httptest.NewRecorder()
	var got http.ResponseWriter
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { got = w })
	statusWrapper(mux, mux).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if got != http.ResponseWriter(rec) {
		t.Errorf("the handler got %T, want the original recorder", got)
	}
}

// registration is one pattern a root file registers on http or a mux.
type registration struct {
	at      string // file:line
	pattern string // "" where the pattern is not a literal
	onHTTP  bool
}

// literalString is e's value when e is a string literal or a concatenation of them.
func literalString(e ast.Expr) (string, bool) {
	switch e := e.(type) {
	case *ast.ParenExpr:
		return literalString(e.X)
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(e.Value)
		return s, err == nil
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		x, ok := literalString(e.X)
		if !ok {
			return "", false
		}
		y, ok := literalString(e.Y)
		return x + y, ok
	}
	return "", false
}

// registrations lists every http.Handle, http.HandleFunc, mux.Handle and
// mux.HandleFunc in root's own non-test files, but mountNav's, which
// registers the nav registry's links.
func registrations(t *testing.T, root string) []registration {
	t.Helper()
	fset := token.NewFileSet()
	var out []registration
	for _, path := range rootGoFiles(t, root) {
		for _, decl := range parseGoFile(t, fset, path).Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == "mountNav" {
				continue
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || (sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc") {
					return true
				}
				recv, ok := sel.X.(*ast.Ident)
				if !ok || (recv.Name != "http" && recv.Name != "mux") {
					return true
				}
				file, line := relPos(fset, root, call.Pos())
				pattern, _ := literalString(call.Args[0])
				out = append(out, registration{at: file + ":" + strconv.Itoa(line), pattern: pattern, onHTTP: recv.Name == "http"})
				return true
			})
		}
	}
	return out
}

func TestRegistrationsSeesEveryForm(t *testing.T) {
	root := t.TempDir()
	src := strings.Join([]string{
		"package main",
		"func routes() {",
		`	http.Handle("/a", h)`,
		`	http.HandleFunc("/b/"+"c", f)`,
		`	mux.Handle("/d/", h)`,
		`	mux.HandleFunc(prefix+"/e", f)`,
		`	nav.Handle(s, w, r)`,
		"}",
		"func (s *site) mountNav(mux *http.ServeMux, nav *NavElem) {",
		"	mux.Handle(nav.Link, h)",
		"}",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(root, "routes.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	want := []registration{
		{at: "routes.go:3", pattern: "/a", onHTTP: true},
		{at: "routes.go:4", pattern: "/b/c", onHTTP: true},
		{at: "routes.go:5", pattern: "/d/"},
		{at: "routes.go:6"},
	}
	if got := registrations(t, root); !slices.Equal(got, want) {
		t.Errorf("registrations = %+v, want %+v", got, want)
	}
}

// Every pattern the site registers has a label. Patterns are read from the
// source so a new http.Handle cannot be forgotten.
func TestEveryRegisteredRouteHasALabel(t *testing.T) {
	route := metricValidators(nil).Route
	check := func(where, pattern, label string) {
		if label == "other" {
			t.Errorf("%s registers %s with no route label", where, pattern)
		} else if !route(label) {
			t.Errorf("the Route check refuses %q, the label of %s", label, pattern)
		}
	}
	found := registrations(t, ".")
	// A pattern on an inner mux is labelled by the outer pattern that reaches it.
	outer := http.NewServeMux()
	for _, reg := range found {
		if reg.onHTTP && reg.pattern != "" {
			outer.Handle(reg.pattern, http.NotFoundHandler())
		}
	}
	for _, reg := range found {
		if reg.pattern == "" {
			t.Errorf("%s registers a pattern that is not a literal", reg.at)
			continue
		}
		_, matched := outer.Handler(httptest.NewRequest(http.MethodGet, reg.pattern, nil))
		check(reg.at, reg.pattern, routeLabel(matched, reg.pattern))
	}
	if len(found) < 50 {
		t.Errorf("found %d registrations; the scan has lost them", len(found))
	}
	// Nav pages are registered from the registry, not literals.
	for _, nav := range ExtraNavs {
		check("nav "+nav.Name, nav.Link, routeLabel(nav.Link, nav.Link))
		for _, sub := range nav.SubPages {
			check("nav "+nav.Name, sub.Link, routeLabel(sub.Link, sub.Link))
		}
		if nav.SettingsTab != "" {
			link := nav.Link + "/settings-values"
			check("nav "+nav.Name, link, routeLabel(link, link))
		}
	}
	// What routeLabel answers past the pattern table.
	for _, path := range []string{"/debug/pprof/", "/data/chart/x", "/data/prices/x", "/data/x"} {
		pattern := "/data/"
		if strings.HasPrefix(path, "/debug") {
			pattern = ""
		}
		if label := routeLabel(pattern, path); !route(label) {
			t.Errorf("the Route check refuses %q, the label of %s", label, path)
		}
	}
	if route("other") || route("wp-login.php") || route("") {
		t.Error("the Route check accepts only labels routeLabel returns")
	}
}
