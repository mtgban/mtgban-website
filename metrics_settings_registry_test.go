package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/observability"
)

// cookieArg is where a helper takes its cookie name, and whether it must be a literal.
type cookieArg struct {
	index    int
	required bool
	exempt   []string // functions that pass a name through
}

// readCookieExempt are the plain functions that pass a cookie name through to readCookie.
var readCookieExempt = []string{"readSetFlag", "getUploadSetting", "tickedStores", "chartInitialRange", "readSearchRun", "SettingsValues", "arbit"}

var cookieHelpers = map[string]cookieArg{
	"setForeverCookie":   {index: 2, required: true, exempt: []string{"readSetFlag"}},
	"readSetFlag":        {index: 3, required: true},
	"readCookie":         {index: 1, required: true, exempt: readCookieExempt},
	"getUploadSetting":   {index: 2, required: true, exempt: []string{"getUploadSetting", "uploadFloatSetting", "uploadIntSetting"}},
	"uploadFloatSetting": {index: 2, required: true, exempt: []string{"getUploadSetting", "uploadFloatSetting", "uploadIntSetting"}},
	"uploadIntSetting":   {index: 2, required: true, exempt: []string{"getUploadSetting", "uploadFloatSetting", "uploadIntSetting"}},
	"tickedStores":       {index: 1, required: true, exempt: []string{"tickedStores"}},
	"setCookie":          {index: 2, required: true, exempt: []string{"setForeverCookie"}},
}

// Methods that read a cookie through a variable, each with the names it reads.
var methodCookieReaders = map[string]string{
	"site.Global":         "GlobalVendorsList, held in a local",
	"site.scraperCompare": "ArbitFilters or GlobalFilters, from arbitSavedCookie",
}

// Cookies the server names that hold no reader choice, each with why.
var notSettingCookies = map[string]string{
	"BAN_SIG":     "the signed access cookie",
	"MTGBAN":      "the legacy signed access cookie",
	"BAN_SESSION": "the Patreon session handle",
	"BAN_HANDOFF": "the API handoff token",
}

// stringLit returns the value of a string literal.
func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}

// cookieNameOf reads a string literal or a package constant holding one.
func cookieNameOf(e ast.Expr, consts map[string]string) (string, bool) {
	if id, ok := e.(*ast.Ident); ok {
		s, ok := consts[id.Name]
		return s, ok
	}
	return stringLit(e)
}

// serverCookieNames walks the root package's non-test files for cookie names.
func serverCookieNames(t *testing.T) (map[string]string, []string) {
	t.Helper()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	consts := map[string]string{}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, id := range vs.Names {
					if i < len(vs.Values) {
						if s, ok := stringLit(vs.Values[i]); ok {
							consts[id.Name] = s
						}
					}
				}
			}
		}
	}
	names := map[string]string{}
	var bad []string
	for _, f := range files {
		for _, decl := range f.Decls {
			enclosing := ""
			if fn, ok := decl.(*ast.FuncDecl); ok {
				enclosing = fn.Name.Name
				if fn.Recv != nil {
					enclosing = recvName(fn.Recv) + "." + enclosing
				}
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					collectCookieCall(fset, x, enclosing, consts, names, &bad)
				case *ast.CompositeLit:
					sel, ok := x.Type.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "Cookie" {
						return true
					}
					if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "http" {
						return true
					}
					for _, el := range x.Elts {
						kv, ok := el.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						if key, ok := kv.Key.(*ast.Ident); !ok || key.Name != "Name" {
							continue
						}
						if name, ok := cookieNameOf(kv.Value, consts); ok {
							names[name] = fset.Position(kv.Pos()).String()
						}
					}
				}
				return true
			})
		}
	}
	return names, bad
}

// recvName is a method receiver's type name, pointer or not.
func recvName(fl *ast.FieldList) string {
	e := fl.List[0].Type
	if star, ok := e.(*ast.StarExpr); ok {
		e = star.X
	}
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

func collectCookieCall(fset *token.FileSet, call *ast.CallExpr, enclosing string, consts, names map[string]string, bad *[]string) {
	var arg ast.Expr
	required := false
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		h, ok := cookieHelpers[fun.Name]
		if !ok || len(call.Args) <= h.index {
			return
		}
		arg = call.Args[h.index]
		method := fun.Name == "readCookie" && methodCookieReaders[enclosing] != ""
		required = h.required && !slices.Contains(h.exempt, enclosing) && !method
	case *ast.SelectorExpr:
		if fun.Sel.Name != "Cookie" || len(call.Args) != 1 {
			return
		}
		arg = call.Args[0]
	default:
		return
	}
	pos := fset.Position(arg.Pos()).String()
	if name, ok := cookieNameOf(arg, consts); ok {
		names[name] = pos
	} else if required {
		*bad = append(*bad, pos)
	}
}

// knownSetting is a registered name, a mirror, or a cookie that packs registered flags.
func knownSetting(name string) bool {
	if _, ok := observability.LookupSetting(name); ok {
		return true
	}
	for _, s := range observability.Settings() {
		if s.Mirror == name || strings.HasPrefix(s.Name, name+".") {
			return true
		}
	}
	return false
}

// Every cookie the server sets as a preference, or reads by name, is in the
// settings registry.
func TestEveryServerCookieIsARegisteredSetting(t *testing.T) {
	names, bad := serverCookieNames(t)
	for _, pos := range bad {
		t.Errorf("%s: a cookie name the test cannot read; pass a string literal", pos)
	}
	if len(names) < 30 {
		t.Fatalf("found %d cookie names, the walk is missing calls", len(names))
	}
	for name, pos := range names {
		if !knownSetting(name) && notSettingCookies[name] == "" {
			t.Errorf("%s: cookie %q is not in observability.Settings()", pos, name)
		}
	}
	for name := range notSettingCookies {
		if names[name] == "" || knownSetting(name) {
			t.Errorf("%s is listed as not a setting but the server does not name it, or it is registered", name)
		}
	}
}

// A cookie the server writes by name on a run, changed or not, is not snapshotted.
func TestCookiesTheServerWritesAreNotSnapshotted(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	found := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "setForeverCookie" || len(call.Args) < 3 {
				return true
			}
			name, ok := stringLit(call.Args[2])
			if !ok {
				return true
			}
			found++
			if observability.IsSetting(name) {
				t.Errorf("%s: %s is written on every run but snapshotted as a preference", fset.Position(call.Pos()), name)
			}
			return true
		})
	}
	if found == 0 {
		t.Fatal("found no setForeverCookie call with a literal name")
	}
}

// Cookies written at / whatever page writes them, each with where.
var rootWrittenCookies = map[string]string{
	"ArbitFilters":      "js/arbit-filters.js writes it at /",
	"GlobalFilters":     "js/arbit-filters.js writes it at /",
	"ArbitFiltersOpen":  "js/arbit-filters.js writes it at /",
	"MobileView":        "mobile.go sets Path /",
	"MobileChartHidden": "js/mobile-chart.js writes path=/",
}

// serverStrings is every string literal in the root package's non-test files.
func serverStrings(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	out := map[string]bool{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok {
				if s, ok := stringLit(lit); ok {
					out[s] = true
				}
			}
			return true
		})
	}
	return out
}

// A cookie setting's Path is where its cookie is written, so it is read against that page's readers.
func TestSettingPathsMatchTheCookiePaths(t *testing.T) {
	known := serverStrings(t)
	page := httptest.NewRequest(http.MethodGet, "/upload", nil)
	for _, s := range observability.Settings() {
		if s.Storage != "cookie" && s.Storage != "both" {
			continue
		}
		base, _, _ := strings.Cut(s.Name, ".")
		if s.Storage == "both" && !known[base] && s.Mirror != "" {
			if !known[s.Mirror] {
				t.Errorf("%s: neither %s nor %s is a cookie the server names", s.Name, base, s.Mirror)
				continue
			}
			base = s.Mirror
		}
		_, listed := rootWrittenCookies[base]
		root := listed || cookiePath(page, base) == "/"
		want := "root"
		if !root {
			want = "the page it is written on"
		}
		if (s.Path == "root") != root {
			t.Errorf("%s: registered at %s, cookie %s is written at %s", s.Name, s.Path, base, want)
		}
	}
}

// The defaults the registry records are the ones the Go readers apply.
func TestSettingDefaultsMatchTheCode(t *testing.T) {
	def := func(name string) string {
		s, ok := observability.LookupSetting(name)
		if !ok {
			t.Fatalf("%s is not registered", name)
		}
		return s.Default
	}
	for _, flag := range []string{"lowval", "highval", "lowvalabs", "highvalabs", "minmargin", "nocond", "noprice", "customperc", "unpack", "noresults"} {
		want := "off"
		if slices.Contains(defaultUploadOpts, flag) {
			want = "on"
		}
		if got := def("UploadOptimizerOpts." + flag); got != want {
			t.Errorf("UploadOptimizerOpts.%s defaults to %s in the registry, %s in defaultUploadOpts", flag, got, want)
		}
	}
	for name, want := range map[string]float64{
		"UploadPercSpread":    MinLowValueSpread,
		"UploadPercSpreadMax": MaxHighValueSpread,
		"UploadMinVal":        MinLowValueAbs,
		"UploadMaxVal":        MaxHighValueAbs,
		"UploadCustomPercMax": VisualPercSpread,
		"UploadMargin":        defaultUploadMargin,
		"chartDateRange":      defaultChartRange,
		"chartMultiDateRange": 0,
	} {
		got, err := strconv.ParseFloat(def(name), 64)
		if err != nil || got != want {
			t.Errorf("%s defaults to %q in the registry, %v in the code", name, def(name), want)
		}
	}
	if def("SearchSealedContents") != ContentsAll {
		t.Errorf("SearchSealedContents defaults to %q, sealedContentsPref to %q", def("SearchSealedContents"), ContentsAll)
	}
	if def("UploadAltPrice") != UploadIndexKeys[0] || def("UploadAltPrice") != UploadIndexComparePriceList[0] {
		t.Errorf("UploadAltPrice defaults to %q, the code to %q", def("UploadAltPrice"), UploadIndexKeys[0])
	}
}

// A setting's server fact is a name the registry knows.
func TestSettingFactsAreRegistered(t *testing.T) {
	v := metricValidators(nil)
	facts := 0
	for _, s := range observability.Settings() {
		if s.Fact == "" {
			if s.FactScope != "" || s.FactValue != "" {
				t.Errorf("%s has a fact scope or value and no fact", s.Name)
			}
			continue
		}
		facts++
		n, ok := observability.Lookup(s.Fact)
		if !ok || n.Family != observability.FamilyServer {
			t.Errorf("%s: fact %s is not a registered server name", s.Name, s.Fact)
			continue
		}
		scope := s.FactScope
		if scope != "" {
			if n.Scope != observability.ScopeEnum || !slices.Contains(n.Scopes, scope) {
				t.Errorf("%s: %s has no scope %q", s.Name, s.Fact, scope)
				continue
			}
		} else if n.Scope != observability.ScopeNone && len(n.Scopes) > 0 {
			scope = n.Scopes[0]
		}
		var values []string
		switch {
		case s.FactValue != "":
			values = []string{s.FactValue}
		case s.Kind == "enum":
			for _, e := range s.Enum {
				if e != s.Default {
					values = append(values, e)
				}
			}
		}
		for _, value := range values {
			if _, _, ok := n.Check(scope, value, v); !ok {
				t.Errorf("%s: %s refuses scope %q value %q", s.Name, s.Fact, scope, value)
			}
		}
	}
	if facts == 0 {
		t.Fatal("no setting names a fact")
	}
}
