package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/observability"
)

// observedName is one name argument a counting call passes.
type observedName struct {
	file    string
	line    int
	name    string
	literal bool
	badHook bool   // an .Observe( call that is neither hook form
	misuse  string // an emitter reached some other way than a call by name
}

// emitterNameArg is the name argument's index in each root-package emitter.
var emitterNameArg = map[string]int{
	"observe":       1,
	"observeScoped": 2,
	"observeStore":  3,
	"observeJob":    2,
	"newFact":       1,
}

// hookNameArg maps an .Observe( hook's argument count to its name's index.
var hookNameArg = map[int]int{4: 2, 3: 1}

// rootGoFiles lists root's own non-test Go files, not its subpackages'.
func rootGoFiles(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && isSourceFile(e.Name()) {
			files = append(files, filepath.Join(root, e.Name()))
		}
	}
	return files
}

func isSourceFile(name string) bool {
	return strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")
}

// hookGoFiles lists the non-test Go files under root's internal/ and userstate/.
func hookGoFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	for _, dir := range []string{"internal", "userstate"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}
			// Skip by entry name: this checkout's absolute path holds .worktrees.
			if d.IsDir() && (d.Name() == ".worktrees" || d.Name() == ".claude") {
				return filepath.SkipDir
			}
			if !d.IsDir() && isSourceFile(d.Name()) {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return files
}

func parseGoFile(t *testing.T, fset *token.FileSet, path string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// relPos is p's file, relative to root, and line.
func relPos(fset *token.FileSet, root string, p token.Pos) (string, int) {
	pos := fset.Position(p)
	rel, err := filepath.Rel(root, pos.Filename)
	if err != nil {
		rel = pos.Filename
	}
	return filepath.ToSlash(rel), pos.Line
}

// nameArg reads call's argument at i as an observedName.
func nameArg(fset *token.FileSet, root string, call *ast.CallExpr, i int) observedName {
	file, line := relPos(fset, root, call.Pos())
	o := observedName{file: file, line: line}
	if i < 0 || i >= len(call.Args) {
		o.badHook = i < 0
		return o
	}
	lit, ok := call.Args[i].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return o
	}
	name, err := strconv.Unquote(lit.Value)
	if err != nil {
		return o
	}
	o.name, o.literal = name, true
	return o
}

// misused is an observedName for an emitter at n reached other than by a call.
func misused(fset *token.FileSet, root string, n ast.Node, what string) observedName {
	file, line := relPos(fset, root, n.Pos())
	return observedName{file: file, line: line, misuse: what}
}

// observedNames collects every name the code under root counts, and every
// emitter it reaches some other way than a call by name.
func observedNames(t *testing.T, root string) []observedName {
	t.Helper()
	fset := token.NewFileSet()
	var out []observedName
	for _, path := range rootGoFiles(t, root) {
		f := parseGoFile(t, fset, path)
		for _, decl := range f.Decls {
			// observeFacts emits names newFact already showed this test.
			if fd, ok := decl.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "observeFacts" {
				continue
			}
			named := map[*ast.Ident]bool{} // called by name, a declaration's name, or a selector's
			if fd, ok := decl.(*ast.FuncDecl); ok {
				named[fd.Name] = true
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.SelectorExpr:
					named[n.Sel] = true
				case *ast.CallExpr:
					if id, ok := n.Fun.(*ast.Ident); ok {
						if i, ok := emitterNameArg[id.Name]; ok {
							named[id] = true
							out = append(out, nameArg(fset, root, n, i))
						}
					}
				case *ast.Ident:
					if _, ok := emitterNameArg[n.Name]; ok && !named[n] {
						out = append(out, misused(fset, root, n, n.Name+" outside a call"))
					}
				}
				return true
			})
		}
	}
	for _, path := range hookGoFiles(t, root) {
		called := map[*ast.SelectorExpr]bool{}
		ast.Inspect(parseGoFile(t, fset, path), func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				sel, ok := n.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				called[sel] = true
				switch sel.Sel.Name {
				case "Observe":
					i, ok := hookNameArg[len(n.Args)]
					if !ok {
						i = -1
					}
					out = append(out, nameArg(fset, root, n, i))
				case "observe":
					out = append(out, misused(fset, root, n, "a lowercase .observe call"))
				}
			case *ast.SelectorExpr:
				if n.Sel.Name == "Observe" && !called[n] {
					out = append(out, misused(fset, root, n, ".Observe outside a call"))
				}
			}
			return true
		})
	}
	return out
}

// counterBypasses lists where root's package reaches FeatureCounter.Add or
// Reject outside metrics.go, past the registry.
func counterBypasses(t *testing.T, root string) []string {
	t.Helper()
	fset := token.NewFileSet()
	var out []string
	for _, path := range rootGoFiles(t, root) {
		if filepath.Base(path) == "metrics.go" {
			continue
		}
		ast.Inspect(parseGoFile(t, fset, path), func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Add" && sel.Sel.Name != "Reject") {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "FeatureCounter" {
				file, line := relPos(fset, root, sel.Pos())
				out = append(out, file+":"+strconv.Itoa(line))
			}
			return true
		})
	}
	return out
}

// isFactType reports whether e is the identifier fact or a pointer to it.
func isFactType(e ast.Expr) bool {
	if star, ok := e.(*ast.StarExpr); ok {
		e = star.X
	}
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "fact"
}

// factLiterals lists the fact literals built outside newFact in root's package.
func factLiterals(t *testing.T, root string) []string {
	t.Helper()
	fset := token.NewFileSet()
	var out []string
	report := func(n ast.Node) {
		pos := fset.Position(n.Pos())
		rel, err := filepath.Rel(root, pos.Filename)
		if err != nil {
			rel = pos.Filename
		}
		out = append(out, filepath.ToSlash(rel)+":"+strconv.Itoa(pos.Line))
	}
	for _, path := range rootGoFiles(t, root) {
		f := parseGoFile(t, fset, path)
		for _, decl := range f.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "newFact" {
				continue
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				if isFactType(lit.Type) {
					report(lit)
					return true
				}
				// An element of a fact slice, array or map may leave its type out.
				var elem ast.Expr
				switch typ := lit.Type.(type) {
				case *ast.ArrayType:
					elem = typ.Elt
				case *ast.MapType:
					elem = typ.Value
				}
				if elem == nil || !isFactType(elem) {
					return true
				}
				for _, el := range lit.Elts {
					if kv, ok := el.(*ast.KeyValueExpr); ok {
						el = kv.Value
					}
					if inner, ok := el.(*ast.CompositeLit); ok && inner.Type == nil {
						report(inner)
					}
				}
				return true
			})
		}
	}
	return out
}

// Every name passed to observe, observeScoped, observeStore, observeJob or
// newFact, or to an Observe hook, is a string literal the registry knows.
func TestEveryObservedNameIsRegistered(t *testing.T) {
	for _, o := range observedNames(t, ".") {
		switch {
		case o.misuse != "":
			t.Errorf("%s:%d: %s; call an emitter by name", o.file, o.line, o.misuse)
		case o.badHook:
			t.Errorf("%s:%d: .Observe call is neither hook form", o.file, o.line)
		case !o.literal:
			t.Errorf("%s:%d: counted name is not a string literal", o.file, o.line)
		default:
			if _, ok := observability.Lookup(o.name); !ok {
				t.Errorf("%s:%d: %q is not registered", o.file, o.line, o.name)
			}
		}
	}
}

// Every Server-family name in the registry is emitted somewhere, so a removed
// emitter takes its entry with it.
func TestEveryServerNameIsObserved(t *testing.T) {
	emitted := map[string]bool{}
	for _, o := range observedNames(t, ".") {
		if o.literal {
			emitted[o.name] = true
		}
	}
	// The counter writes its own metrics.* rows in Add's flush, not observe.
	fset := token.NewFileSet()
	ast.Inspect(parseGoFile(t, fset, filepath.Join("observability", "counter.go")), func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if s, err := strconv.Unquote(lit.Value); err == nil && strings.HasPrefix(s, "metrics.") {
			emitted[s] = true
		}
		return true
	})
	for _, n := range observability.All() {
		if n.Family == observability.FamilyServer && !emitted[n.Name] {
			t.Errorf("registered name %q is never emitted", n.Name)
		}
	}
}

// Only count, in metrics.go, adds to the counter, after the registry's check.
func TestFeatureCounterIsReachedThroughCount(t *testing.T) {
	for _, at := range counterBypasses(t, ".") {
		t.Errorf("%s: FeatureCounter.Add or Reject outside metrics.go; call an emitter", at)
	}
}

// A fact is built with newFact, where its name can be read.
func TestFactsAreBuiltWithNewFact(t *testing.T) {
	for _, at := range factLiterals(t, ".") {
		t.Errorf("%s: fact literal outside newFact; build it with newFact", at)
	}
}

func TestDriftCollectorSeesEveryForm(t *testing.T) {
	root := t.TempDir()
	rootSrc := []string{
		"package main",
		"func handler() {",
		`	observe(r, "a.one", "")`,
		`	observeScoped(r, "s", "a.two", "")`,
		`	observeStore(r, p, "s", "a.three", "CK")`,
		`	observeJob("job", "", "a.four", "")`,
		`	_ = newFact("s", "a.five", "v")`,
		`	observe(r, prefix+name, "")`,
		`	_ = fact{"s", "a.nine", "v"}`,
		`	_ = []fact{{"s", "a.ten", "v"}}`,
		`	_ = map[string]fact{"k": {"s", "a.eleven", "v"}}`,
		`	_ = []fact{newFact("s", "a.twelve", "v")}`,
		"	o := observe",
		`	observe(r, nameConst, "")`,
		`	FeatureCounter.Add(d, "", "a.thirteen", "", 1)`,
		"	reject := FeatureCounter.Reject",
		"}",
		"func observeFacts() {",
		"	observeStore(r, p, f.scope, f.name, f.value)",
		"}",
		"func newFact(scope, name, value string) fact {",
		"	return fact{scope, name, value}",
		"}",
	}
	hookSrc := []string{
		"package x",
		"func h() {",
		`	d.Observe(r, "s", "a.six", "v")`,
		`	d.Observe("s", "a.seven", "v")`,
		`	d.Observe("a.eight", "v")`,
		`	d.Observe("s", name, "v")`,
		`	d.observe("s", "a.fourteen", "v")`,
		"	f := d.Observe",
		"}",
	}
	metricsSrc := []string{
		"package main",
		"func count() {",
		"	FeatureCounter.Add(d, scope, name, value, 1)",
		"	FeatureCounter.Reject()",
		"}",
	}
	write := func(path string, lines []string) {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "main.go"), rootSrc)
	write(filepath.Join(root, "internal", "x", "x.go"), hookSrc)
	write(filepath.Join(root, "metrics.go"), metricsSrc)
	lineOf := func(lines []string, s string) int {
		for i, l := range lines {
			if strings.Contains(l, s) {
				return i + 1
			}
		}
		t.Fatalf("no fixture line holds %q", s)
		return 0
	}

	want := []observedName{
		{file: "main.go", line: lineOf(rootSrc, "a.one"), name: "a.one", literal: true},
		{file: "main.go", line: lineOf(rootSrc, "a.two"), name: "a.two", literal: true},
		{file: "main.go", line: lineOf(rootSrc, "a.three"), name: "a.three", literal: true},
		{file: "main.go", line: lineOf(rootSrc, "a.four"), name: "a.four", literal: true},
		{file: "main.go", line: lineOf(rootSrc, "a.five"), name: "a.five", literal: true},
		{file: "main.go", line: lineOf(rootSrc, "prefix+name")},
		{file: "main.go", line: lineOf(rootSrc, "a.twelve"), name: "a.twelve", literal: true},
		{file: "main.go", line: lineOf(rootSrc, "o := observe"), misuse: "observe outside a call"},
		{file: "main.go", line: lineOf(rootSrc, "nameConst")},
		{file: "internal/x/x.go", line: lineOf(hookSrc, "a.six"), name: "a.six", literal: true},
		{file: "internal/x/x.go", line: lineOf(hookSrc, "a.seven"), name: "a.seven", literal: true},
		{file: "internal/x/x.go", line: lineOf(hookSrc, "a.eight"), badHook: true},
		{file: "internal/x/x.go", line: lineOf(hookSrc, `"s", name,`)},
		{file: "internal/x/x.go", line: lineOf(hookSrc, "a.fourteen"), misuse: "a lowercase .observe call"},
		{file: "internal/x/x.go", line: lineOf(hookSrc, "f := d.Observe"), misuse: ".Observe outside a call"},
	}
	got := observedNames(t, root)
	if len(got) != len(want) {
		t.Errorf("collected %d names, want %d: %+v", len(got), len(want), got)
	}
	for i := range min(len(got), len(want)) {
		if got[i] != want[i] {
			t.Errorf("name %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	wantFacts := []string{
		"main.go:" + strconv.Itoa(lineOf(rootSrc, "a.nine")),
		"main.go:" + strconv.Itoa(lineOf(rootSrc, "a.ten")),
		"main.go:" + strconv.Itoa(lineOf(rootSrc, "a.eleven")),
	}
	gotFacts := factLiterals(t, root)
	if strings.Join(gotFacts, " ") != strings.Join(wantFacts, " ") {
		t.Errorf("fact literals = %v, want %v", gotFacts, wantFacts)
	}

	wantBypasses := []string{
		"main.go:" + strconv.Itoa(lineOf(rootSrc, "a.thirteen")),
		"main.go:" + strconv.Itoa(lineOf(rootSrc, "reject :=")),
	}
	if got := counterBypasses(t, root); strings.Join(got, " ") != strings.Join(wantBypasses, " ") {
		t.Errorf("counter bypasses = %v, want %v", got, wantBypasses)
	}
}
