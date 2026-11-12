package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/observability"
)

// The script's own file: the one place bump is called, and a variable name passes through.
const metricsScript = "js/metrics.js"

// Each pattern's first group is a name a page can send.
var (
	trackedNamePatterns = []*regexp.Regexp{
		regexp.MustCompile(`data-track\s*=\s*\\?["']([^"'\\]*)`),
		regexp.MustCompile(`data-track\s*=\s*([^\s"'\\>]+)`),
		regexp.MustCompile(`BAN\.track\(\s*["']([^"']*)["']`),
		regexp.MustCompile(`setAttribute\(\s*["']data-track["']\s*,\s*["']([^"']*)["']`),
		regexp.MustCompile(`dataset(?:\.track|\[\s*["']track["']\s*\])\s*=\s*["']([^"']*)["']`),
	}
	scriptBumpPattern = regexp.MustCompile(`\bbump\(\s*["']([^"']*)["']`)

	// Uses whose name this test cannot read.
	computedTrackPatterns = []*regexp.Regexp{
		regexp.MustCompile(`BAN\.track\(\s*[^"'\s)]`),
		regexp.MustCompile(`setAttribute\(\s*["']data-track["']\s*,\s*[^"'\s]`),
		regexp.MustCompile(`dataset(?:\.track|\[\s*["']track["']\s*\])\s*=\s*[^"'\s=]`),
		regexp.MustCompile(`dataset\[\s*[^"'\s\]][^\]]*\]\s*=[^=]`),
	}
	pageBumpPattern = regexp.MustCompile(`metrics\.bump\(`)

	// A value or scope mark: in markup (group 1), by setAttribute (group 2) or through dataset (3, 4).
	trackMarkPattern = regexp.MustCompile(`data-track-(value|scope)\s*=|setAttribute\(\s*["']data-track-(value|scope)["']\s*,|dataset(?:\.track(Value|Scope)|\[\s*["']track(Value|Scope)["']\s*\])\s*=`)
	// What follows a markup mark: a quoted value whose closing quote must match its opening one, or a bare one.
	markupQuoted = regexp.MustCompile(`^\s*(\\?["'])([^"'\\]*)(\\?["'])`)
	markupBare   = regexp.MustCompile(`^\s*([^\s"'\\>]+)`)
	// What follows a script mark: one string literal ending the statement or call.
	scriptLiteral = regexp.MustCompile(`^\s*(["'])([^"'\\]*)(["'])\s*(?:[;,)}\r\n]|$)`)
)

// Value and scope marks this test lets through though templated or built, as "file: name: use".
// Each entry needs a comment saying why its value is bounded and never reader text.
var trackValueAllowlist = []string{
	// ui.row.store: a row's scraper shorthand set server side, never reader text; the registry types it a store, so Check folds an unloaded one to other.
	`templates/search.html: ui.row.store: data-track-value="{{or .Shorthand "other"}}" data-track-s`,
	`templates/mobile/search.html: ui.row.store: data-track-value="{{or $entry.Shorthand "other"}}" data-t`,
	// ui.row.condition: $conditions ranges over AllConditions (search.go), the registry's enum exactly; Check refuses any other.
	`templates/mobile/search.html: ui.row.condition: data-track-value="{{$conditions}}">{{$conditions}}</butto`,
}

// allowKey is a mark's key in trackValueAllowlist.
func (m trackMark) allowKey() string {
	return m.file + ": " + m.name + ": " + m.use
}

// trackScan is what the files hold: names with the files sending them, uses it
// could not read, and every value and scope mark.
type trackScan struct {
	names      map[string][]string
	unreadable []string
	marks      []trackMark
}

// trackMark is one data-track-value or data-track-scope use.
type trackMark struct {
	file, attr, use string
	name            string // the data-track name on the same tag, when markup gives one
	value           string
	literal         bool
}

func newTrackScan() *trackScan {
	return &trackScan{names: map[string][]string{}}
}

// trackedNames reads every name templates/, js/ and the root package's Go
// files can send, with the files using it, and each use it could not read.
func trackedNames(t *testing.T) *trackScan {
	t.Helper()
	files := rootGoFiles(t, ".")
	for _, dir := range []struct{ root, ext string }{{"templates", ".html"}, {"js", ".js"}} {
		err := filepath.WalkDir(dir.root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(path, dir.ext) {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", dir.root, err)
		}
	}
	if len(files) == 0 {
		t.Fatal("no files to read")
	}

	scan := newTrackScan()
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		scan.read(filepath.ToSlash(path), string(data))
	}
	return scan
}

// unreadableName reports a name this test cannot check as written.
func unreadableName(name string) bool {
	return name == "" || strings.ContainsAny(name, "%+") || strings.Contains(name, "{{") || strings.Contains(name, "${")
}

// read adds one file's uses to the scan.
func (s *trackScan) read(file, text string) {
	isScript := file == metricsScript
	patterns := trackedNamePatterns
	if isScript {
		patterns = append(slices.Clip(patterns), scriptBumpPattern)
	}
	for _, re := range patterns {
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			name := m[1]
			if unreadableName(name) {
				s.unreadable = append(s.unreadable, file+": "+m[0])
				continue
			}
			if !slices.Contains(s.names[name], file) {
				s.names[name] = append(s.names[name], file)
			}
		}
	}
	if isScript {
		return
	}
	for _, re := range computedTrackPatterns {
		for _, m := range re.FindAllString(text, -1) {
			s.unreadable = append(s.unreadable, file+": "+m)
		}
	}
	for _, m := range pageBumpPattern.FindAllString(text, -1) {
		s.unreadable = append(s.unreadable, file+": "+m+" outside "+metricsScript+"; page scripts count through BAN.track")
	}
	s.readMarks(file, text)
}

// readMarks adds each value and scope mark, literal or not.
func (s *trackScan) readMarks(file, text string) {
	for _, loc := range trackMarkPattern.FindAllStringSubmatchIndex(text, -1) {
		end := loc[1]
		if end < len(text) && text[end] == '=' {
			continue // a comparison, not a mark
		}
		rest := text[end:]
		if i := strings.IndexAny(rest, "\n"); i >= 0 {
			rest = rest[:i]
		}
		mark := trackMark{file: file, use: text[loc[0]:end] + rest[:min(len(rest), 40)]}
		var value string
		ok := false
		switch {
		case loc[2] >= 0:
			mark.attr = "data-track-" + text[loc[2]:loc[3]]
			if m := markupQuoted.FindStringSubmatch(rest); m != nil {
				value, ok = m[2], m[1] == m[3]
			} else if m := markupBare.FindStringSubmatch(rest); m != nil {
				value, ok = m[1], true
			}
			mark.name = tagName(text, loc[0])
		default:
			var kind string
			for g := 2; g <= 4; g++ {
				if loc[2*g] >= 0 {
					kind = text[loc[2*g]:loc[2*g+1]]
				}
			}
			mark.attr = "data-track-" + strings.ToLower(kind)
			if m := scriptLiteral.FindStringSubmatch(rest); m != nil {
				value, ok = m[2], m[1] == m[3]
			}
		}
		built := strings.Contains(value, "{{") || strings.Contains(value, "${") || value != strings.TrimSpace(value)
		mark.value, mark.literal = value, ok && !built
		s.marks = append(s.marks, mark)
	}
}

// tagName returns the readable data-track name on the markup tag holding pos, or "".
func tagName(text string, pos int) string {
	start := strings.LastIndex(text[:pos], "<")
	end := strings.Index(text[pos:], ">")
	if start < 0 || end < 0 || strings.Contains(text[start:pos], ">") {
		return ""
	}
	tag := text[start : pos+end]
	for _, re := range trackedNamePatterns[:2] {
		if m := re.FindStringSubmatch(tag); m != nil && !unreadableName(m[1]) {
			return m[1]
		}
	}
	return ""
}

// problems lists every failure the scan holds against the registry.
func (s *trackScan) problems() []string {
	var out []string
	for _, use := range s.unreadable {
		out = append(out, use+": write the name as a string literal")
	}
	for name, files := range s.names {
		n, found := observability.Lookup(name)
		switch {
		case !found:
			out = append(out, fmt.Sprintf("%s: %q is not in the registry", strings.Join(files, ", "), name))
		case !clientMaySend(n.Family):
			out = append(out, fmt.Sprintf("%s: %q is not a name a browser may send", strings.Join(files, ", "), name))
		}
	}
	for _, m := range s.marks {
		if !m.literal {
			if !slices.Contains(trackValueAllowlist, m.allowKey()) {
				out = append(out, fmt.Sprintf("%s: %s is templated or built (%s): a templated value could send text a reader typed; write a literal, or allowlist it saying why it is bounded", m.file, m.attr, m.use))
			}
			continue
		}
		if p := markProblem(m); p != "" {
			out = append(out, fmt.Sprintf("%s: %s %q %s", m.file, m.attr, m.value, p))
		}
	}
	slices.Sort(out)
	return out
}

// markProblem checks a literal against its name's registered set, where the registry gives one.
func markProblem(m trackMark) string {
	n, found := observability.Lookup(m.name)
	if m.name == "" || !found {
		return ""
	}
	if m.attr == "data-track-scope" {
		switch {
		case n.Scope == observability.ScopeNone && m.value != "":
			return fmt.Sprintf("is set, but %q takes no scope", m.name)
		case n.Scope == observability.ScopeEnum && !slices.Contains(n.Scopes, m.value):
			return fmt.Sprintf("is not one of %q's scopes", m.name)
		}
		return ""
	}
	switch {
	case n.Values == observability.ValueNone && m.value != "":
		return fmt.Sprintf("is set, but %q takes no value", m.name)
	case (n.Values == observability.ValueEnum || n.Values == observability.ValueBucket) && !slices.Contains(n.Enum, m.value):
		return fmt.Sprintf("is not one of %q's values", m.name)
	case n.Values == observability.ValueFlag && m.value != "on" && m.value != "off":
		return fmt.Sprintf("is not on or off, which %q takes", m.name)
	}
	return ""
}

// Every name the pages can send is a ui. or state. name the registry knows,
// and is written as a literal so this test can see it; so is every value and scope.
func TestEveryTrackedNameIsRegistered(t *testing.T) {
	for _, p := range trackedNames(t).problems() {
		t.Error(p)
	}
}

// Every ui. and state. name in the registry has a call site, so a removed
// control takes its entry with it.
func TestEveryClientNameIsTracked(t *testing.T) {
	names := trackedNames(t).names
	for _, n := range observability.All() {
		if clientMaySend(n.Family) && names[n.Name] == nil {
			t.Errorf("%s is registered for the client, but no template, script or Go file sends it", n.Name)
		}
	}
}

// scanFixture reads one made-up file and returns its problems.
func scanFixture(file, text string) (*trackScan, []string) {
	s := newTrackScan()
	s.read(file, text)
	return s, s.problems()
}

// hasProblem reports whether one problem holds every part.
func hasProblem(problems []string, parts ...string) bool {
	return slices.ContainsFunc(problems, func(p string) bool {
		for _, part := range parts {
			if !strings.Contains(p, part) {
				return false
			}
		}
		return true
	})
}

// Every way of writing a mark is either read and checked or flagged.
func TestTrackMarkFormsAreRead(t *testing.T) {
	read := []struct{ file, text, name string }{
		{"templates/a.html", `<b data-track = "ui.ws">`, "ui.ws"},
		{"templates/a.html", `<b data-track=ui.bare>`, "ui.bare"},
		{"templates/a.html", `<b data-track='ui.single'>`, "ui.single"},
		{"js/a.js", `el.dataset.track = 'ui.dot';`, "ui.dot"},
		{"js/a.js", `el.dataset['track'] = "ui.bracket";`, "ui.bracket"},
		{"js/a.js", `el.dataset[ "track" ]='ui.bracket2';`, "ui.bracket2"},
	}
	for _, c := range read {
		s, problems := scanFixture(c.file, c.text)
		if s.names[c.name] == nil {
			t.Errorf("%s: %q not read", c.text, c.name)
		}
		if !hasProblem(problems, c.file, c.name, "not in the registry") {
			t.Errorf("%s: unregistered %q not flagged: %q", c.text, c.name, problems)
		}
	}
	if _, problems := scanFixture("templates/a.html", `<b data-track = 'ui.load'>`); len(problems) != 0 {
		t.Errorf("a registered client name is flagged: %q", problems)
	}

	flagged := []struct{ file, text string }{
		{"templates/a.html", `<b data-track={{.Name}}>`},
		{"js/a.js", `el.dataset.track = name;`},
		{"js/a.js", `el.dataset['track'] = name;`},
		{"js/a.js", `el.dataset[key] = 'ui.x';`},
		{"js/a.js", `el.dataset[k]='ui.x';`},
	}
	for _, c := range flagged {
		if _, problems := scanFixture(c.file, c.text); !hasProblem(problems, c.file, "write the name as a string literal") {
			t.Errorf("%s: not flagged: %q", c.text, problems)
		}
	}
	if _, problems := scanFixture("js/a.js", `if (el.dataset.track === 'ui.load' || el.dataset[k] === v) {}`); len(problems) != 0 {
		t.Errorf("a comparison is read as a mark: %q", problems)
	}
}

// A value or scope that is templated or built is flagged; a literal is checked against the registry.
func TestTrackValuesAreLiterals(t *testing.T) {
	flagged := []struct{ file, text, attr string }{
		{"templates/a.html", `<b data-track="ui.load" data-track-value="{{.Query}}">`, "data-track-value"},
		{"templates/a.html", `<b data-track="ui.load" data-track-scope={{.Page}}>`, "data-track-scope"},
		{"templates/a.html", `<b data-track="ui.load" data-track-value="x{{.Query}}">`, "data-track-value"},
		{"js/a.js", `html = '<b data-track="ui.load" data-track-value="' + q + '">';`, "data-track-value"},
		{"js/a.js", "html = `<b data-track-scope=\"${page}\">`;", "data-track-scope"},
		{"js/a.js", `html = "<b data-track-value=" + q + ">";`, "data-track-value"},
		{"js/a.js", `el.setAttribute('data-track-value', q);`, "data-track-value"},
		{"js/a.js", `el.setAttribute("data-track-scope", 'a' + q);`, "data-track-scope"},
		{"js/a.js", `el.dataset.trackValue = 'a' + q;`, "data-track-value"},
		{"js/a.js", `el.dataset['trackScope'] = q;`, "data-track-scope"},
	}
	for _, c := range flagged {
		_, problems := scanFixture(c.file, c.text)
		if !hasProblem(problems, c.file, c.attr, "text a reader typed") {
			t.Errorf("%s: not flagged: %q", c.text, problems)
		}
	}

	passing := []struct{ file, text string }{
		{"templates/a.html", `<b data-track="ui.load" data-track-scope="search">`},
		{"js/a.js", `html = "<b data-track=\"ui.load\" data-track-scope=\"search\">";`},
		{"js/a.js", `el.setAttribute('data-track-scope', 'search');`},
		{"js/a.js", `el.dataset.trackScope = "search";`},
		{"js/a.js", `if (el.dataset.trackValue === q) {}`},
	}
	for _, c := range passing {
		if _, problems := scanFixture(c.file, c.text); len(problems) != 0 {
			t.Errorf("%s: flagged: %q", c.text, problems)
		}
	}

	// A literal outside its name's registered set fails, naming the file and attribute.
	checked := []struct{ text, attr, why string }{
		{`<b data-track="ui.load" data-track-value="x">`, "data-track-value", "takes no value"},
		{`<b data-track="export.search" data-track-value="bogus" data-track-scope="singles">`, "data-track-value", "is not one of"},
		{`<b data-track="export.search" data-track-value="retail" data-track-scope="bogus">`, "data-track-scope", "is not one of"},
	}
	for _, c := range checked {
		_, problems := scanFixture("templates/a.html", c.text)
		if !hasProblem(problems, "templates/a.html", c.attr, c.why) {
			t.Errorf("%s: not flagged: %q", c.text, problems)
		}
	}
	_, problems := scanFixture("templates/a.html", `<b data-track="export.search" data-track-value="retail" data-track-scope="singles">`)
	if hasProblem(problems, "data-track-") {
		t.Errorf("a literal in its name's sets is flagged: %q", problems)
	}
}

// An allowlist entry covers its own name only, not the same text under another.
func TestTrackValueAllowlistIsKeyedOnTheName(t *testing.T) {
	const use = ` data-track-value="{{or .Shorthand "other"}}" data-track-scope="seller">`
	if _, problems := scanFixture("templates/search.html", `<a data-track="ui.row.store"`+use); len(problems) != 0 {
		t.Errorf("the allowlisted mark is flagged: %q", problems)
	}
	_, problems := scanFixture("templates/search.html", `<a data-track="ui.result.image"`+use)
	if !hasProblem(problems, "templates/search.html", "data-track-value", "text a reader typed") {
		t.Errorf("the allowlisted text under another name is not flagged: %q", problems)
	}
}
