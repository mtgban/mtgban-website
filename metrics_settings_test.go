package main

import (
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/observability"
)

var (
	settingsQuoted   = regexp.MustCompile(`'((?:Search|Upload|Sleepers|Newspaper)[A-Za-z]*)'`)
	settingsCookie   = regexp.MustCompile(`data-cookie="([A-Za-z]+)"`)
	settingsCallSite = regexp.MustCompile(`"CookieName" "([^"]+)"`)
	settingsMisc     = regexp.MustCompile(`data-misc="([^"]+)"`)
	settingsDiv      = regexp.MustCompile(`<div\b|</div>`)
	settingsDrawer   = regexp.MustCompile(`(?s)var DRAWER = \[(.*?)\];`)
	settingsLiteral  = regexp.MustCompile(`'([^']+)'`)
)

// readSettingsFile reads a repo file with LF line endings.
func readSettingsFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(data), "\r\n", "\n")
}

// packedFlags returns each packed cookie's flags: the data-misc inputs inside a div carrying data-cookie.
func packedFlags(text string) map[string][]string {
	out := map[string][]string{}
	for _, m := range settingsCookie.FindAllStringSubmatchIndex(text, -1) {
		start := strings.LastIndex(text[:m[0]], "<")
		if start < 0 || !strings.HasPrefix(text[start:], "<div") {
			continue
		}
		end, depth := len(text), 0
		for _, d := range settingsDiv.FindAllStringIndex(text[start:], -1) {
			if text[start+d[0]+1] == '/' {
				depth--
			} else {
				depth++
			}
			if depth == 0 {
				end = start + d[1]
				break
			}
		}
		for _, f := range settingsMisc.FindAllStringSubmatch(text[start:end], -1) {
			name := text[m[2]:m[3]]
			if !slices.Contains(out[name], f[1]) {
				out[name] = append(out[name], f[1])
			}
		}
	}
	return out
}

// boundSettings returns the plain cookies and the packed ones' flags the modal and the drawer save.
func boundSettings(t *testing.T) ([]string, map[string][]string) {
	t.Helper()
	var plain []string
	add := func(name string) {
		if !slices.Contains(plain, name) {
			plain = append(plain, name)
		}
	}

	js := readSettingsFile(t, "js/settings.js")
	start := strings.Index(js, "const BINDINGS = {")
	end := strings.Index(js[start:], "\n    };")
	if start < 0 || end < 0 {
		t.Fatal("no BINDINGS literal in js/settings.js")
	}
	for _, m := range settingsQuoted.FindAllStringSubmatch(js[start:start+end], -1) {
		add(m[1])
	}

	files, err := filepath.Glob("templates/settings/*.html")
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, "templates/partials/settings-stores-grouped.html")
	packed := map[string][]string{}
	for _, f := range files {
		text := readSettingsFile(t, f)
		for _, m := range settingsCookie.FindAllStringSubmatch(text, -1) {
			add(m[1])
		}
		for _, m := range settingsCallSite.FindAllStringSubmatch(text, -1) {
			add(m[1])
		}
		for name, flags := range packedFlags(text) {
			packed[name] = append(packed[name], flags...)
		}
	}

	drawer := settingsDrawer.FindStringSubmatch(readSettingsFile(t, "js/settings-changes.js"))
	if drawer == nil {
		t.Fatal("no DRAWER literal in js/settings-changes.js")
	}
	for _, m := range settingsLiteral.FindAllStringSubmatch(drawer[1], -1) {
		add(m[1])
	}

	plain = slices.DeleteFunc(plain, func(name string) bool { return packed[name] != nil })
	if len(plain) == 0 || len(packed) == 0 {
		t.Fatalf("read %d plain and %d packed cookies; the files changed shape", len(plain), len(packed))
	}
	return plain, packed
}

// Every cookie the modal binds, and every flag it packs, is a scope
// ui.settings.change accepts, so a new setting cannot ship uncounted.
func TestEveryBoundSettingIsCounted(t *testing.T) {
	n, ok := observability.Lookup("ui.settings.change")
	if !ok {
		t.Fatal("ui.settings.change is not registered")
	}
	v := metricValidators(nil)
	accepted := func(scope string) bool {
		s, _, ok := n.Check(scope, "set", v)
		return ok && s == scope
	}
	plain, packed := boundSettings(t)
	for _, name := range plain {
		if !accepted(name) {
			t.Errorf("%s is saved by the settings but is no scope ui.settings.change accepts", name)
		}
	}
	for cookie, flags := range packed {
		for _, f := range flags {
			if !accepted(cookie + "." + f) {
				t.Errorf("%s.%s is saved by the settings but is no scope ui.settings.change accepts", cookie, f)
			}
		}
	}
}

// Every scope ui.settings.change lists is spelled as the settings registry
// spells it. Skips while the registry is still 1e's empty table.
func TestSettingsChangeScopesAreSettings(t *testing.T) {
	if len(observability.Settings()) == 0 {
		t.Skip("the settings registry is empty")
	}
	n, _ := observability.Lookup("ui.settings.change")
	for _, scope := range n.Scopes {
		found := false
		for _, s := range observability.Settings() {
			if s.Name == scope {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ui.settings.change lists %q, which is no setting", scope)
		}
	}
}

var (
	settingsTable  = regexp.MustCompile(`(?m)^\s*(\w+): \[([^\]]*)\],?$`)
	settingsOthers = regexp.MustCompile(`(?s)var OTHERS = \[(.*?)\];`)
)

// jsTable reads a {Name: ['a', ...]} literal from js/settings-changes.js.
func jsTable(t *testing.T, js, name string) map[string][]string {
	t.Helper()
	m := regexp.MustCompile(`(?s)var ` + name + ` = \{(.*?)\n    \};`).FindStringSubmatch(js)
	if m == nil {
		t.Fatalf("no %s literal in js/settings-changes.js", name)
	}
	out := map[string][]string{}
	for _, row := range settingsTable.FindAllStringSubmatch(m[1], -1) {
		for _, w := range settingsLiteral.FindAllStringSubmatch(row[2], -1) {
			out[row[1]] = append(out[row[1]], w[1])
		}
	}
	if len(out) == 0 {
		t.Fatalf("read nothing from %s", name)
	}
	return out
}

// The closed tables settings-changes.js sends from are the settings registry's, both ways.
func TestSettingsChangesTablesAreTheRegistry(t *testing.T) {
	js := readSettingsFile(t, "js/settings-changes.js")
	flags := jsTable(t, js, "KNOWN_FLAGS")
	enums := jsTable(t, js, "ENUM_VALUES")
	om := settingsOthers.FindStringSubmatch(js)
	if om == nil {
		t.Fatal("no OTHERS literal in js/settings-changes.js")
	}
	var others []string
	for _, w := range settingsLiteral.FindAllStringSubmatch(om[1], -1) {
		others = append(others, w[1])
	}

	registered := map[string][]string{}
	for _, s := range observability.Settings() {
		cookie, flag, ok := strings.Cut(s.Name, ".")
		if ok && s.Class == "preference" && s.Kind == "flag" {
			registered[cookie] = append(registered[cookie], flag)
		}
	}
	for cookie, want := range registered {
		if !slices.Equal(flags[cookie], want) {
			t.Errorf("KNOWN_FLAGS[%s] = %v, the registry has %v", cookie, flags[cookie], want)
		}
	}
	for cookie := range flags {
		if registered[cookie] == nil {
			t.Errorf("KNOWN_FLAGS has %s, which the registry packs no flag into", cookie)
		}
	}

	for name, words := range enums {
		s, ok := observability.LookupSetting(name)
		if !ok || s.Class != "preference" || s.Kind != "enum" || !slices.Equal(s.Enum, words) {
			t.Errorf("ENUM_VALUES[%s] = %v is not the registry's enum preference", name, words)
		}
	}
	for _, name := range others {
		s, ok := observability.LookupSetting(name)
		if !ok || s.Class != "preference" || s.Kind == "enum" || s.Kind == "flag" {
			t.Errorf("OTHERS has %s, which is no registered preference that is set or cleared", name)
		}
	}

	// Every cookie a save writes is in a table, and every table entry is one a save writes.
	plain, packed := boundSettings(t)
	plain = append(plain, "SearchStoreFactors")
	for _, name := range plain {
		if enums[name] == nil && !slices.Contains(others, name) {
			t.Errorf("%s is saved but in no closed table, so its change is never counted", name)
		}
	}
	for cookie := range packed {
		if flags[cookie] == nil {
			t.Errorf("%s packs flags but is not in KNOWN_FLAGS", cookie)
		}
	}
	for _, name := range append(slices.Collect(maps.Keys(enums)), others...) {
		if !slices.Contains(plain, name) {
			t.Errorf("%s is in a closed table but nothing saves it", name)
		}
	}
}
