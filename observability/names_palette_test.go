package observability

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The palette, key and gesture names, with the value and scope lists the scripts send.
func TestPaletteNames(t *testing.T) {
	f := strings.Fields
	cases := []struct {
		name           string
		values, scopes []string
	}{
		{"ui.palette.open", f("ctrl_k slash"), nil},
		{"ui.palette.close", f("acted dismissed"), nil},
		{"ui.palette.mode", f("nav help saved recent sealed upload provider subview sealed_actions search"), f("prefix tile chip typed")},
		{"ui.palette.pick", f("enter shift_enter ctrl_enter tab click"), f("shortcut nav nav_sub card filter_candidate recent saved help command search sealed_suggestion sealed_fallback sealed_action upload_url upload_file upload_page_results upload_export")},
		{"ui.palette.composed_run", f("search nav"), nil},
		{"ui.palette.command", f("toggle_theme random_card random_sealed open_guide copy_url save_search"), f("row hotkey")},
		{"ui.palette.filter", f("r f cond sm sort on format is not skip region c ci s e in store seller vendor -r -f -cond -sm -sort -on -format -is -not -skip -region -c -ci -s -e -in -store -seller -vendor"), nil},
		{"ui.palette.chip", f("lock remove edit"), f("card filter sealed nav nav_sub")},
		{"ui.palette.saved", f("new updated overwrite cap run restore delete delete_silent"), nil},
		{"ui.palette.recent", f("run delete"), nil},
		{"ui.palette.help", f("copy open_guide"), nil},
		{"ui.palette.sealed", f("search contents unpack"), nil},
		{"ui.palette.upload", f("url file page_results export"), f("tcgplayer moxfield manabox archidekt cubecobra mythictools sheets picker page download estimate deckbox tcgplayer_csv")},
		{"ui.palette.nav", f("home changelog account search sets sealed newspaper syp screener sleepers upload global arbitrage reverse alerts api other"), f("leaf parent sub")},
		{"ui.key", f("type_to_focus settings_hotkey backpack_tab_move backpack_tab_switch"), nil},
		{"ui.search.key", f("tab_to_search result_page_down result_page_up pack_add pack_take"), nil},
		{"ui.nav.layout", f("promote swap demote dock undock reorder"), nil},
		{"ui.backpack.drag", f("card_to_tab tab_reorder"), nil},
		{"ui.upload.file_drop", nil, nil},
	}
	for _, c := range cases {
		n, ok := Lookup(c.name)
		if !ok {
			t.Errorf("%s is not registered", c.name)
			continue
		}
		if n.Family != FamilyUI || !slices.Equal(n.Enum, c.values) || !slices.Equal(n.Scopes, c.scopes) {
			t.Errorf("%s = family %v, values %v, scopes %v", c.name, n.Family, n.Enum, n.Scopes)
		}
		// What happens inside the palette is measured against its opens.
		want := ""
		if strings.HasPrefix(c.name, "ui.palette.") && c.name != "ui.palette.open" {
			want = "ui.palette.open"
		}
		if n.Denom != want {
			t.Errorf("%s: Denom %q, want %q", c.name, n.Denom, want)
		}
	}
}

// jsSource reads a script from js/, with Windows line ends folded.
func jsSource(t *testing.T, file string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "js", file))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

// between returns the part of src from the first `from` to the next `to`.
func between(t *testing.T, src, from, to string) string {
	t.Helper()
	i := strings.Index(src, from)
	if i < 0 {
		t.Fatalf("%q not found", from)
	}
	j := strings.Index(src[i+len(from):], to)
	if j < 0 {
		t.Fatalf("%q not found after %q", to, from)
	}
	return src[i : i+len(from)+j]
}

// matches returns the first group of every match of re in src.
func matches(re, src string) []string {
	var out []string
	for _, m := range regexp.MustCompile(re).FindAllStringSubmatch(src, -1) {
		out = append(out, m[1])
	}
	return out
}

// sameSet reports each value one list has and the other lacks, naming where each came from.
func sameSet(t *testing.T, got []string, gotFrom string, want []string, wantFrom string) {
	t.Helper()
	for _, v := range got {
		if !slices.Contains(want, v) {
			t.Errorf("%s has %q, which %s lacks", gotFrom, v, wantFrom)
		}
	}
	for _, v := range want {
		if !slices.Contains(got, v) {
			t.Errorf("%s has %q, which %s lacks", wantFrom, v, gotFrom)
		}
	}
}

// lookup is Lookup for a name the test cannot go on without.
func lookup(t *testing.T, name string) Name {
	t.Helper()
	n, ok := Lookup(name)
	if !ok {
		t.Fatalf("%s is not registered", name)
	}
	return n
}

// providerPrefixes are the filter prefixes palette-providers.js registers, without the colon.
func providerPrefixes(t *testing.T) []string {
	t.Helper()
	prefixes := matches(`(?m)^\s+prefix: '([a-z]+):',$`, jsSource(t, "palette-providers.js"))
	if len(prefixes) < 19 {
		t.Fatalf("palette-providers.js: %d prefixes found, want at least 19; has the file's shape changed?", len(prefixes))
	}
	return prefixes
}

// Every provider prefix, plain and negated, is a ui.palette.filter value, and nothing else is.
func TestPaletteFilterValuesAreTheProviderPrefixes(t *testing.T) {
	var want []string
	for _, p := range providerPrefixes(t) {
		want = append(want, p, "-"+p)
	}
	sameSet(t, want, "palette-providers.js prefixes", lookup(t, "ui.palette.filter").Enum, "ui.palette.filter's Enum")
}

// Every row type a reader can pick is a ui.palette.pick scope, and nothing else is.
func TestPalettePickScopesAreTheRowTypes(t *testing.T) {
	block := between(t, jsSource(t, "command-palette.js"), "var ROW_TYPES = {", "//  Render loop")
	types := matches(`(?m)^        '?([a-z-]+)'?: \{$`, block)
	if len(types) < 20 {
		t.Fatalf("command-palette.js ROW_TYPES: %d types found, want at least 20; has the file's shape changed?", len(types))
	}
	var want []string
	for _, ty := range types {
		// Never pickable: a header is not selectable, the other two are always disabled.
		if ty == "header" || ty == "upload-error" || ty == "upload-hint" {
			continue
		}
		want = append(want, strings.ReplaceAll(ty, "-", "_"))
	}
	sameSet(t, want, "command-palette.js ROW_TYPES", lookup(t, "ui.palette.pick").Scopes, "ui.palette.pick's Scopes")
}

// Every prefixed mode is a ui.palette.mode value.
func TestPaletteModeValuesCoverTheModes(t *testing.T) {
	block := between(t, jsSource(t, "command-palette.js"), "var MODES = {", "function resolveContext")
	modes := matches(`(?m)^        ([a-z]+): \{$`, block)
	if len(modes) != 6 {
		t.Fatalf("command-palette.js MODES: %d modes found, want 6; has the file's shape changed?", len(modes))
	}
	enum := lookup(t, "ui.palette.mode").Enum
	for _, m := range modes {
		if !slices.Contains(enum, m) {
			t.Errorf("command-palette.js MODES has %q, which ui.palette.mode's Enum lacks", m)
		}
	}
	// The contexts that are not a prefixed mode.
	contexts := []string{"provider", "subview", "sealed_actions", "search"}
	sameSet(t, append(modes, contexts...), "command-palette.js MODES and the four contexts", enum, "ui.palette.mode's Enum")
}

// Every slug in the palette is a registered command value or upload scope.
func TestPaletteSlugsAreRegistered(t *testing.T) {
	slugs := matches(`slug: '([a-z_]+)'`, jsSource(t, "command-palette.js"))
	if len(slugs) != 13 {
		t.Fatalf("command-palette.js: %d slugs found, want 13 (six commands, seven hosts); has the file's shape changed?", len(slugs))
	}
	commands := lookup(t, "ui.palette.command").Enum
	var hosts []string
	for _, s := range lookup(t, "ui.palette.upload").Scopes {
		switch s {
		case "picker", "page", "download", "estimate", "deckbox", "tcgplayer_csv":
		default:
			hosts = append(hosts, s)
		}
	}
	for _, s := range slugs {
		if !slices.Contains(commands, s) && !slices.Contains(hosts, s) {
			t.Errorf("command-palette.js slug %q is neither a ui.palette.command value nor a ui.palette.upload host", s)
		}
	}
	for _, v := range append(slices.Clone(commands), hosts...) {
		if !slices.Contains(slugs, v) {
			t.Errorf("%q is registered, but no slug in command-palette.js sends it", v)
		}
	}
}

// Every value of the palette's fixed tables is registered, and every registered value is in a table.
func TestPaletteTableValuesAreRegistered(t *testing.T) {
	src := jsSource(t, "command-palette.js")
	values := func(table string, least int) []string {
		t.Helper()
		v := matches(`:\s*'([a-z_]+)'`, between(t, src, "var "+table+" = {", "};"))
		if len(v) < least {
			t.Fatalf("command-palette.js %s: %d values found, want at least %d; has the file's shape changed?", table, len(v), least)
		}
		return v
	}
	nav := append(values("NAV_SLUGS", 16), "other")
	sameSet(t, nav, "command-palette.js NAV_SLUGS and other", lookup(t, "ui.palette.nav").Enum, "ui.palette.nav's Enum")
	sameSet(t, values("CHIP_SCOPES", 5), "command-palette.js CHIP_SCOPES", lookup(t, "ui.palette.chip").Scopes, "ui.palette.chip's Scopes")
	sameSet(t, values("PICK_SCOPES", 17), "command-palette.js PICK_SCOPES", lookup(t, "ui.palette.pick").Scopes, "ui.palette.pick's Scopes")
	sameSet(t, values("MODE_VALUES", 10), "command-palette.js MODE_VALUES", lookup(t, "ui.palette.mode").Enum, "ui.palette.mode's Enum")

	// The filter allowlist is the providers' prefixes, so a new provider is counted once it is registered.
	filters := matches(`'([a-z]+)'`, between(t, src, "var FILTER_PREFIXES = [", "];"))
	if len(filters) < 19 {
		t.Fatalf("command-palette.js FILTER_PREFIXES: %d values found, want at least 19; has the file's shape changed?", len(filters))
	}
	sameSet(t, filters, "command-palette.js FILTER_PREFIXES", providerPrefixes(t), "palette-providers.js prefixes")
}

// splitArgs splits argument text at its top-level commas.
func splitArgs(text string) []string {
	var out []string
	depth, start := 0, 0
	var quote byte
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
		case c == ',' && depth == 0:
			out = append(out, text[start:i])
			start = i + 1
		}
	}
	return append(out, text[start:])
}

// sentLiterals are the quoted words in an argument that can be sent: a comparison's operand is not.
func sentLiterals(arg string) []string {
	var out []string
	for _, m := range regexp.MustCompile(`(===|!==)?\s*["']([a-z_-]+)["']`).FindAllStringSubmatch(arg, -1) {
		if m[1] == "" {
			out = append(out, m[2])
		}
	}
	return out
}

// addNew appends the values list lacks.
func addNew(list []string, values ...string) []string {
	for _, v := range values {
		if !slices.Contains(list, v) {
			list = append(list, v)
		}
	}
	return list
}

// Every literal a BAN.track call in this stage's scripts can send, value or scope, is registered, and a
// name whose parts are only sent so sends every registered one.
func TestPaletteKeyAndDragLiteralsAreRegistered(t *testing.T) {
	files := []string{"command-palette.js", "search-type-focus.js", "search-result-nav.js", "search-sidebar.js", "settings-loader.js", "settings.js", "backpack.js", "navbar.js", "upload-form.js"}
	call := regexp.MustCompile(`BAN\.track\(\s*["'](ui\.[a-z_.]+)["']([^;]*)\);`)
	values, scopes := map[string][]string{}, map[string][]string{}
	for _, f := range files {
		for _, m := range call.FindAllStringSubmatch(jsSource(t, f), -1) {
			n, ok := Lookup(m[1])
			if !ok {
				continue // the root package's drift test names an unregistered call
			}
			args := splitArgs(strings.TrimPrefix(strings.TrimSpace(m[2]), ","))
			if len(args) > 2 {
				t.Errorf("%s: %s is sent with %d arguments", f, m[1], len(args)+1)
			}
			for _, v := range sentLiterals(args[0]) {
				if !slices.Contains(n.Enum, v) {
					t.Errorf("%s sends %s value %q, which its Enum lacks", f, m[1], v)
				}
				values[m[1]] = addNew(values[m[1]], v)
			}
			if len(args) < 2 {
				continue
			}
			for _, v := range sentLiterals(args[1]) {
				if !slices.Contains(n.Scopes, v) {
					t.Errorf("%s sends %s scope %q, which its Scopes lacks", f, m[1], v)
				}
				scopes[m[1]] = addNew(scopes[m[1]], v)
			}
		}
	}
	if len(values["ui.key"]) == 0 || len(values["ui.palette.saved"]) == 0 {
		t.Fatal("no literal ui.key or ui.palette.saved call found; has the call form changed?")
	}
	for _, name := range []string{"ui.key", "ui.search.key", "ui.nav.layout", "ui.backpack.drag", "ui.palette.open", "ui.palette.close", "ui.palette.composed_run",
		"ui.palette.recent", "ui.palette.upload", "ui.palette.saved", "ui.palette.help", "ui.palette.sealed"} {
		sameSet(t, values[name], "the scripts' "+name+" calls", lookup(t, name).Enum, name+"'s Enum")
	}

	src := jsSource(t, "command-palette.js")
	// The palette passes some parts through a helper rather than BAN.track itself.
	firstArgs := func(fn string, least int) []string {
		t.Helper()
		var out []string
		for _, m := range regexp.MustCompile(`\b`+fn+`\(\s*([^;]*)\);`).FindAllStringSubmatch(src, -1) {
			out = addNew(out, sentLiterals(splitArgs(m[1])[0])...)
		}
		if len(out) < least {
			t.Fatalf("command-palette.js %s: %d literals found, want at least %d; has the file's shape changed?", fn, len(out), least)
		}
		return out
	}
	sameSet(t, firstArgs("trackPick", 5), "command-palette.js trackPick calls", lookup(t, "ui.palette.pick").Enum, "ui.palette.pick's Enum")
	sameSet(t, firstArgs("trackChip", 3), "command-palette.js trackChip calls", lookup(t, "ui.palette.chip").Enum, "ui.palette.chip's Enum")
	sameSet(t, addNew(scopes["ui.palette.nav"], firstArgs("trackNav", 3)...), "command-palette.js trackNav calls", lookup(t, "ui.palette.nav").Scopes, "ui.palette.nav's Scopes")

	var modeScopes []string
	for _, m := range regexp.MustCompile(`scope = ([^;]*);`).FindAllStringSubmatch(between(t, src, "switch (ctx.kind) {", "var mode = own(MODE_VALUES"), -1) {
		modeScopes = addNew(modeScopes, sentLiterals(m[1])...)
	}
	sameSet(t, addNew(scopes["ui.palette.mode"], modeScopes...), "command-palette.js mode scopes", lookup(t, "ui.palette.mode").Scopes, "ui.palette.mode's Scopes")
	sameSet(t, scopes["ui.palette.command"], "the scripts' ui.palette.command calls", lookup(t, "ui.palette.command").Scopes, "ui.palette.command's Scopes")

	// An upload's scope is a literal in its call, a url's host slug, or an export row's field.
	upload := addNew(scopes["ui.palette.upload"], matches(`exportField:\s*'([a-z_]+)'`, src)...)
	commands := lookup(t, "ui.palette.command").Enum
	for _, slug := range matches(`slug: '([a-z_]+)'`, src) {
		if !slices.Contains(commands, slug) {
			upload = addNew(upload, slug)
		}
	}
	sameSet(t, upload, "command-palette.js upload scopes, hosts and export fields", lookup(t, "ui.palette.upload").Scopes, "ui.palette.upload's Scopes")
}
