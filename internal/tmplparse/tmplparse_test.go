package tmplparse

import (
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollapseIndentKeepsOneSeparator(t *testing.T) {
	// Inline elements separated by a line break draw a word space between
	// them; collapsing to nothing would run the words together.
	got := CollapseIndent("<span>one</span>\n        <span>two</span>")
	want := "<span>one</span>\n<span>two</span>"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCollapseIndentDropsBlankLines(t *testing.T) {
	got := CollapseIndent("<div>\n\n    \n        <p>x</p>\n</div>")
	want := "<div>\n<p>x</p>\n</div>"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// The elements whose content renders verbatim have to survive byte for
// byte; the site's admin and upload templates both use them.
func TestCollapseIndentLeavesVerbatimElements(t *testing.T) {
	for _, tag := range []string{"pre", "textarea", "script", "style"} {
		body := "\n    keep\n        this\n"
		src := "<div>\n    <" + tag + " class=\"x\">" + body + "</" + tag + ">\n</div>"
		got := CollapseIndent(src)
		if !strings.Contains(got, body) {
			t.Errorf("<%s> content was altered: %q", tag, got)
		}
	}
}

func TestCollapseIndentIsIdempotent(t *testing.T) {
	src := "<div>\n    <p>a</p>\n\n        <p>b</p>\n</div>\n<pre>\n  x\n</pre>"
	once := CollapseIndent(src)
	if twice := CollapseIndent(once); twice != once {
		t.Errorf("second pass changed the result:\n once: %q\ntwice: %q", once, twice)
	}
}

// Template actions keep working across a collapse, including ones the
// author already trimmed by hand.
func TestCollapseIndentKeepsActions(t *testing.T) {
	src := "{{ range .Items }}\n    <li>{{ .Name }}</li>\n{{ end }}\n{{- if .X }}y{{ end }}"
	got := CollapseIndent(src)
	for _, want := range []string{"{{ range .Items }}", "{{ .Name }}", "{{ end }}", "{{- if .X }}"} {
		if !strings.Contains(got, want) {
			t.Errorf("action %q lost: %q", want, got)
		}
	}
}

// ParseFiles keeps html/template's naming rules, and renders the data it
// is given untouched even where the template around it was collapsed.
func mustWrite(t *testing.T, path string, data []byte, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatalf("writing fixture %s: %v", path, err)
	}
}

func TestParseFilesNamesAndRenders(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.html")
	page := filepath.Join(dir, "page.html")
	mustWrite(t, base, []byte("{{ define \"base.html\" }}\n    <main>\n        {{ template \"page.html\" . }}\n    </main>\n{{ end }}"), 0o600)
	mustWrite(t, page, []byte("{{ define \"page.html\" }}\n    <span>{{ upper .Name }}</span>\n    <span>tail</span>\n{{ end }}"), 0o600)

	funcs := template.FuncMap{"upper": strings.ToUpper}
	tmpl, err := ParseFiles("base.html", []string{base, page}, funcs)
	if err != nil {
		t.Fatalf("ParseFiles: %v", err)
	}

	var out strings.Builder
	err = tmpl.ExecuteTemplate(&out, "base.html", struct{ Name string }{"a b  c"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := out.String()
	if strings.Contains(got, "\n    ") {
		t.Errorf("indentation survived: %q", got)
	}
	// Data passes through as given, spacing included
	if !strings.Contains(got, "A B  C") {
		t.Errorf("rendered value was altered: %q", got)
	}
	// The separator between the two inline elements is still there
	if strings.Contains(got, "</span><span>") {
		t.Errorf("inline elements were run together: %q", got)
	}
}
