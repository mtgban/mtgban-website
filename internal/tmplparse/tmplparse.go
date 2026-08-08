// Package tmplparse parses HTML template files with the indentation they
// are written with stripped out. Nesting a loop of rows inside a page
// inside a base layout leaves every rendered row carrying its accumulated
// indent, which on a large page is most of what the browser has to parse.
package tmplparse

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Runs of whitespace that span a line break, outside the elements whose
// content is whitespace-significant. Go's regexp has no backreferences,
// so each protected element is spelled out rather than matched by name.
var indent = regexp.MustCompile(`(?is)(<pre\b[^>]*>.*?</pre>|<textarea\b[^>]*>.*?</textarea>|<script\b[^>]*>.*?</script>|<style\b[^>]*>.*?</style>)|[ \t]*\n[ \t\n]*`)

// CollapseIndent reduces each run of whitespace containing a newline to a
// single newline, never to nothing: HTML draws a word space between inline
// elements separated by whitespace, so removing it outright would run them
// together. What is left is one separator where the source had some, which
// renders identically.
//
// Elements whose content renders verbatim - pre, textarea, script, style -
// are handed back untouched.
func CollapseIndent(src string) string {
	return indent.ReplaceAllStringFunc(src, func(match string) string {
		// A protected element came through whole; hand it back as it was
		if strings.HasPrefix(match, "<") {
			return match
		}
		return "\n"
	})
}

// ParseFiles is html/template's ParseFiles with the sources collapsed on
// the way in, and so with the same naming rules: each file becomes a
// template named after its base, and the one matching the root's name is
// parsed into the root itself. Only the template text is rewritten, never
// the data later rendered through it.
func ParseFiles(baseName string, files []string, funcs template.FuncMap) (*template.Template, error) {
	root := template.New(baseName).Funcs(funcs)
	for _, file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", file, err)
		}
		name := filepath.Base(file)
		target := root
		if name != baseName {
			target = root.New(name)
		}
		_, err = target.Parse(CollapseIndent(string(src)))
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", file, err)
		}
	}
	return root, nil
}
