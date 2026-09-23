package main

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
	"text/template/parse"
)

// TestTemplatesParse parses every template the way production does (via the
// shared funcMap), catching syntax errors and references to unregistered
// template functions such as a mistyped buylist_badge.
func TestTemplatesParse(t *testing.T) {
	saved := DevMode
	DevMode = false
	defer func() { DevMode = saved }()

	if _, err := buildTemplateCache(); err != nil {
		t.Fatalf("templates failed to parse: %v", err)
	}
}

// TestTemplatesResolveEveryReference checks that each {{template "x"}} a page
// can actually reach resolves in that page's own set.
//
// TestTemplatesParse cannot see this: html/template resolves a reference when
// it executes, not when it parses, so a block that no file in the set defines
// parses clean and fails on the first request. That is how the set symbol block
// came to be defined in base.html alone while the mobile pages, which are built
// from base-mobile.html, kept calling it -- every one of them 500'd.
//
// Reachability is the same rule the renderer follows, walking out from the base
// the page is built on. A block the base never invokes is never resolved, so a
// reference inside one is not a broken page: arbit.html defines a settings block
// that only the desktop settings modal calls, and rendering it on mobile is fine.
func TestTemplatesResolveEveryReference(t *testing.T) {
	saved := DevMode
	DevMode = false
	defer func() { DevMode = saved }()

	cache, err := buildTemplateCache()
	if err != nil {
		t.Fatalf("templates failed to parse: %v", err)
	}

	for key, tmpl := range cache {
		// The root carries the base's name, which is where rendering starts.
		for _, missing := range unresolvedRefs(tmpl, tmpl.Name()) {
			t.Errorf("%s: {{template %q}} is reachable but not defined in its set", key, missing)
		}
	}
}

// unresolvedRefs walks out from the named template and returns every reference
// it can reach that nothing in the set defines.
func unresolvedRefs(tmpl *template.Template, root string) []string {
	var missing []string
	seen := map[string]bool{}

	var visit func(name string)
	visit = func(name string) {
		if seen[name] {
			return
		}
		seen[name] = true

		assoc := tmpl.Lookup(name)
		if assoc == nil {
			missing = append(missing, name)
			return
		}
		if assoc.Tree == nil {
			return
		}
		var refs []string
		collectTemplateRefs(assoc.Tree.Root, &refs)
		for _, ref := range refs {
			visit(ref)
		}
	}
	visit(root)

	return missing
}

// collectTemplateRefs walks the node types that can hold a template reference.
// {{block}} parses into a TemplateNode plus its own definition, so it is
// covered by the same case.
func collectTemplateRefs(node parse.Node, out *[]string) {
	switch n := node.(type) {
	case *parse.ListNode:
		if n == nil {
			return
		}
		for _, child := range n.Nodes {
			collectTemplateRefs(child, out)
		}
	case *parse.TemplateNode:
		*out = append(*out, n.Name)
	case *parse.IfNode:
		collectTemplateRefs(n.List, out)
		collectTemplateRefs(n.ElseList, out)
	case *parse.RangeNode:
		collectTemplateRefs(n.List, out)
		collectTemplateRefs(n.ElseList, out)
	case *parse.WithNode:
		collectTemplateRefs(n.List, out)
		collectTemplateRefs(n.ElseList, out)
	}
}

// TestCardArtPlaceholderSurvivesEscaping pins that the placeholder reaches the
// page as the inert 1x1 gif it is meant to be.
//
// It is a data: URI, and the contextual autoescaper rejects those in a URL
// context unless they are typed template.URL - it writes #ZgotmplZ instead.
// That is not inert: it resolves against the current page, so the browser
// fetches the whole HTML document back as an image (6.3MB on a full arbit
// table), fails to decode it, and the card-art fallback then pulls down the
// game's card back - all before anyone has hovered a row.
//
// Both contexts are checked because they escape differently and only one of
// them was ever broken: the same value goes into an onmouseout handler as a JS
// string, where data: is allowed through and always worked.
func TestCardArtPlaceholderSurvivesEscaping(t *testing.T) {
	for _, tc := range []struct {
		name, tmpl string
	}{
		{"src attribute", `<img class="hoverImage" src="{{card_art_placeholder}}"/>`},
		{"js string argument", `<div onmouseout="setCardArtSource(img,'{{card_art_placeholder}}')"></div>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmpl, err := template.New(tc.name).Funcs(funcMap).Parse(tc.tmpl)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			var out bytes.Buffer
			if err := tmpl.Execute(&out, nil); err != nil {
				t.Fatalf("execute: %v", err)
			}
			got := out.String()
			if strings.Contains(got, "ZgotmplZ") {
				t.Errorf("placeholder was sanitized away, leaving a src that fetches the page itself: %s", got)
			}
			// The JS context escapes the slashes (data:image\/gif), which is
			// the same string once the engine reads it, so compare on the part
			// that cannot be escaped either way.
			if !strings.Contains(got, "base64,R0lGOD") {
				t.Errorf("placeholder did not reach the output: %s", got)
			}
		})
	}
}
