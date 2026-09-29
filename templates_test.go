package main

import (
	"html/template"
	"strings"
	"testing"
	"text/template/parse"

	"github.com/mtgban/go-mtgban/mtgban"
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

// The placeholder is written into src attributes. As a plain string,
// html/template judges a data: URL unsafe there and writes #ZgotmplZ, which
// the browser requests as the page's own address on every view.
func TestCardArtPlaceholderSurvivesSrc(t *testing.T) {
	tmpl := template.Must(template.New("t").Funcs(funcMap).Parse(`<img src="{{card_art_placeholder}}">`))
	var b strings.Builder
	err := tmpl.Execute(&b, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), cardArtPlaceholder) {
		t.Errorf("rendered %s, want the placeholder in src", b.String())
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

// TestBuylistCKHelpers pins the CK buylist helpers and executes them with the
// argument types the pages pass: html/template checks those only when it runs.
func TestBuylistCKHelpers(t *testing.T) {
	state, ok := funcMap["buylist_state"].(func(string, mtgban.Condition, bool, float64, float64, string, bool) string)
	if !ok {
		t.Fatal("buylist_state has another signature")
	}
	for _, tc := range []struct {
		name       string
		shorthand  string
		conditions mtgban.Condition
		isOffer    bool
		price      float64
		ckSignal   string
		pauseWait  bool
		want       string
	}{
		{"CK NM sell", "CK", "NM", true, 10, "sell", false, "best"},
		{"CK NM wait", "CK", "NM", true, 9, "wait", false, "wait"},
		{"CK NM neutral at P90", "CK", "NM", true, 9, "", false, ""},
		{"CK SP never", "CK", "SP", true, 12, "sell", false, ""},
		{"other store at P90", "SCG", "NM", true, 9, "wait", false, "best"},
		{"other store below P90", "SCG", "NM", true, 8, "", false, ""},
		{"not an offer", "SCG", "NM", false, 12, "", false, ""},
		// CK is not paying its last known price, even above its P90.
		{"CK paused above P90", "CKBLLast", "NM", true, 12, "", false, ""},
		{"CK paused, worth waiting", "CKBLLast", "NM", true, 12, "", true, "wait"},
		{"CK paused SP", "CKBLLast", "SP", true, 12, "", true, ""},
	} {
		got := state(tc.shorthand, tc.conditions, tc.isOffer, tc.price, 9, tc.ckSignal, tc.pauseWait)
		if got != tc.want {
			t.Errorf("buylist_state %s: got %q, want %q", tc.name, got, tc.want)
		}
	}

	title, ok := funcMap["buylist_title"].(func(string, mtgban.Condition, string, float64, float64, string, string) string)
	if !ok {
		t.Fatal("buylist_title has another signature")
	}
	for _, tc := range []struct {
		name      string
		shorthand string
		cond      mtgban.Condition
		state     string
		want      string
	}{
		// The verdict, the facts, CK's reference prices, then the odds.
		{"CK NM", "CK", "NM", "wait", "Wait: out\nCK stock 0\n**P90**: $ 9.00 · **90d high**: $ 12.00\nodds 1\nodds 2"},
		{"CK SP", "CK", "SP", "", ""},
		{"other store green", "SCG", "NM", "best", "**A good price**: at or above Card Kingdom's P90 ($ 9.00)"},
		{"other store below P90", "SCG", "NM", "", ""},
	} {
		got := title(tc.shorthand, tc.cond, tc.state, 9, 12, "CK stock 0", "Wait: out\nodds 1\nodds 2")
		if got != tc.want {
			t.Errorf("buylist_title %s: got %q, want %q", tc.name, got, tc.want)
		}
	}
	got := title("CK", "NM", "", 9, 0, "CK stock 3", "")
	if got != "CK stock 3\n**P90**: $ 9.00" {
		t.Errorf("buylist_title CK NM without a signal: got %q", got)
	}

	const page = `{{buylist_state .Shorthand .Cond .IsOffer .Price .Good .Signal false}}|` +
		`{{buylist_wait .Shorthand .Cond .Signal .Tip}}|{{buylist_ck .Signal}}|` +
		`<span title="{{buylist_title .Shorthand .Cond .Signal .Good .Highest .Facts .Tip}}"></span>`
	tmpl := template.Must(template.New("t").Funcs(funcMap).Parse(page))
	var b strings.Builder
	err := tmpl.Execute(&b, struct {
		Shorthand            string
		Cond                 mtgban.Condition
		IsOffer              bool
		Price, Good, Highest float64
		Signal, Tip, Facts   string
	}{"CK", "NM", true, 9, 9, 12, "wait", `CK "odds"`, "CK stock 0 · out 9 days"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"wait|",
		`<span class="ck-wait" title="CK &#34;odds&#34;">&#8593;</span>`,
		// The column's tooltip carries the facts; the line only its verdict.
		`<span class="bl-ck bl-ck-wait">&#8593; Wait</span>`,
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("rendered %s, want %s", b.String(), want)
		}
	}

	// Only the known states become a class.
	ck, ok := funcMap["buylist_ck"].(func(string) template.HTML)
	if !ok {
		t.Fatal("buylist_ck has another signature")
	}
	for _, signal := range []string{"", "best x"} {
		got = string(ck(signal))
		if got != "" {
			t.Errorf("buylist_ck %q: got %s, want nothing", signal, got)
		}
	}
}

// TestTipHelpers checks a tooltip's ** marks become a data-tip beside a plain
// title, and bold where a page writes the tooltip out in full.
func TestTipHelpers(t *testing.T) {
	got := tipAttrs(`**Wait:** CK "odds" <5%>`)
	want := ` title="Wait: CK &#34;odds&#34; &lt;5%&gt;" data-tip="**Wait:** CK &#34;odds&#34; &lt;5%&gt;"`
	if got != want {
		t.Errorf("tipAttrs marked: got %s, want %s", got, want)
	}
	got = tipAttrs("90-day high")
	if got != ` title="90-day high"` {
		t.Errorf("tipAttrs plain: got %s", got)
	}

	html, ok := funcMap["tip_html"].(func(string) template.HTML)
	if !ok {
		t.Fatal("tip_html has another signature")
	}
	got = string(html("**Sell now:** <b>27%</b>"))
	if got != "<strong>Sell now:</strong> &lt;b&gt;27%&lt;/b&gt;" {
		t.Errorf("tip_html: got %s", got)
	}
}

// TestBuylistPause executes the pause pill and its wait arrow the way search
// calls them: on CK's last known NM offer only, the arrow when waiting pays.
func TestBuylistPause(t *testing.T) {
	tmpl := template.Must(template.New("t").Funcs(funcMap).Parse(
		`{{buylist_pause .Shorthand .Cond .Label .Tip}}|{{buylist_pause_wait .Shorthand .Cond .Wait}}`))
	for _, tc := range []struct {
		name, shorthand string
		cond            mtgban.Condition
		label           string
		wait            bool
		want            string
	}{
		{"paused", "CKBLLast", "NM", "Paused 3d", false,
			` <span class="bl-pill bl-pill-paused" title="Paused: CK stopped" data-tip="**Paused**: CK stopped">Paused 3d</span>|`},
		{"wait", "CKBLLast", "NM", "Paused 3d", true,
			` <span class="bl-pill bl-pill-paused" title="Paused: CK stopped" data-tip="**Paused**: CK stopped">Paused 3d</span>|` +
				` <span class="ck-wait" title="Wait: don&#39;t undersell it elsewhere, CK&#39;s buylist may reopen soon." data-tip="**Wait**: don&#39;t undersell it elsewhere, CK&#39;s buylist may reopen soon.">&#8593;</span>`},
		{"not paused", "CKBLLast", "NM", "", false, "|"},
		{"another grade", "CKBLLast", "SP", "Paused 3d", true, "|"},
		{"another store", "CK", "NM", "Paused 3d", true, "|"},
	} {
		var b strings.Builder
		err := tmpl.Execute(&b, struct {
			Shorthand  string
			Cond       mtgban.Condition
			Label, Tip string
			Wait       bool
		}{tc.shorthand, tc.cond, tc.label, "**Paused**: CK stopped", tc.wait})
		if err != nil {
			t.Fatal(err)
		}
		if b.String() != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, b.String(), tc.want)
		}
	}
}

// TestBuylistBadgePills executes the hotlist pills the way the pages call them.
func TestBuylistBadgePills(t *testing.T) {
	tmpl := template.Must(template.New("t").Funcs(funcMap).Parse(`{{buylist_badge .Store .Hotlist .New .Tip}}`))
	for _, tc := range []struct {
		store, hotlist string
		isNew          bool
		want           string
	}{
		{"CK", "CK", true, `class="bl-pill bl-pill-new" title="New high: CK" data-tip="**New high**: CK"`},
		{"CK", "CK", false, `class="bl-pill bl-pill-high"`},
		{"SCG", "CK", true, ""},
		{"CK", "", false, ""},
	} {
		var b strings.Builder
		err := tmpl.Execute(&b, struct {
			Store, Hotlist, Tip string
			New                 bool
		}{tc.store, tc.hotlist, "**New high**: CK", tc.isNew})
		if err != nil {
			t.Fatal(err)
		}
		if (tc.want == "" && b.String() != "") || !strings.Contains(b.String(), tc.want) {
			t.Errorf("%s/%s/%v: rendered %q, want %q", tc.store, tc.hotlist, tc.isNew, b.String(), tc.want)
		}
	}
}

// TestBuylistDetailTint checks Good follows CK's signal, executed the way the
// arbit and upload pages call it.
func TestBuylistDetailTint(t *testing.T) {
	tmpl := template.Must(template.New("t").Funcs(funcMap).Parse(
		`{{buylist_detail .Store .Hotlist .Price .Good .Highest .Always .Signal}}`))
	for _, tc := range []struct {
		signal string
		always bool
		want   string
		not    string
	}{
		{"sell", true, `<span class="bl-good-sell">Good: $ 9.00</span>`, ""},
		{"wait", true, `<span class="bl-good-wait">Good: $ 9.00</span>`, ""},
		{"", true, `<span>Good: $ 9.00</span>`, "bl-good-"},
		{"sell", false, `<span>Good: $ 9.00</span>`, "bl-good-"},
		// Only the known states become a class.
		{"best x", true, `<span>Good: $ 9.00</span>`, "bl-good-"},
	} {
		var b strings.Builder
		err := tmpl.Execute(&b, struct {
			Store, Hotlist       string
			Price, Good, Highest float64
			Always               bool
			Signal               string
		}{"CK", "", 20, 9, 12, tc.always, tc.signal})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(b.String(), tc.want) || (tc.not != "" && strings.Contains(b.String(), tc.not)) {
			t.Errorf("signal %q always %v: rendered %s", tc.signal, tc.always, b.String())
		}
	}
}
