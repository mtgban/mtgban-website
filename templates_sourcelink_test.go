package main

import (
	"html/template"
	"strings"
	"testing"
)

// The notes column is whatever the uploaded file put in it, and the upload
// results turn it into the link on the loaded price. These say what counts
// as a link and what stays the text it was.
func TestSourceLink(t *testing.T) {
	link, ok := funcMap["sourceLink"].(func(string) string)
	if !ok {
		t.Fatal("sourceLink is not in the template funcs")
	}

	const offer = "https://www.cardmarket.com/en/Magic/Users/Lemhast/Offers/Singles?name=X&idExpansions=5359"

	tests := []struct {
		name string
		note string
		want string
	}{
		{"an offer link is one", offer, offer},
		{"so is plain http", "http://example.test/a", "http://example.test/a"},
		{"surrounding space does not stop it", "  " + offer + "  ", offer},
		// A note is not a link merely for being a string.
		{"a sentence is not", "bought at the shop on the corner", ""},
		{"nor is an empty note", "", ""},
		{"nor a bare host", "www.cardmarket.com/en/Magic", ""},
		{"nor a relative path", "/en/Magic/Users/Lemhast/Offers/Singles", ""},
		// html/template would refuse these in an href anyway; they should
		// not get as far as being one.
		{"nor a script", "javascript:alert(1)", ""},
		{"nor a data URL", "data:text/html,<script>alert(1)</script>", ""},
		{"nor a file path", "file:///etc/passwd", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := link(tc.note); got != tc.want {
				t.Errorf("sourceLink(%q) = %q, want %q", tc.note, got, tc.want)
			}
		})
	}
}

// The cell itself: a note that is a link wraps the price in one, and a note
// that is not leaves the price alone. Rendered through html/template so the
// escaping is the real thing.
func TestLoadedPriceCell(t *testing.T) {
	const cell = `<td class="ures-price">{{$source := sourceLink .Notes}}` +
		`{{if $source}}<a href="{{$source}}" target="_blank" rel="nofollow noopener">` +
		`$ {{printf "%.2f" .OriginalPrice}}</a>{{else}}$ {{printf "%.2f" .OriginalPrice}}{{end}}</td>`

	tmpl := template.Must(template.New("cell").Funcs(funcMap).Parse(cell))

	render := func(note string) string {
		var out strings.Builder
		err := tmpl.Execute(&out, struct {
			Notes         string
			OriginalPrice float64
		}{note, 1.5})
		if err != nil {
			t.Fatal(err)
		}
		return out.String()
	}

	linked := render("https://www.cardmarket.com/en/Magic/Users/Lemhast/Offers/Singles")
	if !strings.Contains(linked, `<a href="https://www.cardmarket.com/en/Magic/Users/Lemhast/Offers/Singles"`) {
		t.Errorf("an offer link did not become a link: %s", linked)
	}
	if !strings.Contains(linked, "$ 1.50</a>") {
		t.Errorf("the price is not what was made clickable: %s", linked)
	}

	plain := render("bought at the shop on the corner")
	if strings.Contains(plain, "<a ") {
		t.Errorf("a plain note became a link: %s", plain)
	}
	if !strings.Contains(plain, "$ 1.50") {
		t.Errorf("the price went missing: %s", plain)
	}
}
