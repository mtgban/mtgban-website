package main

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The OpenAPI documents list the id systems the price API accepts, so a
// client generated from them can ask for every one.
func TestOpenAPIListsEveryIDMode(t *testing.T) {
	enum := regexp.MustCompile(`(?s)description: Id system for card keys\s+schema: \{ type: string, enum: \[([^\]]*)\]`)
	for _, path := range []string{"openapi/v1.yaml", "openapi/v2.yaml"} {
		doc, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		m := enum.FindSubmatch(doc)
		if m == nil {
			t.Fatalf("%s: no id enum", path)
		}
		listed := strings.Split(strings.ReplaceAll(string(m[1]), " ", ""), ",")
		slices.Sort(listed)
		want := slices.Clone(v2IDModes)
		if path == "openapi/v1.yaml" {
			// v1 spells MTGBAN ids mtgban
			i := slices.Index(want, "ban")
			if i < 0 {
				t.Fatalf("v2IDModes has no ban: %v", v2IDModes)
			}
			want[i] = "mtgban"
		}
		slices.Sort(want)
		if !slices.Equal(listed, want) {
			t.Errorf("%s lists %v, the API takes %v", path, listed, want)
		}
	}
}

// The OpenAPI document lists every report the newspaper declares, in its
// order, so a client generated from it can ask for each.
func TestOpenAPINamesEveryNewspaperReport(t *testing.T) {
	doc, err := os.ReadFile("openapi/v2.yaml")
	if err != nil {
		t.Fatal(err)
	}
	enum := regexp.MustCompile(`description: A newspaper report key[^\n]*\s+schema: \{ type: string, enum: \[([^\]]*)\]`)
	m := enum.FindSubmatch(doc)
	if m == nil {
		t.Fatal("openapi/v2.yaml: no newspaper report enum")
	}
	listed := strings.Split(strings.ReplaceAll(string(m[1]), " ", ""), ",")
	var want []string
	for _, page := range newspaperPagesInitial {
		if page.Query != "" {
			want = append(want, page.Option)
		}
	}
	if !slices.Equal(listed, want) {
		t.Errorf("openapi/v2.yaml lists %v, the newspaper declares %v", listed, want)
	}
}
