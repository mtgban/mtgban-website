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
		want := slices.Sorted(slices.Values(v2IDModes))
		if !slices.Equal(listed, want) {
			t.Errorf("%s lists %v, the API takes %v", path, listed, want)
		}
	}
}
