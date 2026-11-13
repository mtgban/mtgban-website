package main

import (
	"slices"
	"testing"

	"github.com/mtgban/mtgban-website/apiproductlist"
	"github.com/mtgban/mtgban-website/observability"
)

// Every package on the price list is a value ui.apiplans.choose accepts.
func TestEveryAPIPackageIsACountedValue(t *testing.T) {
	n, _ := observability.Lookup("ui.apiplans.choose")
	list := apiproductlist.MustLoad()
	for _, p := range list.Packages {
		if !slices.Contains(n.Enum, p.Key) {
			t.Errorf("package %s is not a ui.apiplans.choose value", p.Key)
		}
	}
	if len(n.Enum) != len(list.Packages) {
		t.Errorf("ui.apiplans.choose has %d values for %d packages", len(n.Enum), len(list.Packages))
	}
}
