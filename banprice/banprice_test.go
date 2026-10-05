package banprice

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// TestMagicWireIsUnchanged: a card sold in the three finishes Magic has
// serialises exactly as it did before the other finishes had fields.
func TestMagicWireIsUnchanged(t *testing.T) {
	p := &Price{Cond: "NM"}
	p.Set(FinishNonfoil, 1.5)
	p.Set(FinishFoil, 3)
	p.Set(FinishEtched, 4.25)
	p.AddQty(FinishNonfoil, 2)
	p.AddQty(FinishFoil, 1)
	p.Conditions = &Conditions{}
	p.Conditions.Set("NM", 1.5)
	p.Conditions.Set("SP_foil", 2.5)
	p.Quantities = &Quantities{}
	p.Quantities.Set("NM", 2)

	got, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"regular":1.5,"foil":3,"etched":4.25,"cond":"NM","qty":2,"qty_foil":1,` +
		`"conditions":{"NM":1.5,"SP_foil":2.5},"quantities":{"NM":2}}`
	if string(got) != want {
		t.Errorf("wire =\n%s\nwant\n%s", got, want)
	}
	if p.MoreFinishes != nil || p.Conditions.MoreConditions != nil || p.Quantities.MoreQuantities != nil {
		t.Error("the three Magic finishes allocated room for the others")
	}
}

// TestEveryFinishRoundTrips sets every finish at every grade and reads it
// back, through the struct and through the wire.
func TestEveryFinishRoundTrips(t *testing.T) {
	p := &Price{Conditions: &Conditions{}, Quantities: &Quantities{}}
	for i, finish := range Finishes {
		p.Set(finish, float64(i+1))
		p.AddQty(finish, i+1)
	}
	for i, tag := range ConditionTags {
		p.Conditions.Set(tag, float64(i+1))
		p.Quantities.Set(tag, i+1)
	}

	wire, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var back Price
	if err := json.Unmarshal(wire, &back); err != nil {
		t.Fatal(err)
	}

	for _, read := range []*Price{p, &back} {
		for i, finish := range Finishes {
			if got := read.Get(finish); got != float64(i+1) {
				t.Errorf("Get(%s) = %v, want %v", finish, got, i+1)
			}
			if got := read.GetQty(finish); got != i+1 {
				t.Errorf("GetQty(%s) = %v, want %v", finish, got, i+1)
			}
		}
		for i, tag := range ConditionTags {
			if got := read.Conditions.Get(tag); got != float64(i+1) {
				t.Errorf("Conditions.Get(%s) = %v, want %v", tag, got, i+1)
			}
			if got := read.Quantities.Get(tag); got != i+1 {
				t.Errorf("Quantities.Get(%s) = %v, want %v", tag, got, i+1)
			}
		}
	}
}

func TestUnknownFinishesAreIgnored(t *testing.T) {
	var p Price
	p.Set("glitterfoil", 9)
	p.AddQty("glitterfoil", 1)
	if p.MoreFinishes != nil || p.Get("glitterfoil") != 0 {
		t.Error("a finish with no field was filed somewhere")
	}
	c := &Conditions{}
	c.Set("NM_glitterfoil", 9)
	if c.MoreConditions != nil {
		t.Error("a tag with no field allocated the other finishes")
	}
	var nilPrice *Price
	if nilPrice.Get("coldfoil") != 0 || nilPrice.GetQty("coldfoil") != 0 {
		t.Error("a nil price answered")
	}
}

// TestEveryMatcherFinishIsServed keeps the finishes in step with the ones
// go-mtgban names: a finish the matcher files a card under and this has no
// field for would be priced as a plain foil or nonfoil, overwriting one.
func TestEveryMatcherFinishIsServed(t *testing.T) {
	for _, finish := range mtgmatcher.Finishes {
		if !Serves(finish.Slug) {
			t.Errorf("finish %q has no field; add it to gen.go and go generate", finish.Slug)
		}
	}
	for _, finish := range []string{mtgmatcher.FinishNonfoil, mtgmatcher.FinishFoil, mtgmatcher.FinishEtched} {
		if !Serves(finish) {
			t.Errorf("finish %q has no field", finish)
		}
	}
	if !slices.Equal(ConditionTags[:3], []string{"NM", "NM_foil", "NM_etched"}) {
		t.Errorf("ConditionTags opens %v, want the three Magic finishes first", ConditionTags[:3])
	}
}
