package banprice

import (
	"bytes"
	"encoding/json"
	"math"
	"math/rand/v2"
	"testing"
)

// TestWriteJSONMatchesEncodingJSON pins WriteJSON to encoding/json's bytes,
// on the shapes and values most likely to tell them apart.
func TestWriteJSONMatchesEncodingJSON(t *testing.T) {
	odd := []string{"", "plain", "Fire & Ice", "<b>", "a\"b", `back\slash`, "tab\there", "\x01", "\x7f",
		"Æther Vial", "line\u2028sep", "bad\xffbyte", "emoji 🃏", "name|SET|12"}
	prices := []float64{0, math.Copysign(0, -1), 0.1, 1, 26.572020469894643, 1e-7, 9.99e-7, 1e-6,
		1e20, 1e21, 123456789012345678901234, 4.462220609212105, -3.5}

	cases := []V2{
		nil,
		{},
		{"id": nil},
		{"id": {"nonfoil": nil}},
		{"id": {"nonfoil": {"CK": nil, "SCG": {}}}},
	}
	random := rand.New(rand.NewPCG(1, 2))
	for range 200 {
		v := V2{}
		for range random.IntN(5) + 1 {
			finishes := map[string]map[string][]Entry{}
			for range random.IntN(3) + 1 {
				stores := map[string][]Entry{}
				for range random.IntN(4) + 1 {
					var entries []Entry
					for range random.IntN(4) {
						entries = append(entries, Entry{
							Condition: odd[random.IntN(len(odd))],
							Price:     prices[random.IntN(len(prices))],
							Qty:       random.IntN(3) - 1,
							Available: random.IntN(3),
						})
					}
					stores[odd[random.IntN(len(odd))]] = entries
				}
				finishes[odd[random.IntN(len(odd))]] = stores
			}
			v[odd[random.IntN(len(odd))]] = finishes
		}
		cases = append(cases, v)
	}

	for i, v := range cases {
		want, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var got bytes.Buffer
		err = v.WriteJSON(&got)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if !bytes.Equal(got.Bytes(), want) {
			t.Fatalf("case %d:\n got %s\nwant %s", i, got.Bytes(), want)
		}
	}
}

// TestWriteJSONRefusesNaN refuses what encoding/json refuses.
func TestWriteJSONRefusesNaN(t *testing.T) {
	for _, price := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		v := V2{"id": {"nonfoil": {"CK": {{Price: price}}}}}
		_, want := json.Marshal(v)
		got := v.WriteJSON(&bytes.Buffer{})
		if want == nil || got == nil || got.Error() != want.Error() {
			t.Errorf("price %v: got %v, want %v", price, got, want)
		}
	}
}
