// Command gen-ofp1-fixture writes OFP1 fixtures that pin the Go encoder
// and the JS decoder to the same bytes.
package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/mtgban/mtgban-website/internal/offline"
)

// samplePayload exercises every flag the encoder can emit.
func samplePayload() *offline.SetPayload {
	return &offline.SetPayload{
		SetCode:  "NEO",
		Snapshot: time.Unix(1770000000, 0).UTC(),
		Retail: map[string]map[string]*offline.PriceEntry{
			"uuid-0001": {
				"CK": {
					Regular: 0.99, Cond: "NM", Qty: 5,
					Conditions: map[string]float64{"NM": 0.99, "SP": 0.79},
					Quantities: map[string]int{"NM": 5, "SP": 2},
				},
				"TCGLow": {Regular: 0.41},
			},
			"uuid-0002_f": {
				"CK": {Foil: 1.23, Cond: "NM", QtyFoil: 2,
					Conditions: map[string]float64{"NM_foil": 1.23}},
			},
			"uuid-0003_e": {
				"SCG": {Etched: 20, QtyEtched: 1},
			},
			"uuid-0004": {
				"CK": {Regular: 1, Foil: 2.5},
			},
			"uuid-0005": {
				"CK": {Regular: 12345.67},
			},
			"uuid-0006": {
				"TCGLow": {Quantities: map[string]int{"NM": 7}},
			},
			"uuid-sealed-box": {
				"CK": {Sealed: 129.99, QtySealed: 3},
			},
		},
		Buylist: map[string]map[string]*offline.PriceEntry{
			"uuid-0001": {
				"ABU": {Regular: 0.27, Cond: "NM", Qty: 4,
					Conditions: map[string]float64{"NM": 0.27}},
			},
			"uuid-0004": {
				"CK": {Regular: 0.55},
			},
		},
	}
}

func emptyPayload() *offline.SetPayload {
	return &offline.SetPayload{
		SetCode:  "MTY",
		Snapshot: time.Unix(1770000000, 0).UTC(),
		Retail:   map[string]map[string]*offline.PriceEntry{},
		Buylist:  map[string]map[string]*offline.PriceEntry{},
	}
}

// entryJSON mirrors the JS decoder's flag-driven field presence rules.
func entryJSON(e *offline.PriceEntry) map[string]any {
	m := map[string]any{}
	if e.Regular > 0 {
		m["regular"] = e.Regular
	}
	if e.Foil > 0 {
		m["foil"] = e.Foil
	}
	if e.Etched > 0 {
		m["etched"] = e.Etched
	}
	if e.Sealed > 0 {
		m["sealed"] = e.Sealed
	}
	if e.Qty > 0 || e.QtyFoil > 0 || e.QtyEtched > 0 || e.QtySealed > 0 {
		m["qty"] = e.Qty
		m["qtyFoil"] = e.QtyFoil
		m["qtyEtched"] = e.QtyEtched
		m["qtySealed"] = e.QtySealed
	}
	if e.Cond != "" {
		m["cond"] = e.Cond
	}
	if len(e.Conditions) > 0 {
		m["conditions"] = e.Conditions
	}
	if len(e.Quantities) > 0 {
		m["quantities"] = e.Quantities
	}
	return m
}

func sectionJSON(section map[string]map[string]*offline.PriceEntry) map[string]any {
	out := map[string]any{}
	for uuid, byStore := range section {
		entries := map[string]any{}
		for store, e := range byStore {
			entries[store] = entryJSON(e)
		}
		out[uuid] = entries
	}
	return out
}

func writeFixture(dir, name string, p *offline.SetPayload) {
	data, err := offline.Encode(p)
	if err != nil {
		log.Fatal(err)
	}
	// Round-trip through Decode so the JSON reflects the exact wire content.
	decoded, err := offline.Decode(data)
	if err != nil {
		log.Fatal(err)
	}
	doc := map[string]any{
		"setCode":      decoded.SetCode,
		"snapshotUnix": decoded.Snapshot.Unix(),
		"retail":       sectionJSON(decoded.Retail),
		"buylist":      sectionJSON(decoded.Buylist),
	}
	j, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".bin"), data, 0644); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".expected.json"), append(j, '\n'), 0644); err != nil {
		log.Fatal(err)
	}
	log.Printf("%s: %d binary bytes", name, len(data))
}

func main() {
	dir := filepath.Join("tests", "offline", "fixtures")
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Fatal(err)
	}
	writeFixture(dir, "sample", samplePayload())
	writeFixture(dir, "empty", emptyPayload())
}
