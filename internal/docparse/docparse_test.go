package docparse

import (
	"errors"
	"reflect"
	"testing"
)

func TestPartitionEntries(t *testing.T) {
	errEntry := Entry{MismatchError: errors.New("not found")}
	s1 := Entry{CardID: "single1"}
	s2 := Entry{CardID: "single2"}
	sealed1 := Entry{CardID: "sealed1"}
	sealedIDs := []string{"sealed1", "sealed2"}

	tests := []struct {
		name         string
		entries      []Entry
		wantSingles  []Entry
		wantSealed   []Entry
		wantNotFound []Entry
	}{
		{
			name:        "mixed splits by membership",
			entries:     []Entry{s1, sealed1},
			wantSingles: []Entry{s1},
			wantSealed:  []Entry{sealed1},
		},
		{
			name:        "singles only",
			entries:     []Entry{s1, s2},
			wantSingles: []Entry{s1, s2},
		},
		{
			name:         "errors go to notFound with sealed",
			entries:      []Entry{sealed1, errEntry},
			wantSealed:   []Entry{sealed1},
			wantNotFound: []Entry{errEntry},
		},
		{
			name:         "errors go to notFound with singles",
			entries:      []Entry{s1, errEntry},
			wantSingles:  []Entry{s1},
			wantNotFound: []Entry{errEntry},
		},
		{
			name:         "only errors go to notFound",
			entries:      []Entry{errEntry},
			wantNotFound: []Entry{errEntry},
		},
		{
			name:         "mixed with errors",
			entries:      []Entry{s1, sealed1, errEntry},
			wantSingles:  []Entry{s1},
			wantSealed:   []Entry{sealed1},
			wantNotFound: []Entry{errEntry},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotSingles, gotSealed, gotNotFound := PartitionEntries(tc.entries, sealedIDs)
			if !reflect.DeepEqual(gotSingles, tc.wantSingles) {
				t.Errorf("singles = %v, want %v", gotSingles, tc.wantSingles)
			}
			if !reflect.DeepEqual(gotSealed, tc.wantSealed) {
				t.Errorf("sealed = %v, want %v", gotSealed, tc.wantSealed)
			}
			if !reflect.DeepEqual(gotNotFound, tc.wantNotFound) {
				t.Errorf("notFound = %v, want %v", gotNotFound, tc.wantNotFound)
			}
		})
	}
}

func TestParseHeaderMtgbanExport(t *testing.T) {
	p := &Parser{}
	header := []string{"Key", "Name", "Edition", "Finish", "Number", "Rarity", "Conditions", "Price", "Quantity", "URL", "Seller", "Bundle", "Original Id", "Instance Id"}
	indexMap, err := p.ParseHeader(header)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	want := map[string]int{
		"id": 0, "cardName": 1, "edition": 2, "printing": 3,
		"variant": 4, "conditions": 6, "price": 7, "quantity": 8,
	}
	for field, idx := range want {
		if got, found := indexMap[field]; !found || got != idx {
			t.Errorf("%s = %d (found %v), want %d", field, got, found, idx)
		}
	}
}

func TestGetQuantity(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int
		ok   bool
	}{
		{"4", 4, true},
		{"4x", 4, true},
		{" 12x ", 0, false}, // suffix strip happens before trim
		{"12 ", 12, true},
		{"x", 0, false},
		{"", 0, false},
	} {
		got, err := GetQuantity(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("GetQuantity(%q) = %d, %v; want %d, ok=%v", tc.in, got, err, tc.want, tc.ok)
		}
	}
}

func TestParseRowInfersConditionFromSKU(t *testing.T) {
	p := &Parser{
		TCGSkuToUUID: func(sku string) string { return "uuid-" + sku },
		TCGSkuToCondition: func(sku string) string {
			if sku == "SKU-SP" {
				return "SP"
			}
			return ""
		},
	}

	tests := []struct {
		name     string
		indexMap map[string]int
		record   []string
		want     string
	}{
		{
			"inferred from SKU when no condition column",
			map[string]int{"cardName": 0, "tcgSku": 1},
			[]string{"Some Card", "SKU-SP"},
			"SP",
		},
		{
			"explicit condition column wins over the SKU",
			map[string]int{"cardName": 0, "tcgSku": 1, "conditions": 2},
			[]string{"Some Card", "SKU-SP", "Heavily Played"},
			"HP",
		},
		{
			"unknown SKU leaves the condition blank",
			map[string]int{"cardName": 0, "tcgSku": 1},
			[]string{"Some Card", "SKU-UNKNOWN"},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Card matching needs the datastore (not loaded here); the condition
			// is inferred before Match, so the resolution error is irrelevant.
			res, _ := p.ParseRow(tt.indexMap, tt.record)
			if res.OriginalCondition != tt.want {
				t.Errorf("OriginalCondition = %q, want %q", res.OriginalCondition, tt.want)
			}
		})
	}
}

// TestParseHeaderCardmarketID pins which columns name a Cardmarket product
// and, as much, which ones do not: the mtgban export's own "Original Id" and
// "Instance Id" carry the word without naming the marketplace, and a column
// naming the marketplace without an id is a price.
func TestParseHeaderCardmarketID(t *testing.T) {
	for _, tt := range []struct {
		desc   string
		header []string
		want   int
		found  bool
	}{
		{"the column mkmhtml2csv writes", []string{"uuid", "card_name", "mcm_id"}, 2, true},
		// The site spells the marketplace MKM everywhere else - MKMTrend,
		// MKMLow - so a hand-written list is as likely to say that as mcm.
		{"spelled the way the site spells it", []string{"Name", "MKM Id"}, 1, true},
		{"no separator, mkm", []string{"Name", "mkmId"}, 1, true},
		{"spelled out", []string{"Name", "Edition", "Cardmarket Id"}, 2, true},
		{"no separator", []string{"Name", "mcmId"}, 1, true},
		{"the mtgban export's own id columns", []string{"Key", "Name", "Original Id", "Instance Id"}, 0, false},
		{"a price is not an id", []string{"Name", "Edition", "Cardmarket Price"}, 0, false},
		// "mkm" and "id" inside a header naming something else: a price
		// read as a product id prices the row as whatever card that is.
		{"a price guide", []string{"Name", "MKM Price Guide"}, 0, false},
		{"a price paid", []string{"Name", "Price Paid (Cardmarket)"}, 0, false},
		{"another cardmarket id space", []string{"Name", "mcmMetaId", "MKM Expansion Id"}, 0, false},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			p := &Parser{}
			indexMap, err := p.ParseHeader(tt.header)
			if err != nil {
				t.Fatalf("ParseHeader: %v", err)
			}
			got, found := indexMap["mkmID"]
			if found != tt.found {
				t.Fatalf("mkmID found = %v, want %v (map %v)", found, tt.found, indexMap)
			}
			if found && got != tt.want {
				t.Errorf("mkmID = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestParseRowResolvesCardmarketID pins that the hook fills an id nothing
// else answered with, and only then.
func TestParseRowResolvesCardmarketID(t *testing.T) {
	resolving := &Parser{
		MKMIDToUUID: func(mkmID string) string {
			if mkmID == "265854" {
				return "uuid-from-mkm"
			}
			return ""
		},
	}

	for _, tt := range []struct {
		desc     string
		parser   *Parser
		indexMap map[string]int
		record   []string
		want     string
	}{
		{
			"a known product id resolves",
			resolving,
			map[string]int{"cardName": 0, "mkmID": 1},
			[]string{"Some Card", "265854"},
			"uuid-from-mkm",
		},
		{
			"an unknown product id resolves to nothing",
			resolving,
			map[string]int{"cardName": 0, "mkmID": 1},
			[]string{"Some Card", "999999"},
			"",
		},
		{
			"a uuid column wins over the product id",
			resolving,
			map[string]int{"cardName": 0, "mkmID": 1, "id": 2},
			[]string{"Some Card", "265854", "uuid-explicit"},
			"uuid-explicit",
		},
		{
			"a spreadsheet's decimal is not part of the id",
			resolving,
			map[string]int{"cardName": 0, "mkmID": 1},
			[]string{"Some Card", "265854.0"},
			"uuid-from-mkm",
		},
		{
			"anything else is passed on as it came",
			resolving,
			map[string]int{"cardName": 0, "mkmID": 1},
			[]string{"Some Card", "265854.5"},
			"",
		},
		{
			"without the hook the column is ignored",
			&Parser{},
			map[string]int{"cardName": 0, "mkmID": 1},
			[]string{"Some Card", "265854"},
			"",
		},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			// Matching needs the datastore (not loaded here); the id is
			// resolved before Match, so its failure is irrelevant.
			res, _ := tt.parser.ParseRow(tt.indexMap, tt.record)
			if res.Card.ID != tt.want {
				t.Errorf("Card.ID = %q, want %q", res.Card.ID, tt.want)
			}
		})
	}
}

// The cm-banner extension writes a Cardmarket offers page into its last
// column, and the upload results turn that into the link on the loaded
// price. The column is named to land in "notes" because that is the field
// the results already carry through a round trip - nothing in the matcher
// was widened for it, since a case matching "url" would also swallow the
// image-url columns other exports carry.
//
// This is the join between two repositories, so it is pinned here: the
// header is cm-banner's, and a change that stops it reaching notes breaks
// a feature whose other half is not in this tree.
func TestBannerHeaderReachesNotes(t *testing.T) {
	header := []string{
		"mcm_id", "card_name", "edition", "condition",
		"foil", "quantity", "price_usd", "article_id", "mkm_notes",
	}

	p := &Parser{}
	indexMap, err := p.ParseHeader(header)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}

	idx, found := indexMap["notes"]
	if !found {
		t.Fatal("mkm_notes does not reach the notes column")
	}
	if header[idx] != "mkm_notes" {
		t.Errorf("notes is column %d (%q), want mkm_notes", idx, header[idx])
	}

	// And the columns beside it still land where they did.
	for key, want := range map[string]string{
		"mkmID":      "mcm_id",
		"cardName":   "card_name",
		"edition":    "edition",
		"conditions": "condition",
		"printing":   "foil",
		"quantity":   "quantity",
		"price":      "price_usd",
	} {
		at, ok := indexMap[key]
		if !ok {
			t.Errorf("%s reaches nothing", key)
			continue
		}
		if header[at] != want {
			t.Errorf("%s is column %q, want %q", key, header[at], want)
		}
	}

	// article_id is carried for tracing and is meant to reach nothing.
	if at, ok := indexMap["id"]; ok && header[at] == "article_id" {
		t.Error("article_id was read as an identifier")
	}
}
