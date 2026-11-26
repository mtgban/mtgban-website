package salesvelocity

import (
	"context"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
	"weak"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/go-mtgban/mtgban"
)

var gradedNow = time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC)

func gradedMatch(productID int64, printing string) string {
	switch productID {
	case 1:
		return "charizard"
	case 2:
		return "pikachu"
	case 3:
		return "promo"
	case 4:
		return "pikachu5"
	case 5:
		return "hoopa"
	}
	return ""
}

func gradedNumbers(cardID string) catalogCard {
	switch cardID {
	case "charizard":
		return catalogCard{printedNumber: printedNumber{number: "4", total: "102"}}
	case "pikachu":
		return catalogCard{printedNumber: printedNumber{number: "9"}}
	case "pikachu5":
		return catalogCard{printedNumber: printedNumber{number: "5"}}
	case "hoopa":
		return catalogCard{printedNumber: printedNumber{number: "155"}, nonEnglish: true}
	}
	return catalogCard{}
}

func gradedSale(product int64, company string, grade float64, label string, days int, cents int64, title string) gradedRow {
	return gradedRow{
		ProductID: product,
		Printing:  "Holofoil",
		Company:   company,
		Grade:     grade,
		Label:     label,
		Cents:     cents,
		At:        gradedNow.AddDate(0, 0, -days),
		Source:    "ebay",
		ListingID: fmt.Sprintf("%d-%d-%d", product, days, cents),
		Title:     title,
	}
}

var psa10 = mtgban.Slab{Grader: "PSA", Score: 10}

func TestNumberDigits(t *testing.T) {
	for number, want := range map[string]string{
		"004/102": "4",
		"4":       "4",
		"GG48":    "48",
		"TG05":    "5",
		"177a":    "177",
		"SV049":   "49",
		"000":     "0",
		"PW":      "",
		"":        "",
	} {
		got := numberDigits(number)
		if got != want {
			t.Errorf("numberDigits(%q) = %q, want %q", number, got, want)
		}
	}
}

func TestTitleNumbers(t *testing.T) {
	for title, want := range map[string][]printedNumber{
		"Charizard 4/102 Base Set PSA 9":                  {{"4", "102"}},
		"Pokemon 2019 Charizard GX SV49/SV94 Shiny Vault": {{"49", "94"}},
		"Mew #GG10 / GG70 Crown Zenith PSA 10":            {{"10", "70"}},
		"Rayquaza Promos #177a /168 PSA 9":                {{"177", "168"}},
		"2003 Skyridge Moltres H20/144 PSA 9":             {{"20", "144"}},
		"Detective Pikachu Greninja Holo 9/28 PSA 9":      {{"9", "28"}},
		"Captain Pikachu PSA 10":                          nil,
		"Charizard 1999 Base Set Holo PSA 10/10":          nil,
		"Wartortle 151 PSA 10 Gem Mint 171/165":           {{"171", "165"}},
		"Umbreon Neo Discovery 13 BGS 9.5 9.5/9.5/9.5/10": nil,
		"Mega Charizard X EX #023 Promo 10/10/10 Subs":    nil,
		"TAG Gem Mint 10 Mewtwo GX SV59 RANK #8/51":       nil,
		"Galarian Moltres Zapdos Articuno 181/182/183":    {{"181", "182"}},
	} {
		got := titleNumbers(title)
		if !slices.Equal(got, want) {
			t.Errorf("titleNumbers(%q) = %q, want %q", title, got, want)
		}
	}
}

func TestCleanTitle(t *testing.T) {
	for title, want := range map[string]string{
		"Sold  Aug 5, 2025Poliwhirl 176/165 PSA 10 Gem MintOpens in a new window or tab":          "Poliwhirl 176/165 PSA 10 Gem Mint",
		"Sold  Oct 7, 20252022 Pokemon Pikachu PSA 9Opens in a new window or tabConsign with us!": "2022 Pokemon Pikachu PSA 9",
		"2002 Pokemon Legendary Collection Dark Wartortle #39 CGC 10 GEM MINT":                    "2002 Pokemon Legendary Collection Dark Wartortle #39 CGC 10 GEM MINT",
	} {
		got := cleanTitle(title)
		if got != want {
			t.Errorf("cleanTitle(%q) = %q, want %q", title, got, want)
		}
	}
}

func TestNamesNumber(t *testing.T) {
	cases := []struct {
		title, digits string
		want          bool
	}{
		{"Charizard 4/102 Base Set PSA 9", "4", true},
		{"Charizard #004 Base Set", "4", true},
		// The grade's digits are not the card's.
		{"Charizard Base Set PSA 4", "4", false},
		{"Charizard Base Set CGC 9.5", "9", false},
		{"Pikachu Gem Mint 10", "10", false},
		{"Charizard 1999 Base Set PSA 10", "4", false},
	}
	for _, c := range cases {
		got := namesNumber(c.title, c.digits)
		if got != c.want {
			t.Errorf("namesNumber(%q, %q) = %v, want %v", c.title, c.digits, got, c.want)
		}
	}
}

func TestGradedSlab(t *testing.T) {
	cases := []struct {
		company string
		grade   float64
		label   string
		want    mtgban.Slab
		listed  bool
	}{
		{"PSA", 10, "", psa10, true},
		{"CGC", 10, "gemMint", mtgban.Slab{Grader: "CGC", Score: 10}, true},
		{"CGC", 10, "pristine", mtgban.Slab{Grader: "CGC", Score: 10, Label: "Pristine"}, true},
		{"BGS", 10, "blackLabel", mtgban.Slab{Grader: "BGS", Score: 10, Label: "Black Label"}, true},
		{"BGS", 9.5, "", mtgban.Slab{Grader: "BGS", Score: 9.5}, true},
		{"tag", 8, "", mtgban.Slab{Grader: "TAG", Score: 8}, true},
		// No group on the Graded page for these.
		{"SGC", 10, "", mtgban.Slab{}, false},
		{"ACE", 10, "", mtgban.Slab{}, false},
		{"PSA", 10, "someNewTier", mtgban.Slab{}, false},
	}
	for _, c := range cases {
		got, listed := gradedSlab(c.company, c.grade, c.label)
		if got != c.want || listed != c.listed {
			t.Errorf("gradedSlab(%q, %v, %q) = %+v, %v; want %+v, %v", c.company, c.grade, c.label, got, listed, c.want, c.listed)
		}
	}
}

func TestGradedBuilderKeepsNewest(t *testing.T) {
	gb := newGradedBuilder(gradedMatch, gradedNumbers, gradedNow)
	for i := range recentDepth + 5 {
		gb.add(gradedSale(1, "PSA", 10, "", i, int64(50000+i), "Charizard 4/102 Base Set PSA 10"))
	}

	grade := gb.snapshot().For("charizard").Grades[psa10]
	if grade == nil {
		t.Fatal("no PSA 10 sales kept")
	}
	if len(grade.Sales) != recentDepth {
		t.Fatalf("kept %d sales, want %d", len(grade.Sales), recentDepth)
	}
	for i := 1; i < len(grade.Sales); i++ {
		if grade.Sales[i].At > grade.Sales[i-1].At {
			t.Errorf("sale %d is newer than sale %d", i, i-1)
		}
	}
	if grade.Sales[0].Cents != 50000 {
		t.Errorf("newest sale at %d cents, want 50000", grade.Sales[0].Cents)
	}
	if gb.st.kept != recentDepth+5 {
		t.Errorf("counted %d sales kept, want every one read", gb.st.kept)
	}
}

func TestGradedBuilderDropsAnotherNumber(t *testing.T) {
	gb := newGradedBuilder(gradedMatch, gradedNumbers, gradedNow)
	gb.add(gradedSale(1, "PSA", 8, "", 1, 40000, "Charizard 4/102 Base Set PSA 8"))
	// Base Set 2's Charizard: the same digits over another total.
	gb.add(gradedSale(1, "PSA", 8, "", 2, 20000, "Charizard 4/130 Base Set 2 PSA 8"))
	gb.add(gradedSale(1, "PSA", 8, "", 4, 21000, "Charizard 11/108 Evolutions PSA 8"))
	// A title with no number is kept.
	gb.add(gradedSale(1, "PSA", 8, "", 3, 41000, "Charizard Base Set Holo PSA 8"))

	snap := gb.snapshot()
	grade := snap.For("charizard").Grades[mtgban.Slab{Grader: "PSA", Score: 8}]
	if grade == nil || len(grade.Sales) != 2 {
		t.Fatalf("kept %+v, want the two sales naming no other number", grade)
	}
	if gb.st.otherNumber != 2 {
		t.Errorf("dropped %d naming another number, want 2", gb.st.otherNumber)
	}
}

func TestGradedBuilderDropsCatchAllCard(t *testing.T) {
	gb := newGradedBuilder(gradedMatch, gradedNumbers, gradedNow)
	for i := range catchAllSales {
		title := "Captain Pikachu Gem Pack PSA 10"
		if i < 2 {
			title = "Pikachu World Collection 9 PSA 10"
		}
		gb.add(gradedSale(2, "PSA", 10, "", i, 10000, title))
	}
	// The day eBay's sold date prints is not the card's number.
	for i := range catchAllSales {
		gb.add(gradedSale(4, "PSA", 10, "", i, 10000, "Sold  Aug 5, 2025Captain Pikachu Gem Pack PSA 10Opens in a new window or tab"))
	}
	// Few sales: too few to judge, kept.
	for i := range 3 {
		gb.add(gradedSale(3, "PSA", 10, "", i, 10000, "Some Promo PSA 10"))
	}

	snap := gb.snapshot()
	if snap.For("pikachu") != nil {
		t.Error("kept a card whose titles rarely carry its number")
	}
	if snap.For("pikachu5") != nil {
		t.Error("read the sold date's day as the card's number")
	}
	if snap.For("promo") == nil {
		t.Error("dropped a card with no number to judge it by")
	}
	if gb.st.catchAllCards != 2 || gb.st.catchAllSales != 2*catchAllSales {
		t.Errorf("dropped %d sales on %d cards, want %d on 2", gb.st.catchAllSales, gb.st.catchAllCards, 2*catchAllSales)
	}
}

func TestGradedBuilderSkipsUnlistedAndUnmatched(t *testing.T) {
	gb := newGradedBuilder(gradedMatch, gradedNumbers, gradedNow)
	gb.add(gradedSale(9, "PSA", 10, "", 1, 10000, "Unknown card"))
	gb.add(gradedSale(1, "SGC", 10, "", 1, 10000, "Charizard 4/102 SGC 10"))
	gb.add(gradedSale(1, "PSA", 10, "", 1, 0, "Charizard 4/102 PSA 10"))

	snap := gb.snapshot()
	if len(snap.Cards) != 0 {
		t.Errorf("kept %d cards, want none", len(snap.Cards))
	}
	if gb.st.unmatched != 2 || gb.st.ungraded != 1 {
		t.Errorf("unmatched %d, ungraded %d; want 2, 1", gb.st.unmatched, gb.st.ungraded)
	}
	report := gb.st.report(0)
	if !strings.Contains(report, "1 of other graders") {
		t.Errorf("report %q does not name the other graders", report)
	}
}

func TestGradeSalesGroup(t *testing.T) {
	var sales []GradedSale
	for i := range RecentShown + 2 {
		sales = append(sales, GradedSale{At: uint32(gradedNow.AddDate(0, 0, -i).Unix()), Cents: 50000, ListingID: fmt.Sprint(i)})
	}
	sales[0] = GradedSale{At: uint32(gradedNow.Unix()), Cents: 51500, ListingID: "357409617632"}
	sales[1].Fanatics, sales[1].ListingID = true, "fanatics:WEEKLY5559473"
	// A best offer's price is the ask: listed, not in the average.
	sales[2].BestOffer, sales[2].Cents = true, 999900

	group := (&GradeSales{Sales: sales}).Group("PSA 10")
	if group.Grade != "PSA 10" || !group.Slab || group.Link != "" {
		t.Errorf("group %+v", group)
	}
	if group.Avg != "502.50" {
		t.Errorf("avg %q, want 502.50", group.Avg)
	}
	if len(group.Shown) != RecentShown || len(group.More) != 2 {
		t.Errorf("shown %d, more %d; want %d, 2", len(group.Shown), len(group.More), RecentShown)
	}
	ebay, fanatics, offer := group.Shown[0], group.Shown[1], group.Shown[2]
	if ebay.Source != "eBay" || ebay.Link != "https://www.ebay.com/itm/357409617632" || ebay.Price != "515.00" || ebay.Date != "2026-11-26" {
		t.Errorf("eBay line %+v", ebay)
	}
	if fanatics.Source != "Fanatics" || fanatics.Link != "https://sales-history.fanaticscollect.com/items/WEEKLY5559473" {
		t.Errorf("Fanatics line %+v", fanatics)
	}
	if offer.Qty != "offer" || offer.Note == "" || ebay.Qty != "" {
		t.Errorf("best offer marked %q, plain sale marked %q", offer.Qty, ebay.Qty)
	}

	allOffers := (&GradeSales{Sales: []GradedSale{{Cents: 100, BestOffer: true}}}).Group("CGC 10 Pristine")
	if allOffers.Avg != "" {
		t.Errorf("avg of best offers alone %q, want none", allOffers.Avg)
	}
}

func TestGradedVelocity(t *testing.T) {
	gb := newGradedBuilder(gradedMatch, gradedNumbers, gradedNow)
	title := "Charizard 4/102 Base Set"
	gb.add(gradedSale(1, "PSA", 10, "", 0, 200000, title))
	gb.add(gradedSale(1, "PSA", 9, "", 0, 80000, title))
	fanatics := gradedSale(1, "CGC", 10, "pristine", 3, 150000, title)
	fanatics.Source = "fanatics"
	gb.add(fanatics)
	// Out of the window: on record, not in the rate.
	gb.add(gradedSale(1, "PSA", 10, "", Window, 190000, title))
	card := gb.snapshot().For("charizard")
	if card.Sales != 3 || card.Days != 2 || card.Fanatics != 1 {
		t.Errorf("sales %d, days %d, Fanatics %d; want 3, 2, 1", card.Sales, card.Days, card.Fanatics)
	}

	name := func(slab mtgban.Slab) string { return fmt.Sprintf("%s %g %s", slab.Grader, slab.Score, slab.Label) }
	rate, detail := card.Velocity(gradedNow, name)
	if rate != "0.1/day" {
		t.Errorf("rate %q, want 0.1/day", rate)
	}
	for _, want := range []string{"|sales|3|days|2/30", "|eBay|2|Fanatics|1", "\n\n|last sale|$2000.00 PSA 10  · Nov 26"} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail %q has no %q", detail, want)
		}
	}

	quiet := &GradedCard{Last: GradedSale{At: uint32(gradedNow.AddDate(-1, 0, 0).Unix()), Cents: 5000}, LastSlab: psa10}
	rate, detail = quiet.Velocity(gradedNow, name)
	if rate != "0/day" || detail != "no sale in 30 days\n|last sale|$50.00 PSA 10  · Nov 26, 2025" {
		t.Errorf("quiet card: rate %q, detail %q", rate, detail)
	}
	var none *GradedCard
	rate, detail = none.Velocity(gradedNow, name)
	if rate != "" || detail != "" {
		t.Errorf("no card: rate %q, detail %q", rate, detail)
	}
}

func TestGradedStoreReloadsOnlyWhenStale(t *testing.T) {
	var s GradedStore
	b := &matcher.Backend{}
	snap := &GradedSnapshot{Loaded: gradedNow, Backend: weak.Make(b)}
	s.Publish(snap)
	// Fresh and on the same backend: no query, so a nil database is fine.
	result, problem := s.Load(context.Background(), nil, b, "Pokemon", gradedNow.Add(GradedReload-time.Minute))
	if result != "" || problem != "" || s.Snapshot() != snap {
		t.Errorf("a fresh load read again: %q, %q", result, problem)
	}
	runtime.KeepAlive(b)
}

func TestGradedTitleFilters(t *testing.T) {
	cases := []struct {
		title             string
		foreign, lot      bool
		guessed, contrary string
	}{
		{title: "Mega Tokyo's Pikachu 098/XY-P Japanese PSA 10", foreign: true},
		{title: "Pikachu 153 5th Anniversary CS Chinese PSA 10", foreign: true},
		{title: "Blastoise 1998 JPN Pikachu Records Promo BGS 7.5", foreign: true},
		{title: "Charizard 4/102 Base Set German PSA 9", foreign: true},
		{title: "Charizard 4/102 Base Set PSA 9"},
		{title: "Moltres Holo 2003 Skyridge PSA 9 Lot", lot: true},
		{title: "Charizard 3 pcs PSA 10", lot: true},
		// Single cards whose names read like lots.
		{title: "2023 POKEMON SVP PROMO #066 IRON BUNDLE PSA 10"},
		{title: "Prismatic Evolutions Costco Exclusive 8-Tin Bundle Leafeon #005 CGC 10"},
		{title: "PSA 10 Pikachu V-Union [Set of 4] SWSH Promo"},
		{title: "Lotad 70/108 PSA 10"},
		// A guessed printing the title names against.
		{title: "2002 Neo Destiny 1st Edition Holo Dark Crobat #2 PSA 7", guessed: "Unlimited Holofoil", contrary: "yes"},
		{title: "Meganium 11/111 Neo Genesis Holo 1st Edtition CGC 10", guessed: "1st Edition Holofoil"},
		{title: "Sabrina's Gastly 1ED 96/132 Gym Challenge CGC 9", guessed: "1st Edition"},
		{title: "Fossil Aerodactyl 1/62 Holo 1st PSA 8", guessed: "1st Edition Holofoil"},
		{title: "2000 POKEMON ROCKET #2 DARK ARBOK-HOLO PSA 7", guessed: "1st Edition Holofoil", contrary: "yes"},
		{title: "Gyarados Reverse Holo EX Holon Phantoms PSA 8", guessed: "Holofoil", contrary: "yes"},
		{title: "Gyarados Reverse Holo EX Holon Phantoms PSA 8", guessed: "Reverse Holofoil"},
		{title: "2026 Mega Promo First Partner Illustration S2 Grookey #52 CGC 9", guessed: "Holofoil"},
	}
	for _, c := range cases {
		if got := titleForeign.MatchString(c.title); got != c.foreign {
			t.Errorf("%q: another language %v, want %v", c.title, got, c.foreign)
		}
		if got := titleLot.MatchString(c.title); got != c.lot {
			t.Errorf("%q: lot %v, want %v", c.title, got, c.lot)
		}
		if c.guessed != "" {
			got := contradicts(c.title, c.guessed)
			if got != (c.contrary != "") {
				t.Errorf("%q against %q: contradicts %v", c.title, c.guessed, got)
			}
		}
	}
}

func TestGradedBuilderDropsByTitle(t *testing.T) {
	gb := newGradedBuilder(gradedMatch, gradedNumbers, gradedNow)
	gb.add(gradedSale(1, "PSA", 9, "", 1, 10000, "Charizard 4/102 Japanese PSA 9"))
	// A Japanese card the catalog carries keeps its Japanese sales.
	gb.add(gradedSale(5, "PSA", 9, "", 1, 10000, "Hoopa 155/XY-P Promo Japanese PSA 9"))
	gb.add(gradedSale(1, "PSA", 9, "", 2, 10000, "Charizard 4/102 PSA 9 Lot"))
	guess := gradedSale(1, "PSA", 9, "", 3, 10000, "Charizard 4/102 1st Edition PSA 9")
	guess.PrintingSource = "default"
	gb.add(guess)
	// The same words with the printing read off the sale stay.
	named := gradedSale(1, "PSA", 9, "", 4, 10000, "Charizard 4/102 1st Edition PSA 9")
	named.PrintingSource = "per_printing"
	gb.add(named)

	grade := gb.snapshot().For("charizard").Grades[mtgban.Slab{Grader: "PSA", Score: 9}]
	if grade == nil || len(grade.Sales) != 1 {
		t.Fatalf("kept %+v, want the one sale whose printing was read", grade)
	}
	if gb.snapshot().For("hoopa") == nil {
		t.Error("dropped a Japanese card's Japanese sale")
	}
	if gb.st.foreign != 1 || gb.st.lots != 1 || gb.st.guessed != 1 {
		t.Errorf("foreign %d, lots %d, guessed %d; want 1 each", gb.st.foreign, gb.st.lots, gb.st.guessed)
	}
}
