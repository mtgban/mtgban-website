package salesvelocity

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"weak"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/go-mtgban/mtgban"
)

// The graded sales are pokemonpricetracker's eBay and Fanatics Collect sales
// of slabs, which the newspaper pulls. Its terms let the site show them on
// its own pages and nowhere else: never through the API or an export
// (docs/adr/0012-graded-sales.md).

// GradedQuery is game's graded sales since $2, each one filed under a single
// product: a listing the source filed under several is some other card's too.
// A listing the source stopped returning is kept: it aged out of its window.
const GradedQuery = `
	SELECT g.tcgplayer_product_id, g.printing, coalesce(g.printing_source, ''), g.grading_company, g.grade,
	       coalesce(g.grade_label, ''), round(g.price * 100)::bigint, g.sold_at, g.source, g.listing_id,
	       coalesce(g.best_offer_accepted, false), g.title
	  FROM pptgradedsalemodel g
	 WHERE g.sold_at >= $2
	   AND g.tcgplayer_product_id IN (SELECT product_id FROM tcgplayerproductinfomodel WHERE game_name = $1)
	   AND NOT EXISTS (SELECT 1 FROM pptgradedsalemodel o
	                    WHERE o.source = g.source AND o.listing_id = g.listing_id
	                      AND o.tcgplayer_product_id <> g.tcgplayer_product_id)`

// GradedAnyQuery says whether game has a graded sale since $2: about a second
// where it has none, against GradedQuery reading the whole table to say so.
const GradedAnyQuery = `
	SELECT EXISTS (SELECT 1 FROM tcgplayerproductinfomodel i
	                 JOIN pptgradedsalemodel g ON g.tcgplayer_product_id = i.product_id
	                WHERE i.game_name = $1 AND g.sold_at >= $2)`

// GradedSince is the oldest sale read, where the site's price history starts.
var GradedSince = time.Date(2025, time.September, 1, 0, 0, 0, 0, time.UTC)

const (
	// A card with this many sales or more, few of whose titles carry its
	// number, is one the source files unrelated sales under.
	catchAllSales = 20
	catchAllShare = 0.2

	fanaticsSource = "fanatics"
)

// gradedLabels are the source's slab tiers, as the stores' slabs spell them;
// a Gem Mint 10 is the plain score.
var gradedLabels = map[string]string{
	"":           "",
	"gemMint":    "",
	"pristine":   "Pristine",
	"blackLabel": "Black Label",
	"perfect":    "Perfect",
}

// gradedGraders are the graders the Graded page lists slabs under.
var gradedGraders = []string{"PSA", "BGS", "CGC", "TAG"}

// GradedSale is one sold slab.
type GradedSale struct {
	// Seconds since the epoch, UTC.
	At    uint32
	Cents uint32
	// Fanatics is a Fanatics Collect sale, else an eBay one.
	Fanatics bool
	// BestOffer is an eBay sale whose offer was accepted: Cents is then the
	// asking price, more than the buyer paid.
	BestOffer bool
	ListingID string
}

// GradeSales is one grade's newest sales of a card, newest first, as many as
// the recent orders keep of a condition.
type GradeSales struct {
	Sales []GradedSale
}

// GradedCard is one card's graded sales: the newest per slab, and its
// velocity over Window days, every slab together.
type GradedCard struct {
	Grades map[mtgban.Slab]*GradeSales
	// The sales in the window, the days with one, and Fanatics Collect's
	// share of them; eBay made the rest.
	Sales, Days, Fanatics int
	// The newest sale, of any age and slab, and its slab.
	Last     GradedSale
	LastSlab mtgban.Slab
}

// GradedSnapshot is the loaded sales, by card uuid.
type GradedSnapshot struct {
	Cards map[string]*GradedCard
	// The window's last day.
	Day     time.Time
	Loaded  time.Time
	Backend weak.Pointer[matcher.Backend]
}

// For is the card's sales, nil when none were loaded.
func (s *GradedSnapshot) For(cardID string) *GradedCard {
	if s == nil {
		return nil
	}
	return s.Cards[cardID]
}

// GradedStore is the last load of the graded sales. The zero value is empty
// and ready to use.
type GradedStore struct {
	current atomic.Pointer[GradedSnapshot]
	loading atomic.Bool
}

// Snapshot is the last load, nil before the first.
func (s *GradedStore) Snapshot() *GradedSnapshot {
	return s.current.Load()
}

// Publish makes snap the last load.
func (s *GradedStore) Publish(snap *GradedSnapshot) {
	s.current.Store(snap)
}

// GradedReload is how old a load gets before Load reads again; a load matched
// against another backend is read again at once.
const GradedReload = 6 * time.Hour

// Load reads game's graded sales into a new snapshot, unless the last one is
// on b and younger than GradedReload; a game with none gets an empty one
// without the full read. A failure keeps the last one for the
// next run to retry.
func (s *GradedStore) Load(ctx context.Context, db *sql.DB, b *matcher.Backend, game string, now time.Time) (result, problem string) {
	if !s.loading.CompareAndSwap(false, true) {
		return "", ""
	}
	defer s.loading.Store(false)

	current := s.current.Load()
	if current != nil && current.Backend == weak.Make(b) && now.Sub(current.Loaded) < GradedReload {
		return "", ""
	}

	found, err := anyGraded(ctx, db, game)
	if err != nil {
		return gradedFailure(err)
	}
	if !found {
		s.current.Store(&GradedSnapshot{Cards: map[string]*GradedCard{}, Day: startOfDay(now), Loaded: now, Backend: weak.Make(b)})
		return "", ""
	}

	gb := newGradedBuilder(cardMatcher(b), cardFacts(b), now)
	err = scanGraded(ctx, db, game, gb)
	if err != nil {
		return gradedFailure(err)
	}

	snap := gb.snapshot()
	if len(snap.Cards) == 0 && gb.st.rows > 0 {
		return "", fmt.Sprintf("no cards kept of %d graded sales, keeping the previous load", gb.st.rows)
	}
	snap.Backend = weak.Make(b)
	s.current.Store(snap)

	result = gb.st.report(len(snap.Cards))
	log.Println("graded sales:", result)
	return result, ""
}

// gradedFailure is a load's result and problem for err: a note for the table
// missing or unreadable, a problem for any other error.
func gradedFailure(err error) (result, problem string) {
	note := recentUnavailable(err)
	if note != "" {
		return strings.Replace(note, "recent sales", "graded sales", 1), ""
	}
	log.Println("graded sales:", err)
	return "", "cannot read graded sales: " + err.Error()
}

// anyGraded is GradedAnyQuery's answer for game.
func anyGraded(ctx context.Context, q salesQuerier, game string) (bool, error) {
	rows, err := q.QueryContext(ctx, GradedAnyQuery, game, GradedSince)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	var found bool
	if rows.Next() {
		err = rows.Scan(&found)
		if err != nil {
			return false, err
		}
	}
	return found, rows.Err()
}

// gradedRow is one row of GradedQuery.
type gradedRow struct {
	ProductID int64
	Printing  string
	// How the source chose Printing: "default" is its guess at the card's
	// primary one, for a sale that names none.
	PrintingSource string
	Company        string
	Grade          float64
	Label          string
	Cents          int64
	At             time.Time
	Source         string
	ListingID      string
	BestOffer      bool
	Title          string
}

// scanGraded reads game's graded sales into gb one row at a time.
func scanGraded(ctx context.Context, q salesQuerier, game string, gb *gradedBuilder) error {
	rows, err := q.QueryContext(ctx, GradedQuery, game, GradedSince)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var row gradedRow
		err := rows.Scan(&row.ProductID, &row.Printing, &row.PrintingSource, &row.Company, &row.Grade,
			&row.Label, &row.Cents, &row.At, &row.Source, &row.ListingID, &row.BestOffer, &row.Title)
		if err != nil {
			return err
		}
		gb.add(row)
	}
	return rows.Err()
}

// printedNumber is a card's collector number as a title can spell it, each
// part as numberDigits reads it: "4" of "102" for Base Set's 004/102.
type printedNumber struct {
	number, total string
}

// catalogCard is what the catalog says of the card a sale is filed under: its
// printed number, and whether it is a card printed in another language.
type catalogCard struct {
	printedNumber
	nonEnglish bool
}

// cardFacts is a card's catalogCard, empty for a card the backend lacks. A
// Japanese promo's total (XY-P, SM-P, S-P) marks it, the datastore giving it
// no language.
func cardFacts(b *matcher.Backend) func(cardID string) catalogCard {
	return func(cardID string) catalogCard {
		co, err := b.GetUUID(cardID)
		if err != nil {
			return catalogCard{}
		}
		return catalogCard{
			printedNumber: printedNumber{number: numberDigits(co.Number), total: numberDigits(co.SetTotal)},
			nonEnglish:    co.Language != "English" || strings.HasSuffix(co.SetTotal, "-P"),
		}
	}
}

// fits reports whether a fraction a title spells is this number: the same
// digits, over the same total where the card prints one.
func (n printedNumber) fits(f printedNumber) bool {
	return f.number == n.number && (n.total == "" || f.total == n.total)
}

// numberDigits is the first run of digits in number, without leading zeros.
func numberDigits(number string) string {
	start := strings.IndexFunc(number, isDigit)
	if start < 0 {
		return ""
	}
	end := strings.IndexFunc(number[start:], func(r rune) bool { return !isDigit(r) })
	if end >= 0 {
		number = number[:start+end]
	}
	return orZero(strings.TrimLeft(number[start:], "0"))
}

func isDigit(r rune) bool { return r >= '0' && r <= '9' }

// orZero keeps a number that was all zeros as "0".
func orZero(digits string) string {
	if digits == "" {
		return "0"
	}
	return digits
}

var (
	// A collector number as titles print it, "4/102", "#SV49/SV94",
	// "GG10 / GG70": the card's digits, then the total's.
	titleFraction = regexp.MustCompile(`(?i)(?:^|[^0-9a-z.])[a-z]{0,4}([0-9]{1,3})[a-z]?\s*/\s*[a-z]{0,4}([0-9]{2,3})(?:[^0-9]|$)`)
	// A grade, or a TAG rank, whose digits name no card.
	titleGrade  = regexp.MustCompile(`(?i)\b(?:(?:psa|cgc|bgs|sgc|tag|ace|beckett|grade[d]?|gem\s*mint|mint|pristine)\s*(?:10|[1-9])(?:\.5)?(?:[^0-9/.]|$)|rank\s*#?\s*[0-9]+\s*/\s*[0-9]+)`)
	titleDigits = regexp.MustCompile(`[0-9]+`)
	// A copy in another language than English, which an English card's
	// sales cannot be: European copies print the English set's numbers.
	titleForeign = regexp.MustCompile(`(?i)\b(?:japanese|japan|jpn|korean|chinese|german|french|italian|spanish|portuguese)\b`)
	// More than one card sold together. Not "bundle", which names a card
	// (Iron Bundle) and the products single promos came in, nor "set of",
	// which names the V-Union cards printed in four pieces.
	titleLot = regexp.MustCompile(`(?i)\blot\b|\b[0-9]+\s*pcs\b`)
	// The printings a title can name against the source's guess: sellers
	// spell 1st Edition "1st", "1ED" or "first ed", and misspell the rest.
	// A bare "first" names promos, "First Partner".
	titleFirst   = regexp.MustCompile(`(?i)\b1st\b|\b1\s*ed\b|\bfirst\s*ed`)
	titleReverse = regexp.MustCompile(`(?i)\brev(?:erse|\.)?\s*(?:holo|foil)`)
	// What eBay's sold page wraps a title in, whose date names no card.
	titleSold  = regexp.MustCompile(`^Sold\s+[A-Z][a-z]{2} [0-9]{1,2}, [0-9]{4}`)
	titleOpens = regexp.MustCompile(`Opens in a new window or tab.*$`)
)

// titleNumbers are the collector numbers a title spells as fractions, its
// grade left out.
func titleNumbers(title string) []printedNumber {
	title = titleGrade.ReplaceAllString(title, " ")
	var numbers []printedNumber
	for _, m := range titleFraction.FindAllStringSubmatch(title, -1) {
		total := orZero(strings.TrimLeft(m[2], "0"))
		// Out of ten is a subgrade, "10/10/10", not a card.
		if total == "10" {
			continue
		}
		numbers = append(numbers, printedNumber{number: orZero(strings.TrimLeft(m[1], "0")), total: total})
	}
	return numbers
}

// cleanTitle is a listing's title without the sold date and link text eBay's
// page wraps it in.
func cleanTitle(title string) string {
	title = titleSold.ReplaceAllString(title, "")
	return titleOpens.ReplaceAllString(title, "")
}

// contradicts reports whether title names a printing against the one the
// source guessed: 1st Edition one way or the other, or a reverse holo.
func contradicts(title, guessed string) bool {
	first := strings.Contains(guessed, "1st Edition")
	if first != titleFirst.MatchString(title) {
		return true
	}
	return guessed != "Reverse Holofoil" && titleReverse.MatchString(title)
}

// namesNumber reports whether title carries the card number digits anywhere
// outside its grade.
func namesNumber(title, digits string) bool {
	title = titleGrade.ReplaceAllString(title, " ")
	for _, run := range titleDigits.FindAllString(title, -1) {
		if orZero(strings.TrimLeft(run, "0")) == digits {
			return true
		}
	}
	return false
}

// gradedSlab is the slab a sale was of, as the stores list it, and whether
// the Graded page lists that grader.
func gradedSlab(company string, grade float64, label string) (mtgban.Slab, bool) {
	company = strings.ToUpper(company)
	tier, found := gradedLabels[label]
	if !found || !slices.Contains(gradedGraders, company) {
		return mtgban.Slab{}, false
	}
	return mtgban.Slab{Grader: company, Score: grade, Label: tier}, true
}

// gradedStats counts what a load read and could not keep.
type gradedStats struct {
	rows, unmatched, ungraded, otherNumber int
	foreign, lots, guessed                 int
	catchAllCards, catchAllSales           int
	kept                                   int
}

// report is the job's line for a load.
func (st gradedStats) report(cards int) string {
	line := fmt.Sprintf("%d cards, %d of %d graded sales kept", cards, st.kept, st.rows)
	var dropped []string
	if st.unmatched > 0 {
		dropped = append(dropped, fmt.Sprintf("%d unmatched", st.unmatched))
	}
	if st.ungraded > 0 {
		dropped = append(dropped, fmt.Sprintf("%d of other graders", st.ungraded))
	}
	if st.foreign > 0 {
		dropped = append(dropped, fmt.Sprintf("%d in another language", st.foreign))
	}
	if st.lots > 0 {
		dropped = append(dropped, fmt.Sprintf("%d lots", st.lots))
	}
	if st.guessed > 0 {
		dropped = append(dropped, fmt.Sprintf("%d against their guessed printing", st.guessed))
	}
	if st.otherNumber > 0 {
		dropped = append(dropped, fmt.Sprintf("%d naming another number", st.otherNumber))
	}
	if st.catchAllCards > 0 {
		dropped = append(dropped, fmt.Sprintf("%d on %d cards whose titles rarely carry their number", st.catchAllSales, st.catchAllCards))
	}
	if len(dropped) > 0 {
		line += "; dropped " + strings.Join(dropped, ", ")
	}
	return line
}

// gradedCard is one card's sales while a load reads them.
type gradedCard struct {
	catalog catalogCard
	// The window's sales, the days with one (days since the epoch), and
	// Fanatics Collect's.
	window, fanatics int
	days             map[uint32]bool
	last             GradedSale
	lastSlab         mtgban.Slab
	// Its sales, and those whose title carries its number.
	sales, named int
	grades       map[mtgban.Slab]*gradeBuild
}

// gradeBuild is one grade's sales while a load reads them.
type gradeBuild struct {
	newest []GradedSale
	count  int
}

// gradedBuilder files the sales a load reads by card and slab.
type gradedBuilder struct {
	match   func(productID int64, printing string) string
	catalog func(cardID string) catalogCard
	now     time.Time
	since   uint32
	cards   map[string]*gradedCard
	st      gradedStats
}

func newGradedBuilder(match func(int64, string) string, catalog func(string) catalogCard, now time.Time) *gradedBuilder {
	return &gradedBuilder{
		match:   match,
		catalog: catalog,
		now:     now,
		since:   uint32(startOfDay(now).AddDate(0, 0, 1-Window).Unix()),
		cards:   map[string]*gradedCard{},
	}
}

// add files one sale, unless its title names another language than the
// card's, a lot, a printing against the source's guess or another card's
// number.
func (gb *gradedBuilder) add(row gradedRow) {
	gb.st.rows++
	cardID := gb.match(row.ProductID, row.Printing)
	if cardID == "" {
		gb.st.unmatched++
		return
	}
	slab, listed := gradedSlab(row.Company, row.Grade, row.Label)
	if !listed {
		gb.st.ungraded++
		return
	}
	if row.Cents <= 0 || row.At.IsZero() {
		gb.st.unmatched++
		return
	}

	card := gb.cards[cardID]
	if card == nil {
		card = &gradedCard{catalog: gb.catalog(cardID), grades: map[mtgban.Slab]*gradeBuild{}, days: map[uint32]bool{}}
		gb.cards[cardID] = card
	}
	title := cleanTitle(row.Title)
	switch {
	case titleForeign.MatchString(title) && !card.catalog.nonEnglish:
		gb.st.foreign++
		return
	case titleLot.MatchString(title):
		gb.st.lots++
		return
	case row.PrintingSource == "default" && contradicts(title, row.Printing):
		gb.st.guessed++
		return
	}
	card.sales++
	if card.catalog.number != "" && namesNumber(title, card.catalog.number) {
		card.named++
	}
	if card.catalog.number != "" {
		numbers := titleNumbers(title)
		if len(numbers) > 0 && !slices.ContainsFunc(numbers, card.catalog.fits) {
			gb.st.otherNumber++
			return
		}
	}

	grade := card.grades[slab]
	if grade == nil {
		grade = &gradeBuild{}
		card.grades[slab] = grade
	}
	sale := GradedSale{
		At:        uint32(row.At.Unix()),
		Cents:     uint32(min(row.Cents, int64(^uint32(0)))),
		Fanatics:  row.Source == fanaticsSource,
		BestOffer: row.BestOffer,
		ListingID: row.ListingID,
	}
	grade.count++
	grade.newest = keepNewest(grade.newest, sale)
	if sale.At >= gb.since {
		card.window++
		card.days[sale.At/86400] = true
		if sale.Fanatics {
			card.fanatics++
		}
	}
	if sale.At > card.last.At {
		card.last, card.lastSlab = sale, slab
	}
}

// keepNewest adds sale to newest, newest first, keeping recentDepth.
func keepNewest(newest []GradedSale, sale GradedSale) []GradedSale {
	at, _ := slices.BinarySearchFunc(newest, sale, func(a, b GradedSale) int {
		// Descending by time, so a later sale sorts before.
		switch {
		case a.At > b.At:
			return -1
		case a.At < b.At:
			return 1
		}
		return strings.Compare(a.ListingID, b.ListingID)
	})
	if at >= recentDepth {
		return newest
	}
	newest = slices.Insert(newest, at, sale)
	if len(newest) > recentDepth {
		newest = newest[:recentDepth]
	}
	return newest
}

// snapshot is what gb read, less the cards it judged the source files
// unrelated sales under.
func (gb *gradedBuilder) snapshot() *GradedSnapshot {
	snap := &GradedSnapshot{Cards: map[string]*GradedCard{}, Day: startOfDay(gb.now), Loaded: gb.now}
	for cardID, card := range gb.cards {
		kept := 0
		for _, grade := range card.grades {
			kept += grade.count
		}
		if card.catalog.number != "" && card.sales >= catchAllSales && float64(card.named) < catchAllShare*float64(card.sales) {
			gb.st.catchAllCards++
			gb.st.catchAllSales += kept
			continue
		}
		grades := map[mtgban.Slab]*GradeSales{}
		for slab, grade := range card.grades {
			grades[slab] = &GradeSales{Sales: slices.Clone(grade.newest)}
		}
		if len(grades) > 0 {
			snap.Cards[cardID] = &GradedCard{
				Grades:   grades,
				Sales:    card.window,
				Days:     len(card.days),
				Fanatics: card.fanatics,
				Last:     card.last,
				LastSlab: card.lastSlab,
			}
			gb.st.kept += kept
		}
	}
	return snap
}

// Velocity is the card's Sales Velocity row as the TCGplayer one reads, for
// day: its rate and the details its drawer opens to, with the last sale under
// name's spelling of its slab. Both are empty for nil.
func (c *GradedCard) Velocity(day time.Time, name func(mtgban.Slab) string) (rate, detail string) {
	if c == nil {
		return "", ""
	}
	date := time.Unix(int64(c.Last.At), 0).UTC()
	when := date.Format("Jan 2")
	if date.Year() != day.Year() {
		when = date.Format("Jan 2, 2006")
	}
	last := "|last sale|$" + centsText(uint64(c.Last.Cents)) + " " + name(c.LastSlab) + " · " + when
	if c.Sales == 0 {
		return "0/day", fmt.Sprintf("no sale in %d days\n%s", Window, last)
	}
	perDay := float64(c.Sales) / Window
	rate = strconv.FormatFloat(perDay, 'f', 1, 64) + "/day"
	if perDay < 0.1 {
		rate = "<0.1/day"
	}
	lines := []string{
		fmt.Sprintf("|sales|%d|days|%d/%d", c.Sales, c.Days, Window),
		fmt.Sprintf("|eBay|%d|Fanatics|%d", c.Sales-c.Fanatics, c.Fanatics),
		"",
		last,
	}
	return rate, strings.Join(lines, "\n")
}

// Group is g's sales as the Sales pane draws a condition's orders, under the
// slab's grade: their average, best offers left out, the newest RecentShown,
// then the rest, each linking to its listing.
func (g *GradeSales) Group(grade string) Group {
	group := Group{Grade: grade, Slab: true}
	var cents, sales uint64
	for i, sale := range g.Sales {
		if !sale.BestOffer {
			cents += uint64(sale.Cents)
			sales++
		}
		line := gradedLine(sale)
		if i < RecentShown {
			group.Shown = append(group.Shown, line)
		} else {
			group.More = append(group.More, line)
		}
	}
	if sales > 0 {
		group.Avg = centsText((cents + sales/2) / sales)
	}
	return group
}

// gradedLine is one sale's marketplace, date, price and listing, and a mark
// on a best offer, whose price is the ask.
func gradedLine(sale GradedSale) Line {
	at := time.Unix(int64(sale.At), 0).UTC()
	line := Line{
		Date:   at.Format(time.DateOnly),
		Time:   at.Format("2006-01-02 15:04 UTC"),
		Source: "eBay",
		Price:  centsText(uint64(sale.Cents)),
		// nordt keeps eBay on the sold item rather than redirecting an
		// ended listing to similar live ones.
		Link: "https://www.ebay.com/itm/" + sale.ListingID + "?nordt=true",
	}
	if sale.Fanatics {
		line.Source = "Fanatics"
		line.Link = "https://sales-history.fanaticscollect.com/items/" + strings.TrimPrefix(sale.ListingID, fanaticsSource+":")
	}
	if sale.BestOffer {
		line.Qty = "offer"
		line.Note = "Best offer accepted: this is the asking price, the buyer paid less"
	}
	return line
}
