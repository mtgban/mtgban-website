package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/internal/palette"
	"github.com/mtgban/mtgban-website/observability"
)

// csvWithout returns csv with `drop` and any empty entries removed. Used by
// the templates to build "remove this card" URLs that strip one entry from the
// chart roster while keeping the rest in order.
// firstCSV joins the first n elements of keys into a comma-separated string,
// capping n at len(keys). Used to build the "chart the top results" link from
// the ordered result keys (AllKeys).
func firstCSV(keys []string, n int) string {
	if n > len(keys) {
		n = len(keys)
	}
	if n <= 0 {
		return ""
	}
	return strings.Join(keys[:n], ",")
}

func csvWithout(csv, drop string) string {
	parts := strings.Split(csv, ",")
	out := parts[:0]
	for _, p := range parts {
		if p != "" && p != drop {
			out = append(out, p)
		}
	}
	return strings.Join(out, ",")
}

// A tooltip's text (js/tooltips.js) marks what it sets in bold with **, and
// may hold tables: a line starting with | is a row of cells split on |, and
// one starting with |# is a header row, which starts a new table. A table
// with a header sets its other columns as numbers, one without sets its
// first column as labels, and the text after a table is its footnote.

// tipBlock is one of a tooltip's tables, or a run of its lines between them.
type tipBlock struct {
	table  bool
	lines  []string
	header []string
	rows   [][]string
}

// tipBlocks splits a tooltip into its tables and the lines around them.
func tipBlocks(tip string) []tipBlock {
	var blocks []tipBlock
	for _, line := range strings.Split(tip, "\n") {
		last := len(blocks) - 1
		switch {
		case strings.HasPrefix(line, "|#"):
			blocks = append(blocks, tipBlock{table: true, header: tipCells(line[2:])})
		case strings.HasPrefix(line, "|"):
			if last < 0 || !blocks[last].table {
				blocks = append(blocks, tipBlock{table: true})
				last++
			}
			blocks[last].rows = append(blocks[last].rows, tipCells(line[1:]))
		default:
			if last < 0 || blocks[last].table {
				blocks = append(blocks, tipBlock{})
				last++
			}
			blocks[last].lines = append(blocks[last].lines, line)
		}
	}
	return blocks
}

// tipCells are a row's cells, trimmed.
func tipCells(row string) []string {
	cells := strings.Split(row, "|")
	for i, cell := range cells {
		cells[i] = strings.TrimSpace(cell)
	}
	return cells
}

// hasTipTable tells whether a tooltip holds a table.
func hasTipTable(tip string) bool {
	return strings.HasPrefix(tip, "|") || strings.Contains(tip, "\n|")
}

// plainTip is a tooltip's text without the ** marks that set its parts in
// bold, and with its tables as sentences: a header's first cell on a line of
// its own, then each row as "Near Mint: sellers 12, copies 30".
func plainTip(tip string) string {
	if !hasTipTable(tip) {
		return strings.ReplaceAll(tip, "**", "")
	}
	var lines []string
	for _, block := range tipBlocks(tip) {
		if !block.table {
			lines = append(lines, block.lines...)
			continue
		}
		if len(block.header) > 0 && block.header[0] != "" {
			lines = append(lines, block.header[0])
		}
		for _, row := range block.rows {
			lines = append(lines, plainTipRow(row, block.header))
		}
	}
	return strings.ReplaceAll(strings.Join(lines, "\n"), "**", "")
}

// plainTipRow is a table row as a sentence, each cell after the first after
// its column's header, which needs no plural that way.
func plainTipRow(row, header []string) string {
	if len(row) < 2 {
		return strings.Join(row, "")
	}
	rest := make([]string, 0, len(row)-1)
	for i, cell := range row[1:] {
		if i+1 < len(header) && header[i+1] != "" {
			cell = strings.ToLower(header[i+1]) + " " + cell
		}
		rest = append(rest, cell)
	}
	return row[0] + ": " + strings.Join(rest, ", ")
}

// tipHTML is a tooltip as escaped HTML, for the pages that show it in place
// rather than on hover: its tables as tables, as js/tooltips.js draws them.
func tipHTML(tip string) template.HTML {
	if !hasTipTable(tip) {
		return template.HTML(tipBoldHTML(tip))
	}
	var b strings.Builder
	afterTable := false
	for _, block := range tipBlocks(tip) {
		if !block.table {
			class := ""
			if afterTable {
				class = ` class="tip-foot"`
			}
			b.WriteString("<div" + class + ">" + tipBoldHTML(strings.Join(block.lines, "\n")) + "</div>")
			continue
		}
		afterTable = true
		b.WriteString(`<table class="tip-table">`)
		if block.header != nil {
			b.WriteString("<tr>")
			for i, cell := range block.header {
				b.WriteString("<th" + tipCellClass(i, true) + ">" + tipBoldHTML(cell) + "</th>")
			}
			b.WriteString("</tr>")
		}
		for _, row := range block.rows {
			b.WriteString("<tr>")
			for i, cell := range row {
				b.WriteString("<td" + tipCellClass(i, block.header != nil) + ">" + tipBoldHTML(cell) + "</td>")
			}
			b.WriteString("</tr>")
		}
		b.WriteString("</table>")
	}
	return template.HTML(b.String())
}

// tipCellClass is the class of a table's column: a number after a header's
// first column, a label as a header-less table's first one.
func tipCellClass(column int, headed bool) string {
	switch {
	case headed && column > 0:
		return ` class="tip-num"`
	case !headed && column == 0:
		return ` class="tip-label"`
	}
	return ""
}

// tipBoldHTML is text escaped, what sits between ** marks in <strong>.
func tipBoldHTML(text string) string {
	var b strings.Builder
	for i, part := range strings.Split(text, "**") {
		if i%2 == 1 {
			b.WriteString("<strong>" + template.HTMLEscapeString(part) + "</strong>")
			continue
		}
		b.WriteString(template.HTMLEscapeString(part))
	}
	return b.String()
}

// tipAttrs is the title, and the data-tip when it marks anything bold or
// holds a table, of an element whose tooltip is tip.
func tipAttrs(tip string) string {
	plain := plainTip(tip)
	attrs := ` title="` + template.HTMLEscapeString(plain) + `"`
	if plain != tip {
		attrs += ` data-tip="` + template.HTMLEscapeString(tip) + `"`
	}
	return attrs
}

const cardArtPlaceholder = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"

var funcMap = template.FuncMap{
	// A URL, or html/template rewrites the data: scheme in src to
	// #ZgotmplZ, which the browser fetches as the page's own address.
	"card_art_placeholder": func() template.URL {
		return template.URL(cardArtPlaceholder)
	},
	// jsonArray writes a list of strings for a script to read out of an
	// attribute. A list that cannot be written comes out as an empty one:
	// for the handoff page, whose attribute names who may hand it a card
	// list, that is a page listening to nobody rather than to everybody.
	// What a page documenting the upload may say about its size, read off
	// the handler's own constants rather than written out beside them.
	"uploadLimit":    func() int { return MaxUploadEntries },
	"uploadProLimit": func() int { return MaxUploadProEntries },
	"uploadMaxMB":    func() int { return MaxUploadFileSize >> 20 },
	"jsonArray": func(values []string) string {
		if values == nil {
			values = []string{}
		}
		encoded, err := json.Marshal(values)
		if err != nil {
			return "[]"
		}
		return string(encoded)
	},
	// sourceLink answers with a URL a results row can be made clickable
	// with, or "" for a note that is not one.
	//
	// The notes column is whatever the uploaded file put in it, so only an
	// absolute http or https URL becomes a link and every other note stays
	// the text it is. html/template would refuse a javascript: href on its
	// own, but a note is not a link merely for being a string, and a row
	// whose note is a sentence should not look like one.
	"sourceLink": func(note string) string {
		parsed, err := url.Parse(strings.TrimSpace(note))
		if err != nil || parsed.Host == "" {
			return ""
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return ""
		}
		// Rebuilt rather than echoed, the same way the handoff link is:
		// Host excludes userinfo, so https://user:pass@host/... would get
		// this far and keep the credentials in the href, which a browser
		// may then send as Basic auth.
		clean := url.URL{
			Scheme:   parsed.Scheme,
			Host:     parsed.Host,
			Path:     parsed.Path,
			RawPath:  parsed.RawPath,
			RawQuery: parsed.RawQuery,
			Fragment: parsed.Fragment,
		}
		return clean.String()
	},
	"inc": func(i, j int) int {
		return i + j
	},
	"csv_without": csvWithout,
	"first_csv":   firstCSV,
	// Which of the three readings a sealed product's link opens, given what
	// the product holds and what the reader asked for in the settings
	"sealed_contents_filter": sealedContentsFilter,
	"dec": func(i, j int) int {
		return i - j
	},
	"mulf": func(i, j float64) float64 {
		return i * j
	},
	"print_perc": func(s string) string {
		n, _ := strconv.ParseFloat(s, 64)
		return fmt.Sprintf("%0.2f %%", n*100)
	},
	"perc_class": func(s string) string {
		n, _ := strconv.ParseFloat(s, 64)
		if n > 0 {
			return "news-perc-up"
		}
		if n < 0 {
			return "news-perc-down"
		}
		return "news-perc-zero"
	},
	"print_price": func(s string) string {
		n, _ := strconv.ParseFloat(s, 64)
		return fmt.Sprintf("$ %0.2f", n)
	},
	"scraper_name": func(s string) string {
		return scraperName(s)
	},
	"strip_edition": func(name, edition string, sealed bool) string {
		if !sealed || edition == "" {
			return name
		}
		if strings.HasPrefix(name, edition) {
			shortened := strings.TrimPrefix(name, edition)
			shortened = strings.TrimLeft(shortened, " :-–—")
			if shortened != "" {
				return shortened
			}
		}
		return name
	},
	"slug": func(s string) string {
		s = strings.ToLower(s)
		s = strings.ReplaceAll(s, " ", "-")
		var b strings.Builder
		for _, r := range s {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				b.WriteRune(r)
			}
		}
		return b.String()
	},
	"slice_has": func(s []string, p string) bool {
		return slices.Contains(s, p)
	},
	"has_prefix": func(s, p string) bool {
		return strings.HasPrefix(s, p)
	},
	"set_mark": palette.SetMark,
	"contains": func(s, p string) bool {
		return strings.Contains(s, p)
	},
	"is_sealed_scraper": func(shorthand string) bool {
		for _, seller := range GetSellers() {
			if seller != nil && seller.Info().Shorthand == shorthand {
				return seller.Info().SealedMode
			}
		}
		for _, vendor := range GetVendors() {
			if vendor != nil && vendor.Info().Shorthand == shorthand {
				return vendor.Info().SealedMode
			}
		}
		return false
	},
	"load_partner": func(s string) string {
		return Affiliates().Codes[s]
	},
	"game_title": func() string {
		return gameMap[Config().Game]
	},
	// game_badge names the game a deployment serves for the brand lockup,
	// where the wordmark alone says nothing about which site this is. Empty
	// on Magic, whose logo already reads MTGBAN.
	"game_badge": func() string {
		if Config().Game == DefaultGame {
			return ""
		}
		return gameBadgeMap[Config().Game]
	},
	// game is the slug the deployment serves, for the places that style or
	// address a game rather than name it.
	"game": func() string {
		return string(Config().Game)
	},
	// bantool_run_name is the GitHub Actions run name a store's bantool
	// workflow gets, which the admin dashboard's running-workflow poll
	// matches a row against (see newBantoolWorkflow).
	"bantool_run_name": func(store string) string {
		return newBantoolWorkflow(Config().Game, store).RunName
	},
	// stale_count counts the rows of an admin scraper table whose stale
	// badge, column 8, is set.
	"stale_count": func(rows [][]string) int {
		count := 0
		for _, row := range rows {
			if len(row) > 8 && row[8] != "" {
				count++
			}
		}
		return count
	},
	// stale_stores lists the store, column 2, of every stale row in the admin
	// tables, sorted and deduplicated, leaving out "UNKNOWN" and "session".
	"stale_stores": func(tables [][][]string) []string {
		var stores []string
		for _, rows := range tables {
			for _, row := range rows {
				// Only the scraper tables reach column 8.
				if len(row) < 9 || row[8] == "" || row[2] == "UNKNOWN" || row[2] == "session" {
					continue
				}
				stores = append(stores, row[2])
			}
		}
		slices.Sort(stores)
		return slices.Compact(stores)
	},
	"card_back": func() string {
		return "/img/backs/" + string(Config().Game) + ".webp"
	},
	// rarity_badge hands the set-symbol block the drawing for one rarity,
	// already sized for the code it has to hold.
	"rarity_badge": func(rarity, code string) rarityBadge {
		badge, found := rarityBadges[mtgmatcher.RarityName(rarity)]
		if !found {
			badge = rarityBadges[""]
		}
		return fitCode(badge, code)
	},
	"uuid2ckid": func(s string) string {
		bl, err := findVendorBuylist("CK")
		if err != nil {
			return ""
		}
		entries, found := bl[s]
		if !found {
			return ""
		}
		return entries[0].OriginalID
	},
	"cart_load":        cartLoadFor,
	"cart_load_arbit":  cartLoadForArbit,
	"cart_stores_in":   cartStoresIn,
	"cart_bookmarklet": cartBookmarklet,
	"isSussy": func(m map[string]float64, s string) bool {
		_, found := m[s]
		return found
	},
	"invalid_direct": invalidDirect,
	// price_warning_tip is the tooltip of a price invalid_direct flags.
	"price_warning_tip": directPriceWarning,
	"color2hex": func(s string) string {
		color, found := colorValues[s]
		if !found {
			return "#111111"
		}
		return color
	},
	"tcg_market_price": func(s string) float64 {
		return getTCGMarketPrice(s)
	},
	// buylist_badge renders a pill next to the store name when the store is the
	// card's hotlist store: "New high" when Card Kingdom's price beats every
	// price of the last 90 days, "90d high" when it ties the highest.
	"buylist_badge": func(shorthand, hotlistStore string, newHigh bool, newHighTip string) template.HTML {
		switch {
		case shorthand != hotlistStore:
			return ""
		case newHigh:
			return template.HTML(` <span class="bl-pill bl-pill-new"` + tipAttrs(newHighTip) + `>New high</span>`)
		}
		return template.HTML(` <span class="bl-pill bl-pill-high"` + tipAttrs(ckAtHighTip) + `>90d high</span>`)
	},
	// buylist_detail renders a card's precomputed Card Kingdom "Good" (P90) and
	// "Highest" (90-day) buylist prices (passed in) as small, labeled prices for a
	// dedicated column — the pills live next to the card name (see
	// buylist_badge). With always=false it returns "" unless the store is the
	// hotlist store or the offer meets good; with always=true it shows the
	// prices whenever they exist.
	"buylist_detail": func(shorthand, hotlistStore string, price, good, highest float64, always bool, ckSignal string) template.HTML {
		hasBadge := shorthand == hotlistStore || (good > 0 && price >= good)
		if !hasBadge && !always {
			return ""
		}
		prices := ""
		if good > 0 {
			// In always-show (optimizer) mode, tint Good by CK's signal: green
			// when its offer is worth taking now, amber while CK is likely to
			// pay more soon (ckbuylist.go).
			goodClass := ""
			switch {
			case !always:
			case ckSignal == "sell":
				goodClass = ` class="bl-good-sell"`
			case ckSignal == "wait":
				goodClass = ` class="bl-good-wait"`
			}
			prices += fmt.Sprintf(`<span%s>Good: $ %.2f</span>`, goodClass, good)
		}
		if highest > 0 {
			prices += fmt.Sprintf(`<span>Highest: $ %.2f</span>`, highest)
		}
		if prices == "" {
			return ""
		}
		return template.HTML(fmt.Sprintf(`<span class="bl-prices">%s</span>`, prices))
	},
	// grade spells a grade for indexing the condition-keyed maps, which
	// take a typed key where a template literal is a plain string.
	"grade": func(s string) mtgban.Condition {
		return mtgban.Condition(s)
	},
	// buylist_state is how a buylist price is highlighted. Card Kingdom's NM
	// offer follows CK's signal ("best" to take it, "wait" when CK is likely
	// to pay more soon; ckbuylist.go), any other store's offer is "best" at or
	// above CK's P90.
	"buylist_state": func(shorthand string, conditions mtgban.Condition, isOffer bool, price, good float64, ckSignal string, ckPauseWait bool) string {
		switch {
		case !isOffer:
			return ""
		case shorthand == "CK" && conditions != "NM":
			return ""
		case shorthand == "CK" && ckSignal == "sell":
			return "best"
		case shorthand == "CK":
			return ckSignal
		// CK is not paying its last known price: never one to take, at most
		// one to wait for.
		case shorthand == "CKBLLast" && conditions == "NM" && ckPauseWait:
			return "wait"
		case shorthand == "CKBLLast":
			return ""
		case good > 0 && price >= good:
			return "best"
		}
		return ""
	},
	// buylist_title is the tooltip of a buylist price, on the offers that
	// have something to say: on CK's NM offer the signal's verdict, CK's
	// stock facts, its P90 and 90-day high, and the odds behind the verdict;
	// on another store's green offer, the P90 it reaches.
	"buylist_title": func(shorthand string, conditions mtgban.Condition, state string, good, highest float64, facts, tip string) string {
		if shorthand != "CK" {
			if state != "best" || good <= 0 {
				return ""
			}
			return fmt.Sprintf("**A good price**: at or above Card Kingdom's P90 ($ %.2f)", good)
		}
		if conditions != "NM" {
			return ""
		}
		// A tip is its verdict, then the odds behind it.
		verdict, odds, _ := strings.Cut(tip, "\n")
		return joinLines(verdict, facts, ckReferencePrices(good, highest), odds)
	},
	// buylist_wait marks Card Kingdom's NM offer while CK is likely to pay
	// more soon.
	"buylist_wait": func(shorthand string, conditions mtgban.Condition, ckSignal, tip string) template.HTML {
		if shorthand != "CK" || conditions != "NM" || ckSignal != "wait" {
			return ""
		}
		return template.HTML(` <span class="ck-wait"` + tipAttrs(tip) + `>&#8593;</span>`)
	},
	// buylist_pause marks Card Kingdom's last known NM offer on a card CK has
	// paused with a pill saying for how long, the chances as its tooltip.
	"buylist_pause": func(shorthand string, conditions mtgban.Condition, label, tip string) template.HTML {
		if shorthand != "CKBLLast" || conditions != "NM" || label == "" {
			return ""
		}
		return template.HTML(` <span class="bl-pill bl-pill-paused"` + tipAttrs(tip) + `>` + template.HTMLEscapeString(label) + `</span>`)
	},
	// buylist_pause_wait is the wait arrow on that offer, when waiting for CK
	// beats every other cash offer.
	"buylist_pause_wait": func(shorthand string, conditions mtgban.Condition, wait bool) template.HTML {
		if shorthand != "CKBLLast" || conditions != "NM" || !wait {
			return ""
		}
		return template.HTML(` <span class="ck-wait"` + tipAttrs(ckPauseWaitTip) + `>&#8593;</span>`)
	},
	// buylist_ck is a card's CK signal on the pages with a column of card
	// details: "Sell now" or "Wait". The column's tooltip explains it.
	"buylist_ck": func(ckSignal string) template.HTML {
		switch ckSignal {
		case "wait":
			return `<span class="bl-ck bl-ck-wait">&#8593; Wait</span>`
		case "sell":
			return `<span class="bl-ck bl-ck-sell">Sell now</span>`
		}
		return ""
	},
	// direct_stock is TCGplayer Direct's stock of a card in a grade, 0 where
	// the last scrape did not see it.
	"direct_stock": func(cardID string, grade mtgban.Condition) int {
		stock, _ := tcgDirectStock(cardID, grade)
		return stock
	},
	// plain_tip is a tooltip without its ** bold marks and with its tables
	// as sentences, for a title.
	"plain_tip": plainTip,
	// tip_html writes a tooltip as HTML, its marked parts in bold and its
	// tables as tables, where a page shows it in full rather than on hover.
	"tip_html": tipHTML,
	"base64enc": func(s string) string {
		return base64.StdEncoding.EncodeToString([]byte(s))
	},
	// Every desktop page embeds these, and their lists never change: build
	// each one once.
	"palette_newspaper_targets": sync.OnceValue(func() template.JS { return palette.NewspaperTargetsJSON(paletteNewspaperPages()) }),
	"palette_sleepers_targets":  sync.OnceValue(palette.SleepersTargetsJSON),
	"palette_arbit_targets":     sync.OnceValue(palette.ArbitTargetsJSON),
	"guide_stores":              guideStoresJSON,
	"usd":                       formatUSD,
	"plural":                    plural,
	"api_plans_json":            apiPlansJSON,
	"plan_icon":                 planIcon,
	"usage_path_url":            observability.PathURL,
	"dict": func(values ...any) (map[string]any, error) {
		if len(values)%2 != 0 {
			return nil, errors.New("dict requires even number of args")
		}
		m := make(map[string]any, len(values)/2)
		for i := 0; i < len(values); i += 2 {
			k, ok := values[i].(string)
			if !ok {
				return nil, errors.New("dict keys must be strings")
			}
			m[k] = values[i+1]
		}
		return m, nil
	},
}
