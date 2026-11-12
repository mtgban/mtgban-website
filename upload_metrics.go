package main

import (
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mtgban/mtgban-website/observability"
)

// uploadRun is what one priced upload ran with.
type uploadRun struct {
	source, host, origin string // from uploadSourceKind; origin is handoffOriginHost's answer
	from                 string // the from query as posted
	buylist              bool   // priced on the buylist side
	rows, cards, sealed  int    // merged rows; ids.cardIDs; ids.sealedProductIDs
	st                   uploadSettings
	away                 []string // the optimizer options the reader's settings cookie saved away from their default
	marginChanged        bool     // the margin option is on with a margin other than the page's
	stores               int      // enabled singles plus sealed stores
	customBuylist        bool     // prices.customTips is not empty
	indexChanged         bool     // the index keys in force differ from the defaults
	unpacked, published  bool
	elapsed              time.Duration
}

// uploadURLHosts maps a remote URL's host to upload.url_host's value.
var uploadURLHosts = map[string]string{
	"store.tcgplayer.com": "tcgplayer",
	"moxfield.com":        "moxfield",
	"www.moxfield.com":    "moxfield",
	"manabox.app":         "manabox",
	"www.manabox.app":     "manabox",
	"archidekt.com":       "archidekt",
	"www.archidekt.com":   "archidekt",
	"cubecobra.com":       "cubecobra",
	"www.cubecobra.com":   "cubecobra",
	"mythic.tools":        "mythictools",
	"www.mythic.tools":    "mythictools",
	"app.getcollectr.com": "collectr",
	"docs.google.com":     "gdocs",
}

// uploadFroms are the from values the list-posting controls send.
var uploadFroms = []string{"search_sidebar", "favorites", "backpack", "news", "screener", "palette", "results_reload", "upload_form"}

// uploadSorts are the result sorts upload.sorting counts.
var uploadSorts = []string{"highprice", "alphabetical", "setalpha", "setchrono", "highspread", "profitability"}

// uploadOptions are the optimizer options, in upload.option's order, each with its flag.
var uploadOptions = []struct {
	name string
	on   func(uploadSettings) bool
}{
	{"lowval", func(st uploadSettings) bool { return st.skipLowValue }},
	{"lowvalabs", func(st uploadSettings) bool { return st.skipLowValueAbs }},
	{"highval", func(st uploadSettings) bool { return st.skipHighValue }},
	{"highvalabs", func(st uploadSettings) bool { return st.skipHighValueAbs }},
	{"minmargin", func(st uploadSettings) bool { return st.useMargin }},
	{"nocond", func(st uploadSettings) bool { return st.skipConds }},
	{"noprice", func(st uploadSettings) bool { return st.skipPrices }},
	{"customperc", func(st uploadSettings) bool { return st.visualIndicator }},
}

// uploadSourceKind names where in's list came from, in loadUploadEntries' order, and a remote URL's site.
func uploadSourceKind(in uploadInput, origin string) (source, host string) {
	switch {
	case in.shared:
		return "share", ""
	case len(in.hashes) != 0:
		return "hashes", ""
	case in.textArea != "":
		if origin != "" {
			return "handoff", ""
		}
		return "text", ""
	case in.handler != nil:
		name := strings.ToLower(in.handler.Filename)
		switch {
		case strings.HasSuffix(name, ".xlsx"):
			return "file_xlsx", ""
		case strings.HasSuffix(name, ".xls"):
			return "file_xls", ""
		case strings.HasSuffix(name, ".txt"):
			return "file_txt", ""
		}
		return "file_csv", ""
	case in.remoteURL != "":
		host = "other"
		if u, err := url.Parse(in.remoteURL); err == nil {
			if v, ok := uploadURLHosts[u.Host]; ok {
				host = v
			}
		}
		return "url", host
	}
	return "", ""
}

// uploadFrom is upload.from's value for raw: a control's own value, else unknown.
func uploadFrom(raw string) string {
	if slices.Contains(uploadFroms, raw) {
		return raw
	}
	return "unknown"
}

// uploadPriceSource is upload.price_source's value, "" for a source the page does not offer.
func uploadPriceSource(raw string) string {
	switch raw {
	case "":
		return "default"
	case "credit", "marketCredit":
		return raw
	}
	return ""
}

// uploadSealed is upload.sealed's value.
func uploadSealed(cards, sealed int) string {
	switch {
	case sealed == 0:
		return "none"
	case cards == 0:
		return "all"
	}
	return "some"
}

// uploadFacts lists what one priced upload ran with; a run with no source yields nothing.
func uploadFacts(run uploadRun) []fact {
	if run.source == "" {
		return nil
	}
	facts := []fact{newFact("", "upload.source", run.source)}
	switch run.source {
	case "url":
		facts = append(facts, newFact("", "upload.url_host", run.host))
	case "handoff":
		facts = append(facts, newFact("", "upload.handoff_origin", run.origin))
	case "hashes":
		facts = append(facts, newFact("", "upload.from", uploadFrom(run.from)))
	}
	mode := "retail"
	if run.buylist {
		mode = "buylist"
	}
	facts = append(facts,
		newFact("", "upload.mode", mode),
		newFact("", "upload.rows", observability.Bucket([]int64{1, 10, 100, 1000}, int64(run.rows))),
		newFact("", "upload.sealed", uploadSealed(run.cards, run.sealed)),
	)

	st := run.st
	// A retail run reads no option, so every flag is off there.
	for _, opt := range uploadOptions {
		if run.buylist && slices.Contains(run.away, opt.name) && opt.on(st) != slices.Contains(defaultUploadOpts, opt.name) {
			facts = append(facts, newFact("", "upload.option", opt.name))
		}
	}
	for _, set := range []struct {
		name string
		off  bool
	}{
		{"percspread", st.percSpread != MinLowValueSpread},
		{"percspreadmax", st.percSpreadMax > 0},
		{"minval", st.minLowVal != MinLowValueAbs},
		{"maxval", st.maxHighVal > 0},
		{"margin", run.marginChanged},
		{"custompercmax", st.visualPerc != VisualPercSpread},
		{"multiplier", st.multiplier > 1},
		{"maxqty", st.maxQty > 0},
	} {
		if set.off {
			facts = append(facts, newFact("", "upload.value_set", set.name))
		}
	}
	if slices.Contains(uploadSorts, st.sorting) {
		facts = append(facts, newFact("", "upload.sorting", st.sorting))
	}
	if v := uploadPriceSource(st.priceSource); run.buylist && v != "" {
		facts = append(facts, newFact("", "upload.price_source", v))
	}
	if run.customBuylist {
		facts = append(facts, newFact("", "upload.custom_buylist", ""))
	}
	facts = append(facts, newFact("", "upload.stores", observability.Bucket([]int64{1, 5, 10, 20}, int64(run.stores))))
	if run.indexChanged {
		facts = append(facts, newFact("", "upload.index_pref", ""))
	}
	if run.unpacked {
		facts = append(facts, newFact("", "upload.unpack", ""))
	}
	if run.published {
		facts = append(facts, newFact("", "upload.publish", ""))
	}
	return append(facts, newFact("", "upload.duration", durationBucket(run.elapsed)))
}

// awayUploadOptions are the optimizer options whose state in the reader's settings cookie differs from the default.
// The form is not read: js/upload-options.js posts the defaults when nothing is saved.
func awayUploadOptions(r *http.Request) []string {
	raw := readCookie(r, "UploadOptimizerOpts")
	if raw == "" {
		return nil
	}
	saved := strings.Split(raw, ",")
	var away []string
	for _, opt := range uploadOptions {
		if slices.Contains(saved, opt.name) != slices.Contains(defaultUploadOpts, opt.name) {
			away = append(away, opt.name)
		}
	}
	return away
}

// defaultUploadMargin is the page's margin, as js/upload-options.js and templates/settings/upload.html set it.
const defaultUploadMargin = 10.0

// uploadMarginChanged reports whether the margin in force differs from the page's default.
func uploadMarginChanged(r *http.Request, st uploadSettings) bool {
	raw := getUploadSetting(r, "margin", "UploadMargin")
	if !st.useMargin || raw == "" {
		return false
	}
	v, err := strconv.ParseFloat(raw, 64)
	return err == nil && v >= 0 && v != defaultUploadMargin
}

// readUploadRun reads what one priced upload ran with from its request and results.
func readUploadRun(r *http.Request, in uploadInput, blMode bool, st uploadSettings, selected uploadStores,
	rows int, ids uploadIDs, prices uploadPrices, elapsed time.Duration) uploadRun {
	run := uploadRun{
		origin:        handoffOriginHost(r.FormValue("uploadSource")),
		from:          r.URL.Query().Get("from"),
		buylist:       blMode,
		rows:          rows,
		cards:         len(ids.cardIDs),
		sealed:        len(ids.sealedProductIDs),
		st:            st,
		away:          awayUploadOptions(r),
		marginChanged: uploadMarginChanged(r, st),
		stores:        len(selected.enabledStores) + len(selected.enabledSealedStores),
		customBuylist: len(prices.customTips) != 0,
		indexChanged: !slices.Equal(selected.enabledIndexKeys, UploadIndexKeysPublic) ||
			!slices.Equal(selected.enabledSealedIndexKeys, selected.sealedIndexes),
		unpacked:  r.FormValue("unpack") == "true",
		published: st.publishStore,
		elapsed:   elapsed,
	}
	run.source, run.host = uploadSourceKind(in, run.origin)
	return run
}

// uploadTag is upload.tag's scope and value for a transfer's tag; ("", "") for any other tag.
func uploadTag(tag string) (scope, value string) {
	switch tag {
	case "SCGRetail":
		return "SCG", "load_at"
	case "CK":
		return "CK", "csv"
	case "SCG":
		return "SCG", "csv"
	case "TCG":
		return "TCG", "tcg_remove"
	}
	return "", ""
}

// observeUploadTag counts a transfer served for tag; a tag that is not a transfer is not counted.
func observeUploadTag(r *http.Request, tag string) {
	if scope, value := uploadTag(tag); scope != "" {
		observeScoped(r, scope, "upload.tag", value)
	}
}

// uploadExportScope is upload.export's scope for a posted csvscope.
func uploadExportScope(csvscope string) string {
	switch csvscope {
	case "singles":
		return "singles"
	case "sealed":
		return "sealed"
	}
	return "all"
}

// uploadErrorScope is upload.parse_error's scope for in: its source, or none.
func uploadErrorScope(r *http.Request, in uploadInput) string {
	source, _ := uploadSourceKind(in, handoffOriginHost(r.FormValue("uploadSource")))
	if source == "" {
		return "none"
	}
	return source
}
