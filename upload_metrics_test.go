package main

import (
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/observability"
	"github.com/mtgban/mtgban-website/userstate"
)

// listPostFiles are the templates and scripts that post a list to /upload.
var listPostFiles = []string{
	"templates/search.html", "templates/news.html", "templates/screener.html", "templates/upload.html",
	"js/favorites.js", "js/backpack.js", "js/command-palette.js",
}

// Every post of a list to /upload names the control that made it in the
// action's query, never in a form field.
func TestEveryListPostNamesItsOrigin(t *testing.T) {
	for file, want := range map[string][]string{
		"templates/search.html":   {`<form action="/upload?from=search_sidebar" method="post"`},
		"templates/news.html":     {`<form action="/upload?from=news" method="post">`},
		"templates/screener.html": {`<form action="/upload?from=screener" method="post">`},
		"templates/upload.html": {
			`action="/upload{{if .CardHashes}}?from=upload_form{{end}}" method="post" id="upload_form"`,
			`<form id="upload_form" action="/upload?from=results_reload" method="post" style="display:none">`,
		},
		"js/favorites.js":       {`form.action = '/upload?from=favorites';`},
		"js/backpack.js":        {`form.setAttribute("action", "/upload?from=backpack");`},
		"js/command-palette.js": {`form.action = '/upload?from=palette';`},
	} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range want {
			if !strings.Contains(string(src), w) {
				t.Errorf("%s does not carry %s", file, w)
			}
		}
		for _, field := range []string{`name="from"`, `name = 'from'`, `name = "from"`, `'from', `} {
			if strings.Contains(string(src), field) {
				t.Errorf("%s posts the origin as a form field (%s)", file, field)
			}
		}
	}
}

// The from values the controls send are upload.from's enum, unknown aside.
func TestListPostOriginsAreRegistered(t *testing.T) {
	sent := map[string]bool{}
	from := regexp.MustCompile(`/upload(?:\{\{if \.CardHashes\}\})?\?from=([a-z_]+)`)
	for _, file := range listPostFiles {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range from.FindAllStringSubmatch(string(src), -1) {
			sent[m[1]] = true
		}
	}
	entry, ok := observability.Lookup("upload.from")
	if !ok {
		t.Fatal("upload.from is not registered")
	}
	for v := range sent {
		if !slices.Contains(entry.Enum, v) {
			t.Errorf("a control sends from=%s, which upload.from does not list", v)
		}
		if uploadFrom(v) != v {
			t.Errorf("uploadFrom(%q) does not keep it", v)
		}
	}
	for _, v := range entry.Enum {
		if v != "unknown" && !sent[v] {
			t.Errorf("upload.from lists %s, which no control sends", v)
		}
	}
	if len(sent) != 8 {
		t.Errorf("found %d origins, want the 8 controls: %v", len(sent), sent)
	}
}

func TestUploadSourceKind(t *testing.T) {
	file := func(name string) uploadInput {
		return uploadInput{handler: &multipart.FileHeader{Filename: name}}
	}
	for i, c := range []struct {
		in           uploadInput
		origin       string
		source, host string
	}{
		{uploadInput{shared: true, hashes: []string{"a"}}, "", "share", ""},
		{uploadInput{hashes: []string{"a"}, textArea: "x"}, "", "hashes", ""},
		{uploadInput{textArea: "4 Bolt"}, "", "text", ""},
		{uploadInput{textArea: "4 Bolt"}, "www.cardmarket.com", "handoff", ""},
		{file("List.XLSX"), "", "file_xlsx", ""},
		{file("old.xls"), "", "file_xls", ""},
		{file("deck.txt"), "", "file_txt", ""},
		{file("export"), "", "file_csv", ""},
		{uploadInput{remoteURL: "https://www.moxfield.com/decks/abc"}, "", "url", "moxfield"},
		{uploadInput{remoteURL: "https://store.tcgplayer.com/collection/view/1"}, "", "url", "tcgplayer"},
		{uploadInput{remoteURL: "https://app.getcollectr.com/showcase/profile/x"}, "", "url", "collectr"},
		{uploadInput{remoteURL: "https://docs.google.com/spreadsheets/d/x/edit"}, "", "url", "gdocs"},
		{uploadInput{remoteURL: "https://example.test/list"}, "", "url", "other"},
		{uploadInput{remoteURL: "://"}, "", "url", "other"},
		{uploadInput{}, "", "", ""},
	} {
		source, host := uploadSourceKind(c.in, c.origin)
		if source != c.source || host != c.host {
			t.Errorf("case %d: got (%q, %q), want (%q, %q)", i, source, host, c.source, c.host)
		}
	}
}

func TestUploadFrom(t *testing.T) {
	for raw, want := range map[string]string{
		"backpack": "backpack", "results_reload": "results_reload",
		"": "unknown", "unknown": "unknown", "<script>": "unknown", "Backpack": "unknown",
	} {
		if got := uploadFrom(raw); got != want {
			t.Errorf("uploadFrom(%q) = %q, want %q", raw, got, want)
		}
	}
}

// uploadDefaults are the settings readUploadSettings gives with nothing set.
var uploadDefaults = uploadSettings{
	percSpread: MinLowValueSpread, minLowVal: MinLowValueAbs, percMargin: 1,
	visualPerc: VisualPercSpread, multiplier: 1,
}

func TestUploadFacts(t *testing.T) {
	retail := uploadFacts(uploadRun{
		source: "hashes", from: "nonsense", rows: 12, cards: 12, st: uploadDefaults, stores: 4,
		elapsed: 300 * time.Millisecond,
	})
	wantFacts(t, retail, []fact{
		newFact("", "upload.source", "hashes"), newFact("", "upload.from", "unknown"), newFact("", "upload.mode", "retail"),
		newFact("", "upload.rows", "10-99"), newFact("", "upload.sealed", "none"),
		newFact("", "upload.stores", "1-4"), newFact("", "upload.duration", "<1s"),
	})
	// A retail run counts no option, even one the cookie saved away from its default.
	for _, f := range uploadFacts(uploadRun{source: "text", st: uploadDefaults, away: []string{"lowval", "highval"}}) {
		if f.name == "upload.option" {
			t.Errorf("a retail run counted %v", f)
		}
	}

	tuned := uploadDefaults
	tuned.skipHighValue, tuned.useMargin, tuned.percMargin = true, true, 0.75
	tuned.percSpread, tuned.maxQty, tuned.sorting, tuned.priceSource = 45, 4, "highspread", "credit"
	// lowval is saved off, away from its default; lowvalabs is saved off but the form turned it on.
	tuned.skipLowValueAbs = true
	buylist := uploadFacts(uploadRun{
		source: "url", host: "moxfield", buylist: true, rows: 1500, cards: 0, sealed: 3, st: tuned,
		away: []string{"lowval", "lowvalabs", "highval"}, marginChanged: true, stores: 22, customBuylist: true, indexChanged: true,
		unpacked: true, published: true, elapsed: 6 * time.Second,
	})
	wantFacts(t, buylist, []fact{
		newFact("", "upload.source", "url"), newFact("", "upload.url_host", "moxfield"), newFact("", "upload.mode", "buylist"),
		newFact("", "upload.rows", "1000+"), newFact("", "upload.sealed", "all"),
		newFact("", "upload.option", "lowval"), newFact("", "upload.option", "highval"),
		newFact("", "upload.value_set", "percspread"), newFact("", "upload.value_set", "margin"), newFact("", "upload.value_set", "maxqty"),
		newFact("", "upload.sorting", "highspread"), newFact("", "upload.price_source", "credit"),
		newFact("", "upload.custom_buylist", ""), newFact("", "upload.stores", "20+"), newFact("", "upload.index_pref", ""),
		newFact("", "upload.unpack", ""), newFact("", "upload.publish", ""), newFact("", "upload.duration", "5s+"),
	})

	handoff := uploadFacts(uploadRun{source: "handoff", origin: "www.cardmarket.com", buylist: true, rows: 1, cards: 1, sealed: 1, st: uploadDefaults})
	wantFacts(t, handoff, []fact{
		newFact("", "upload.source", "handoff"), newFact("", "upload.handoff_origin", "www.cardmarket.com"),
		newFact("", "upload.mode", "buylist"), newFact("", "upload.rows", "1-9"), newFact("", "upload.sealed", "some"),
		newFact("", "upload.price_source", "default"), newFact("", "upload.stores", "0"), newFact("", "upload.duration", "<50ms"),
	})

	// The page's 10% margin is in force but not a change.
	margin := uploadDefaults
	margin.useMargin, margin.percMargin = true, 0.9
	for _, f := range uploadFacts(uploadRun{source: "text", buylist: true, st: margin}) {
		if f.name == "upload.value_set" {
			t.Errorf("the default margin was counted: %v", f)
		}
	}

	if got := uploadFacts(uploadRun{st: uploadDefaults}); len(got) != 0 {
		t.Errorf("a run with no list yields %v", got)
	}
	// A sort the page does not offer, or a price source it does not, is not a value.
	odd := uploadDefaults
	odd.sorting, odd.priceSource = "'; drop", "anything"
	for _, f := range uploadFacts(uploadRun{source: "text", buylist: true, st: odd}) {
		if f.name == "upload.sorting" || f.name == "upload.price_source" {
			t.Errorf("an unknown value was emitted: %v", f)
		}
	}
}

// defaultsOn is uploadFacts over each source, sort and price source, with
// every flag on and then off, saved away from its default, and every setting off its default.
func defaultsOn() []fact {
	st := uploadSettings{
		skipLowValue: true, skipLowValueAbs: true, skipHighValue: true, skipHighValueAbs: true,
		useMargin: true, skipConds: true, skipPrices: true, visualIndicator: true,
		percSpread: 1, percSpreadMax: 1, minLowVal: 2, maxHighVal: 1, percMargin: 0.5,
		visualPerc: 1, multiplier: 2, maxQty: 1,
	}
	sorts := []string{"highprice", "alphabetical", "setalpha", "setchrono", "highspread", "profitability"}
	priceSources := []string{"", "credit", "marketCredit"}
	var all []fact
	for i, source := range uploadSources() {
		st.sorting = sorts[i%len(sorts)]
		st.priceSource = priceSources[i%len(priceSources)]
		all = append(all, uploadFacts(uploadRun{
			source: source, host: "other", origin: "www.cardmarket.com", from: "palette", buylist: true,
			rows: i * 100, cards: i, sealed: 1, st: st, away: uploadOptionNames(), marginChanged: true, stores: i * 3,
			customBuylist: true, indexChanged: true, unpacked: true, published: true,
			elapsed: time.Duration(i) * time.Second,
		})...)
	}
	for i, sort := range sorts {
		st.sorting, st.priceSource = sort, priceSources[i%len(priceSources)]
		all = append(all, uploadFacts(uploadRun{source: "text", buylist: true, st: st})...)
	}
	off := st
	off.skipLowValue, off.skipLowValueAbs, off.useMargin, off.visualIndicator = false, false, false, false
	return append(all, uploadFacts(uploadRun{source: "text", buylist: true, st: off, away: uploadOptionNames()})...)
}

// uploadSources are the sources uploadSourceKind can name.
func uploadSources() []string {
	return []string{"hashes", "text", "file_csv", "file_txt", "file_xls", "file_xlsx", "url", "share", "handoff"}
}

// uploadOptionNames are every option uploadFacts can count.
func uploadOptionNames() []string {
	var names []string
	for _, opt := range uploadOptions {
		names = append(names, opt.name)
	}
	return names
}

// Every fact uploadFacts can yield passes the registry.
func TestUploadFactsAreRegistered(t *testing.T) {
	v := observability.Validators{Origin: func(string) bool { return true }}
	all := defaultsOn()
	seen := map[string]bool{}
	for _, f := range all {
		seen[f.name] = true
		entry, ok := observability.Lookup(f.name)
		if !ok {
			t.Errorf("%s is not registered", f.name)
			continue
		}
		if _, _, ok := entry.Check(f.scope, f.value, v); !ok {
			t.Errorf("the registry refuses %v", f)
		}
	}
	for _, name := range []string{"upload.url_host", "upload.handoff_origin", "upload.from", "upload.option", "upload.value_set", "upload.sorting", "upload.price_source"} {
		if !seen[name] {
			t.Errorf("defaultsOn never yields %s", name)
		}
	}
}

// scriptDefaults are the fields js/upload-options.js posts when nothing is saved.
func scriptDefaults() url.Values {
	return url.Values{
		"lowval": {"true"}, "lowvalabs": {"true"}, "minmargin": {"true"}, "customperc": {"true"},
		"percspread": {"60"}, "percspreadmax": {"0"}, "minval": {"1"}, "maxval": {"0"}, "margin": {"10"},
		"custompercmax": {"100"}, "multiplier": {"1"}, "maxqty": {"0"},
		"sorting": {""}, "altPrice": {""}, "pricesource": {""},
	}
}

// uploadRequest is a parsed POST /upload carrying form and cookies.
func uploadRequest(t *testing.T, target string, form url.Values, cookies map[string]string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Dest", "document")
	for name, value := range cookies {
		r.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}
	return r
}

// A flag counts only when the reader's settings cookie saved it away from its default; the form is not read.
func TestUploadOptionsAway(t *testing.T) {
	for _, c := range []struct {
		what   string
		form   url.Values
		cookie string
		want   []string
	}{
		{"nothing saved", url.Values{}, "", nil},
		{"the script's defaults", scriptDefaults(), "", nil},
		{"a form field alone", url.Values{"highval": {"true"}}, "", nil},
		{"the defaults saved", url.Values{}, "lowval,lowvalabs,minmargin,customperc", nil},
		{"the defaults plus one", url.Values{}, "lowval,lowvalabs,minmargin,customperc,highval", []string{"highval"}},
		{"a default dropped", url.Values{}, "lowvalabs,minmargin,customperc", []string{"lowval"}},
		{"saved", url.Values{}, "nocond,lowval,noresults", []string{"lowvalabs", "minmargin", "nocond", "customperc"}},
		{"saved beats the form", url.Values{"highval": {"true"}}, "lowval,lowvalabs,minmargin,customperc,nocond", []string{"nocond"}},
	} {
		cookies := map[string]string{}
		if c.cookie != "" {
			cookies["UploadOptimizerOpts"] = c.cookie
		}
		r := uploadRequest(t, "/upload", c.form, cookies)
		if got := awayUploadOptions(r); !slices.Equal(got, c.want) {
			t.Errorf("%s: away %v, want %v", c.what, got, c.want)
		}
	}
}

// The margin counts only when its option is on and it is not the page's 10.
func TestUploadMarginChanged(t *testing.T) {
	for _, c := range []struct {
		what      string
		form      url.Values
		cookie    string
		useMargin bool
		want      bool
	}{
		{"the script's default", url.Values{"margin": {"10"}}, "", true, false},
		{"nothing posted or saved", url.Values{}, "", true, false},
		{"saved", url.Values{}, "25", true, true},
		{"posted", url.Values{"margin": {"5"}}, "", true, true},
		{"zero", url.Values{"margin": {"0"}}, "", true, true},
		{"option off", url.Values{"margin": {"25"}}, "", false, false},
		{"not a number", url.Values{"margin": {"x"}}, "", true, false},
	} {
		cookies := map[string]string{}
		if c.cookie != "" {
			cookies["UploadMargin"] = c.cookie
		}
		r := uploadRequest(t, "/upload", c.form, cookies)
		if got := uploadMarginChanged(r, uploadSettings{useMargin: c.useMargin}); got != c.want {
			t.Errorf("%s: changed %v, want %v", c.what, got, c.want)
		}
	}
}

// postHashes serves POST /upload?from=news with two cards, as a page view or a fetch.
func postHashes(t *testing.T, dest string) []observability.Row {
	t.Helper()
	cards := twoCards(t)
	withSigMode(t, true, false)
	quietUploadLog(t)
	rows := withFeatureCounter(t)

	form := url.Values{"mode": {"false"}, "hashes": cards}
	req := httptest.NewRequest(http.MethodPost, "/upload?from=news", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Dest", dest)
	testSite.Upload(httptest.NewRecorder(), req)
	return rows.rows()
}

func TestUploadCountsWhatItRanWith(t *testing.T) {
	got := postHashes(t, "document")
	wantRow(t, got, "", "upload.source", "hashes", 1)
	wantRow(t, got, "", "upload.from", "news", 1)
	wantRow(t, got, "", "upload.mode", "retail", 1)
	wantRow(t, got, "", "upload.rows", "1-9", 1)
	wantNoRow(t, got, "upload.option")
	wantNoRow(t, got, "metrics.rejected")
}

// A fetch to the same URL is not a page view and counts nothing.
func TestUploadFetchCountsNothing(t *testing.T) {
	got := postHashes(t, "empty")
	wantNoRow(t, got, "upload.source")
	wantNoRow(t, got, "upload.mode")
}

func TestUploadCountsAnEmptyPost(t *testing.T) {
	withSigMode(t, true, false)
	quietUploadLog(t)
	rows := withFeatureCounter(t)
	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Dest", "document")
	testSite.Upload(httptest.NewRecorder(), req)
	got := rows.rows()
	wantRow(t, got, "none", "upload.parse_error", "no_list", 1)
	wantNoRow(t, got, "upload.mode")
}

func TestUploadCountsShareOpens(t *testing.T) {
	t.Run("gone", func(t *testing.T) {
		rows := withFeatureCounter(t)
		openShare(t, shareTestReader{})
		got := rows.rows()
		wantRow(t, got, "", "upload_share.open", "gone", 1)
		wantNoRow(t, got, "upload.mode")
	})
	t.Run("ok", func(t *testing.T) {
		rows := withFeatureCounter(t)
		share := userstate.UploadShare{Key: goodShareKey, Rows: shareRows(3)}
		openShare(t, shareTestReader{share: share, found: true})
		got := rows.rows()
		wantRow(t, got, "", "upload_share.open", "ok", 1)
		wantNoRow(t, got, "metrics.rejected")
	})
}

// A load that fails is counted under its source.
func TestUploadCountsALoadError(t *testing.T) {
	withSigMode(t, true, false)
	quietUploadLog(t)
	rows := withFeatureCounter(t)
	form := url.Values{"gdocURL": {"https://example.test/list"}}
	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Dest", "document")
	testSite.Upload(httptest.NewRecorder(), req)
	got := rows.rows()
	wantRow(t, got, "url", "upload.parse_error", "load_error", 1)
	wantNoRow(t, got, "upload.mode")
}

// A buylist upload from the uploader counts what the reader saved, not
// the defaults the page's script posts.
func TestUploadCountsSavedBuylistOptions(t *testing.T) {
	post := func(t *testing.T, form url.Values, cookies map[string]string) []observability.Row {
		t.Helper()
		cards := twoCards(t)
		withSigMode(t, true, false)
		quietUploadLog(t)
		rows := withFeatureCounter(t)
		if !form.Has("mode") {
			form.Set("mode", "true")
		}
		form["hashes"] = cards
		testSite.Upload(httptest.NewRecorder(), uploadRequest(t, "/upload?from=upload_form", form, cookies))
		return rows.rows()
	}
	t.Run("defaults", func(t *testing.T) {
		got := post(t, scriptDefaults(), nil)
		wantRow(t, got, "", "upload.mode", "buylist", 1)
		wantNoRow(t, got, "upload.option")
		wantNoRow(t, got, "upload.value_set")
		wantNoRow(t, got, "metrics.rejected")
	})
	t.Run("saved", func(t *testing.T) {
		form := scriptDefaults()
		for _, k := range []string{"lowval", "lowvalabs", "customperc"} {
			form.Del(k)
		}
		form.Set("highval", "true")
		form.Set("margin", "25")
		got := post(t, form, map[string]string{"UploadOptimizerOpts": "highval,minmargin", "UploadMargin": "25"})
		wantRow(t, got, "", "upload.mode", "buylist", 1)
		for _, opt := range []string{"lowval", "lowvalabs", "highval", "customperc"} {
			wantRow(t, got, "", "upload.option", opt, 1)
		}
		if n := len(find(got, "upload.option")); n != 4 {
			t.Errorf("%d upload.option rows, want 4", n)
		}
		wantRow(t, got, "", "upload.value_set", "margin", 1)
		if n := len(find(got, "upload.value_set")); n != 1 {
			t.Errorf("%d upload.value_set rows, want 1", n)
		}
		wantRow(t, got, "", "upload.price_source", "default", 1)
		wantNoRow(t, got, "metrics.rejected")
	})
	t.Run("defaults saved", func(t *testing.T) {
		got := post(t, scriptDefaults(), map[string]string{"UploadOptimizerOpts": "lowval,lowvalabs,minmargin,customperc"})
		wantRow(t, got, "", "upload.mode", "buylist", 1)
		wantNoRow(t, got, "upload.option")
	})
	t.Run("defaults plus one", func(t *testing.T) {
		form := scriptDefaults()
		form.Set("highval", "true")
		got := post(t, form, map[string]string{"UploadOptimizerOpts": "lowval,lowvalabs,minmargin,customperc,highval"})
		wantRow(t, got, "", "upload.option", "highval", 1)
		if n := len(find(got, "upload.option")); n != 1 {
			t.Errorf("%d upload.option rows, want 1", n)
		}
	})
	t.Run("retail", func(t *testing.T) {
		form := scriptDefaults()
		form.Set("mode", "false")
		got := post(t, form, map[string]string{"UploadOptimizerOpts": "highval,minmargin"})
		wantRow(t, got, "", "upload.mode", "retail", 1)
		wantNoRow(t, got, "upload.option")
		wantNoRow(t, got, "metrics.rejected")
	})
	t.Run("a default dropped", func(t *testing.T) {
		form := scriptDefaults()
		form.Del("lowval")
		got := post(t, form, map[string]string{"UploadOptimizerOpts": "lowvalabs,minmargin,customperc"})
		wantRow(t, got, "", "upload.option", "lowval", 1)
		if n := len(find(got, "upload.option")); n != 1 {
			t.Errorf("%d upload.option rows, want 1", n)
		}
	})
}

func TestUploadTag(t *testing.T) {
	for tag, want := range map[string][2]string{
		"SCGRetail": {"SCG", "load_at"}, "CK": {"CK", "csv"}, "SCG": {"SCG", "csv"},
		"TCG": {"TCG", "tcg_remove"}, "": {"", ""}, "CKRetail": {"", ""},
	} {
		scope, value := uploadTag(tag)
		if scope != want[0] || value != want[1] {
			t.Errorf("uploadTag(%q) = (%q, %q), want %v", tag, scope, value, want)
		}
	}
}

func TestUploadExportScope(t *testing.T) {
	for raw, want := range map[string]string{"singles": "singles", "sealed": "sealed", "": "all", "x": "all"} {
		if got := uploadExportScope(raw); got != want {
			t.Errorf("uploadExportScope(%q) = %q, want %q", raw, got, want)
		}
	}
}

// A transfer is counted once it was served, not when its store is missing or the write failed.
func TestUploadTagIsCounted(t *testing.T) {
	quietUploadLog(t)
	s := uploadCountSite(t)
	post := func(w http.ResponseWriter, tag string) {
		form := url.Values{"tag": {tag}, tag + "hashes": {"FIXTUREA-1"}, tag + "hashesQtys": {"1"}}
		req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		s.Upload(w, req)
	}

	rows := withFeatureCounter(t)
	for _, tag := range []string{"TCG", "CK"} {
		rec := httptest.NewRecorder()
		post(rec, tag)
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "csv") {
			t.Fatalf("the %s transfer answered %q, want a CSV", tag, ct)
		}
	}
	post(httptest.NewRecorder(), "SCG")                  // no SCG buylist: the page answers
	post(failingResponse{httptest.NewRecorder()}, "TCG") // the client went away
	post(failingResponse{httptest.NewRecorder()}, "CK")
	got := rows.rows()
	wantRow(t, got, "TCG", "upload.tag", "tcg_remove", 1)
	wantRow(t, got, "CK", "upload.tag", "csv", 1)
	if n := len(find(got, "upload.tag")); n != 2 {
		t.Errorf("%d upload.tag rows, want 2", n)
	}
}

// uploadCountSite is a fixture site with one card, a TCGPlayer seller and a CK buylist.
func uploadCountSite(t *testing.T) *site {
	t.Helper()
	b := fixtureBackend("FIXTUREA", "Fixture Edition Alpha", "2020-01-01", [][2]string{{"Fixture Card Alpha", "1"}})
	tcg := mtgban.InventoryRecord{}
	tcg.Add("FIXTUREA-1", &mtgban.InventoryEntry{Conditions: "NM", Price: 1.5, InstanceID: "111"})
	ck := mtgban.BuylistRecord{"FIXTUREA-1": {{CustomFields: map[string]string{"CKTitle": "A", "CKEdition": "Set"}}}}
	return fixtureSite(t, b,
		[]mtgban.Seller{mtgban.NewSellerFromInventory(tcg, mtgban.ScraperInfo{Shorthand: "TCGPlayer"})},
		[]mtgban.Vendor{mtgban.NewVendorFromBuylist(ck, mtgban.ScraperInfo{Shorthand: "CK"})})
}

// The deckbox and TCGplayer exports of one card are counted once served, not when the write failed.
func TestUploadCardExportsAreCounted(t *testing.T) {
	withSigMode(t, true, false)
	quietUploadLog(t)
	s := uploadCountSite(t)
	post := func(w http.ResponseWriter, export string) {
		form := url.Values{"mode": {"false"}, export: {"true"}, "rows": {"FIXTUREA-1\t1\n"}}
		req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		s.Upload(w, req)
	}

	rows := withFeatureCounter(t)
	for _, export := range []string{"tcgplayer_csv", "deckbox"} {
		rec := httptest.NewRecorder()
		post(rec, export)
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "csv") {
			t.Fatalf("the %s export answered %q, want a CSV", export, ct)
		}
		post(failingResponse{httptest.NewRecorder()}, export)
	}
	got := rows.rows()
	wantRow(t, got, "all", "upload.export", "tcgplayer_csv", 1)
	wantRow(t, got, "all", "upload.export", "deckbox", 1)
	if n := len(find(got, "upload.export")); n != 2 {
		t.Errorf("%d upload.export rows, want 2", n)
	}
}

func TestURLPrefixRedirectIsCounted(t *testing.T) {
	rows := withFeatureCounter(t)
	UploadURLRedirect(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/https:/www.moxfield.com/decks/abc", nil))
	UploadURLRedirect(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/https:/", nil)) // no host: not counted
	wantRow(t, rows.rows(), "", "upload.source", "url_prefix", 1)
}

func TestHandoffPageIsCounted(t *testing.T) {
	signingEnabled(t, true)
	rows := withFeatureCounter(t)
	granted := signedAs(t, url.Values{"Upload": {"true"}, "UserTier": {"Pro"}}, time.Now().Add(time.Hour))
	for _, sig := range []string{"", granted} {
		req := httptest.NewRequest(http.MethodGet, "/upload/handoff", nil)
		req.Header.Set("Sec-Fetch-Dest", "document")
		if sig != "" {
			req.AddCookie(&http.Cookie{Name: "BAN_SIG", Value: sig})
		}
		testSite.UploadHandoff(httptest.NewRecorder(), req)
	}
	// A fetch of the page is not a view.
	req := httptest.NewRequest(http.MethodGet, "/upload/handoff", nil)
	req.Header.Set("Sec-Fetch-Dest", "empty")
	testSite.UploadHandoff(httptest.NewRecorder(), req)

	got := rows.rows()
	wantRow(t, got, "", "upload.handoff_page", "locked", 1)
	wantRow(t, got, "", "upload.handoff_page", "shown", 1)
}

func TestUploadShareCreateIsCounted(t *testing.T) {
	withSigMode(t, false, true)
	rows := withFeatureCounter(t)
	code, body := shareStatus(t, &fakeShareWriter{}, shareRequest(t, "Legacy", nextShareEmail(), uploadGrant, `{"rows":"uuid-1\t1\t\t\t\t\t","buylist":true}`, true))
	if code != http.StatusCreated {
		t.Fatalf("status %d body %v", code, body)
	}
	got := rows.rows()
	wantRow(t, got, "", "upload_share.create", "buylist", 1)

	rows = withFeatureCounter(t)
	shareStatus(t, &fakeShareWriter{}, shareRequest(t, "Legacy", nextShareEmail(), uploadGrant, `{"rows":""}`, true))
	shareStatus(t, &fakeShareWriter{fail: errors.New("down")}, shareRequest(t, "Legacy", nextShareEmail(), uploadGrant, `{"rows":"uuid-1\t1\t\t\t\t\t"}`, true))
	wantNoRow(t, rows.rows(), "upload_share.create")
}

// An export is counted once served, scoped by csvscope, and not when the write failed.
func TestUploadExportIsCounted(t *testing.T) {
	cards := twoCards(t)
	withSigMode(t, true, false)
	quietUploadLog(t)
	post := func(w http.ResponseWriter, form url.Values) {
		form.Set("mode", "false")
		form.Set("rows", cards[0]+"\t1\n"+cards[1]+"\t1\n")
		req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		testSite.Upload(w, req)
	}

	rows := withFeatureCounter(t)
	rec := httptest.NewRecorder()
	post(rec, url.Values{"download": {"true"}, "csvscope": {"singles"}})
	if got := rec.Header().Get("Content-Type"); got != "text/csv" {
		t.Fatalf("the download came back as %q, want a file", got)
	}
	post(httptest.NewRecorder(), url.Values{"deckbox": {"true"}})
	post(failingResponse{httptest.NewRecorder()}, url.Values{"download": {"true"}})
	got := rows.rows()
	wantRow(t, got, "singles", "upload.export", "download", 1)
	wantRow(t, got, "all", "upload.export", "deckbox", 1)
	if n := len(find(got, "upload.export")); n != 2 {
		t.Errorf("%d upload.export rows, want 2", n)
	}
	wantNoRow(t, got, "metrics.rejected")
}
