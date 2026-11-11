package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/observability"
	"github.com/mtgban/mtgban-website/ratelimit"
)

const googlebotUA = "Googlebot/2.1 (+http://www.google.com/bot.html)"

func TestMetricDims(t *testing.T) {
	signingEnabled(t, false)
	installAccess(t, `{"Any": {}, "Legacy": {}}`, `[]`)
	fields := url.Values{"UserEmail": {"reader@example.com"}, "UserTier": {"Legacy"}}
	signed := signedAs(t, fields, time.Now().Add(time.Hour))

	anon := httptest.NewRequest(http.MethodGet, "/search", nil)
	if d := metricDims(anon); d.Tier != "Any" || d.Signed || d.Device != "desktop" || d.Bot || d.Instance != observabilityInstance {
		t.Errorf("anonymous dims = %+v", d)
	}
	member := httptest.NewRequest(http.MethodGet, "/search", nil)
	member.AddCookie(&http.Cookie{Name: "BAN_SIG", Value: signed})
	if d := metricDims(member); d.Tier != "Legacy" || !d.Signed {
		t.Errorf("member dims = %+v", d)
	}
	phone := httptest.NewRequest(http.MethodGet, "/search", nil)
	phone.AddCookie(&http.Cookie{Name: "MobileView", Value: "true"})
	if d := metricDims(phone); d.Device != "mobile" {
		t.Errorf("mobile dims = %+v", d)
	}

	linked := httptest.NewRequest(http.MethodGet, "/search?sig="+url.QueryEscape(signed), nil)
	if d := metricDims(linked); d.Tier != "Legacy" || !d.Signed {
		t.Errorf("?sig= in the URL dims = %+v", d)
	}

	// A form a wrapper already parsed is read, its body sig included.
	parsed := httptest.NewRequest(http.MethodPost, "/search", strings.NewReader(url.Values{"sig": {signed}}.Encode()))
	parsed.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := parsed.ParseForm(); err != nil {
		t.Fatal(err)
	}
	if d := metricDims(parsed); d.Tier != "Legacy" || !d.Signed {
		t.Errorf("an already parsed form's sig dims = %+v", d)
	}

	// A signed cookie tampered with after signing is not trusted.
	raw, err := base64.StdEncoding.DecodeString(signed)
	if err != nil {
		t.Fatal(err)
	}
	v, err := url.ParseQuery(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	v.Set("UserTier", "ROOT")
	forged := httptest.NewRequest(http.MethodGet, "/search", nil)
	forged.AddCookie(&http.Cookie{Name: "BAN_SIG", Value: base64.StdEncoding.EncodeToString([]byte(v.Encode()))})
	if d := metricDims(forged); d.Tier != "Any" || d.Signed {
		t.Errorf("forged dims = %+v", d)
	}
}

// untouchedBody fails the test if anything reads it.
type untouchedBody struct{ t *testing.T }

func (b untouchedBody) Read([]byte) (int, error) {
	b.t.Error("the request body was read")
	return 0, io.EOF
}

// Working out the dimensions never reads or parses the request body.
func TestMetricDimsLeaveTheBodyUnread(t *testing.T) {
	signingEnabled(t, false)
	for _, contentType := range []string{"multipart/form-data; boundary=x", "application/x-www-form-urlencoded"} {
		r := httptest.NewRequest(http.MethodPost, "/search", untouchedBody{t})
		r.Header.Set("Content-Type", contentType)
		if d := metricDims(r); d.Tier != "Any" || d.Signed {
			t.Errorf("%s: dims = %+v, want anonymous", contentType, d)
		}
		if r.Form != nil || r.MultipartForm != nil {
			t.Errorf("%s: the form was parsed", contentType)
		}
	}
}

// An invite link is signed with no email: a tier, but not a signed-in reader.
func TestInviteIsNotSignedIn(t *testing.T) {
	signingEnabled(t, false)
	installAccess(t, `{"Any": {}, "Legacy": {}}`, `[]`)
	invite := signedAs(t, url.Values{"UserTier": {"Legacy"}}, time.Now().Add(time.Hour))
	r := httptest.NewRequest(http.MethodGet, "/search", nil)
	r.AddCookie(&http.Cookie{Name: "BAN_SIG", Value: invite})
	if d := metricDims(r); d.Signed || d.Tier != "Legacy" {
		t.Errorf("an invite with no email counted as signed in: %+v", d)
	}
}

// The dimensions are worked out once however many facts a request emits.
func TestDimsAreComputedOncePerRequest(t *testing.T) {
	bot := httptest.NewRequest(http.MethodGet, "/search", nil)
	bot.Header.Set("User-Agent", googlebotUA)
	if d := metricDims(bot); !d.Bot {
		t.Fatalf("the user agent the test relies on does not read as a bot: %+v", d)
	}

	r := withDimsHolder(httptest.NewRequest(http.MethodGet, "/search", nil))
	first := metricDims(r)
	r.Header.Set("User-Agent", googlebotUA) // would flip Bot if recomputed
	if second := metricDims(r); second != first {
		t.Errorf("dims recomputed: %+v then %+v", first, second)
	}
}

// A holder the wrapper installed and a route then filled is what both requests read.
func TestWithMetricDimsFillsTheInstalledHolder(t *testing.T) {
	api := observability.Dims{Instance: "test", Tier: "api", Device: "api", Signed: true}

	outer := withDimsHolder(httptest.NewRequest(http.MethodGet, "/api/v2/retail/all.json", nil))
	inner := withMetricDims(outer, api)
	if got := metricDims(outer); got != api {
		t.Errorf("the wrapper's request reads %+v, want %+v", got, api)
	}
	if got := metricDims(inner); got != api {
		t.Errorf("the returned request reads %+v, want %+v", got, api)
	}

	// Dims already computed are replaced, not kept.
	late := withDimsHolder(httptest.NewRequest(http.MethodGet, "/api/v2/retail/all.json", nil))
	if d := metricDims(late); d.Device != "desktop" {
		t.Fatalf("before the route sets them: %+v", d)
	}
	withMetricDims(late, api)
	if got := metricDims(late); got != api {
		t.Errorf("after the route sets them: %+v, want %+v", got, api)
	}

	// With no holder there is nothing to fill: only the returned request carries d.
	bare := httptest.NewRequest(http.MethodGet, "/api/v2/retail/all.json", nil)
	filled := withMetricDims(bare, api)
	if got := metricDims(filled); got != api {
		t.Errorf("a request with no holder: the returned one reads %+v, want %+v", got, api)
	}
	if got := metricDims(bare); got.Device == "api" {
		t.Errorf("a request with no holder is left as it was: %+v", got)
	}
}

func TestMetricValidatorsTakeNoSnapshot(t *testing.T) {
	v := metricValidators(nil)
	if v.Store("CK") {
		t.Error("with no snapshot no store is known")
	}
	if !v.Page("search") || !v.Page("newspaper/syp") || v.Page("other") || v.Page("wp-login.php") {
		t.Error("Page accepts exactly the labels in pageLabels")
	}
	for _, label := range pageLabels() {
		if !v.Page(label) {
			t.Errorf("Page refuses %q, which pageLabels lists", label)
		}
	}
	if v.Route == nil || !v.Route("search") || !v.Route("api.v2") || v.Route("other") || v.Route("wp-login.php") {
		t.Error("Route accepts exactly the labels routeLabel returns")
	}
	if v.Setting != nil || v.SettingValue != nil || v.Origin != nil {
		t.Error("the settings and origin checks arrive in 2e and 1c")
	}
}

// A store is checked against the snapshot the caller hands over, and only there.
func TestObserveStoreChecksTheSnapshot(t *testing.T) {
	ck := mtgban.NewSellerFromInventory(mtgban.InventoryRecord{}, mtgban.ScraperInfo{Shorthand: "CK", Name: "Card Kingdom"})
	syp := mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{}, mtgban.ScraperInfo{Shorthand: "SYP"})
	p := newPrices(nil, []mtgban.Seller{ck}, []mtgban.Vendor{syp}, scraperIndex{})

	v := metricValidators(p)
	if !v.Store("CK") || !v.Store("SYP") {
		t.Error("a loaded seller or vendor is a known store")
	}
	if v.Store("Bob's Cards") || v.Store("ck") {
		t.Error("only an exact loaded shorthand is a known store")
	}
	if metricValidators(nil).Store("CK") {
		t.Error("with no snapshot no store is known")
	}

	rows := withFeatureCounter(t)
	r := httptest.NewRequest(http.MethodGet, "/search", nil)
	observeStore(r, p, "search", "http.status", "2xx")
	observeStore(r, nil, "search", "http.status", "2xx") // a nil snapshot is not a refusal
	observeStore(r, p, "", "no.such.name", "")
	got := rows.rows()
	status := find(got, "http.status")
	if len(status) != 1 || status[0].Scope != "search" || status[0].Value != "2xx" || status[0].N != 2 {
		t.Errorf("http.status rows = %+v, want one row search/2xx with n 2", status)
	}
	if rejected := find(got, "metrics.rejected"); len(rejected) != 1 || rejected[0].N != 1 {
		t.Errorf("metrics.rejected rows = %+v, want one row with n 1", rejected)
	}
}

func TestObserveFactsEmitsEach(t *testing.T) {
	rows := withFeatureCounter(t)
	r := httptest.NewRequest(http.MethodGet, "/search", nil)
	observeFacts(r, nil, []fact{
		newFact("search", "http.status", "2xx"),
		newFact("search", "http.status", "2xx"),
		newFact("search", "http.duration", "<50ms"),
		newFact("", "http.status", "2xx"), // a scoped name with no scope
		newFact("", "no.such.name", ""),
	})
	observeFacts(r, nil, nil) // nothing to emit
	got := rows.rows()
	status := find(got, "http.status")
	if len(status) != 1 || status[0].Scope != "search" || status[0].Value != "2xx" || status[0].N != 2 {
		t.Errorf("http.status rows = %+v, want one row search/2xx with n 2", status)
	}
	duration := find(got, "http.duration")
	if len(duration) != 1 || duration[0].Scope != "search" || duration[0].Value != "<50ms" || duration[0].N != 1 {
		t.Errorf("http.duration rows = %+v, want one row search/<50ms with n 1", duration)
	}
	if rejected := find(got, "metrics.rejected"); len(rejected) != 1 || rejected[0].N != 2 {
		t.Errorf("metrics.rejected rows = %+v, want one row with n 2", rejected)
	}
}

// With no counter every helper returns before working out the dimensions.
func TestNilCounterIsSafe(t *testing.T) {
	prev := FeatureCounter
	t.Cleanup(func() { FeatureCounter = prev })
	FeatureCounter = nil

	r := withDimsHolder(httptest.NewRequest(http.MethodGet, "/", nil))
	observe(r, "page.view", "home")
	observeScoped(r, "search", "http.status", "2xx")
	observeStore(r, nil, "search", "http.status", "2xx")
	observeJob("job", "", "ratelimit.reject", "page")
	observeFacts(r, nil, []fact{newFact("", "page.view", "home")})
	if dimsHolderSet(r) {
		t.Error("a helper worked out the dimensions with no counter installed")
	}
}

func TestSmallCountAndPageBucket(t *testing.T) {
	for n, want := range map[int]string{-1: "0", 0: "0", 1: "1", 2: "2", 3: "3-5", 5: "3-5", 6: "6+", 400: "6+"} {
		if got := smallCount(n); got != want {
			t.Errorf("smallCount(%d) = %q, want %q", n, got, want)
		}
	}
	for n, want := range map[int]string{-1: "1", 0: "1", 1: "1", 2: "2", 3: "3-5", 5: "3-5", 6: "6+", 400: "6+"} {
		if got := pageBucket(n); got != want {
			t.Errorf("pageBucket(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestObserveStoresARegisteredValue(t *testing.T) {
	rows := withFeatureCounter(t)
	r := httptest.NewRequest(http.MethodGet, "/search", nil)
	observe(r, "page.view", "search")
	observeScoped(r, "search", "http.status", "2xx")
	got := rows.rows()
	view := find(got, "page.view")
	if len(view) != 1 {
		t.Fatalf("page.view rows = %+v, want one", view)
	}
	if v := view[0]; v.Scope != "" || v.Value != "search" || v.N != 1 || v.Instance != "test" || v.Device != "desktop" {
		t.Errorf("page.view row = %+v", v)
	}
	status := find(got, "http.status")
	if len(status) != 1 || status[0].Scope != "search" || status[0].Value != "2xx" || status[0].N != 1 {
		t.Errorf("http.status rows = %+v, want one row search/2xx with n 1", status)
	}
	if rejected := find(got, "metrics.rejected"); len(rejected) != 0 {
		t.Errorf("metrics.rejected rows = %+v, want none", rejected)
	}
}

func TestObserveRejectsWhatTheRegistryDoesNotAllow(t *testing.T) {
	rows := withFeatureCounter(t)
	r := httptest.NewRequest(http.MethodGet, "/search?x=<script>", nil)
	observeScoped(r, "search", "http.status", r.FormValue("x")) // a raw parameter as the value
	observe(r, "http.status", "2xx")                            // a scoped name sent with no scope
	observe(r, "no.such.name", "")
	got := rows.rows()
	if status := find(got, "http.status"); len(status) != 0 {
		t.Errorf("http.status rows = %+v, want none", status)
	}
	if unknown := find(got, "no.such.name"); len(unknown) != 0 {
		t.Errorf("no.such.name rows = %+v, want none", unknown)
	}
	if rejected := find(got, "metrics.rejected"); len(rejected) != 1 || rejected[0].N != 3 {
		t.Errorf("metrics.rejected rows = %+v, want one row with n 3", rejected)
	}
}

func TestObserveJobCarriesTheJobDims(t *testing.T) {
	rows := withFeatureCounter(t)
	observeJob("job", "", "ratelimit.reject", "page")
	got := find(rows.rows(), "ratelimit.reject")
	if len(got) != 1 {
		t.Fatalf("ratelimit.reject rows = %+v, want one", got)
	}
	want := observability.Dims{Instance: "test", Device: "job"}
	if got[0].Dims != want || got[0].Value != "page" || got[0].N != 1 {
		t.Errorf("ratelimit.reject row = %+v, want dims %+v and page with n 1", got[0], want)
	}
}

func TestPageViewIsCounted(t *testing.T) {
	prev := ObservabilityRecorder
	t.Cleanup(func() { ObservabilityRecorder = prev })
	ObservabilityRecorder = nil

	rows := withFeatureCounter(t)
	r := httptest.NewRequest(http.MethodGet, "/newspaper?page=syp", nil)
	r.Header.Set("Sec-Fetch-Dest", "document")
	recordPageHit(r) // ObservabilityRecorder nil: the events row is skipped, page.view is not
	view := find(rows.rows(), "page.view")
	if len(view) != 1 || view[0].Value != "newspaper/syp" || view[0].N != 1 {
		t.Errorf("page.view rows = %+v, want one newspaper/syp with n 1", view)
	}
}

// What Discord emits while it closes is written: the counter closes after it.
func TestShutdownClosesTheCounterAfterDiscord(t *testing.T) {
	prev := discordCleanup
	t.Cleanup(func() { discordCleanup = prev })
	discordCleanup = func() { observeJob("discord", "", "ratelimit.reject", "page") }

	rows := withFeatureCounter(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	(&site{}).shutdownTelemetry(ctx)

	// Written by shutdownTelemetry's own close, before rows() closes again.
	if got := find(rows.store.snapshot(), "ratelimit.reject"); len(got) != 1 {
		t.Errorf("rows written by the shutdown = %+v, want the one Discord emitted while closing", got)
	}
	observeJob("job", "", "ratelimit.reject", "vote") // the counter is closed: not counted

	got := find(rows.rows(), "ratelimit.reject")
	if len(got) != 1 || got[0].Device != "discord" || got[0].Value != "page" || got[0].N != 1 {
		t.Errorf("ratelimit.reject rows = %+v, want only the one Discord emitted while closing", got)
	}
}

func TestRefusalReasons(t *testing.T) {
	for status, want := range map[int]string{401: "unauthenticated", 429: "rate_limited", 403: "other", 500: "other"} {
		if got := refusalReason(status); got != want {
			t.Errorf("refusalReason(%d) = %q, want %q", status, got, want)
		}
	}
}

// A refusal written by signing is counted under the route it refused.
func TestSigningRefusalIsCounted(t *testing.T) {
	rows := withFeatureCounter(t)
	for _, status := range []int{http.StatusUnauthorized, http.StatusTooManyRequests} {
		r := httptest.NewRequest(http.MethodGet, "/search", nil)
		r.Pattern = "/search"
		signingRefusal{status: status, msg: "no"}.write(httptest.NewRecorder(), r, nil, "", true)
	}
	var got []string
	for _, row := range find(rows.rows(), "auth.refuse") {
		got = append(got, fmt.Sprintf("%s/%s/%d", row.Scope, row.Value, row.N))
	}
	slices.Sort(got)
	if want := []string{"search/rate_limited/1", "search/unauthenticated/1"}; !slices.Equal(got, want) {
		t.Errorf("auth.refuse rows = %v, want %v", got, want)
	}
}

// A signed reader without the page's grant gets the BANned page, counted as
// no_access; one with the grant is not counted.
func TestNoAccessIsCounted(t *testing.T) {
	handler := anyTierNav(t, "BODY")
	savedFields := SignedFields
	SignedFields = append(slices.Clone(SignedFields), "Gated")
	t.Cleanup(func() { SignedFields = savedFields })
	UserRateLimiter = ratelimit.NewLimiter(1000, 1000) // anyTierNav restores it

	rows := withFeatureCounter(t)
	for _, fields := range []url.Values{
		{"UserTier": {"Legacy"}},
		{"UserTier": {"Legacy"}, "Gated": {"true"}},
	} {
		req := httptest.NewRequest(http.MethodGet, "/gated", nil)
		req.Pattern = "/gated"
		req.AddCookie(&http.Cookie{Name: "BAN_SIG", Value: signedAs(t, fields, time.Now().Add(time.Hour))})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if granted := fields.Get("Gated") != ""; granted != strings.Contains(rec.Body.String(), "BODY") {
			t.Fatalf("granted=%v: body %q", granted, rec.Body.String())
		}
	}
	// The test nav is not a registered route, so its label folds to other.
	got := find(rows.rows(), "auth.refuse")
	if len(got) != 1 || got[0].Value != "no_access" || got[0].Scope != "other" || got[0].N != 1 {
		t.Errorf("auth.refuse rows = %+v, want one no_access", got)
	}
}

// Each root-package limiter counts its refusal under its own value.
func TestRateLimitRefusalsAreCounted(t *testing.T) {
	savedAPI, savedUpload, savedShared := APIRateLimiter, uploadShareLimiter, sharedPageLimiter
	t.Cleanup(func() {
		APIRateLimiter, uploadShareLimiter, sharedPageLimiter = savedAPI, savedUpload, savedShared
	})
	refuseAll := func() *ratelimit.Limiter { return ratelimit.NewLimiter(0, 0) }
	APIRateLimiter, uploadShareLimiter, sharedPageLimiter = refuseAll(), refuseAll(), refuseAll()
	rows := withFeatureCounter(t)

	// Signed by the real ACL, before anyTierNav swaps it.
	withSigMode(t, false, true)
	upload, _ := shareStatus(t, &fakeShareWriter{}, shareRequest(t, "Legacy", nextShareEmail(), uploadGrant, `{"rows":"uuid-1	1					"}`, true))
	shared := sharedGet(t, &fakeShareStore{}, "?id="+liveShareID, "192.0.2.92:1", false)

	api := httptest.NewRecorder()
	apiReq := httptest.NewRequest(http.MethodGet, "/api/load/cardkingdom", nil)
	apiReq.RemoteAddr = "192.0.2.91:1234"
	enforceAPISigning(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(api, apiReq)

	handler := anyTierNav(t, "BODY")
	UserRateLimiter = refuseAll() // anyTierNav restores it
	page := httptest.NewRecorder()
	handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/gated", nil))

	for name, code := range map[string]int{"page": page.Code, "api": api.Code, "upload": upload, "shared": shared.Code} {
		want := http.StatusTooManyRequests
		if name == "page" {
			want = http.StatusOK // the error page is rendered with 200
		}
		if code != want {
			t.Errorf("%s answered %d, want %d", name, code, want)
		}
	}
	got := rows.rows()
	var values []string
	for _, row := range find(got, "ratelimit.reject") {
		values = append(values, row.Value)
	}
	slices.Sort(values)
	if want := []string{"api", "favorites_share", "page", "upload_share"}; !slices.Equal(values, want) {
		t.Errorf("ratelimit.reject values = %v, want %v", values, want)
	}
	if refuse := find(got, "auth.refuse"); len(refuse) != 1 || refuse[0].Value != "rate_limited" {
		t.Errorf("auth.refuse rows = %+v, want one rate_limited", refuse)
	}
}

// The vote limiter's refusal is counted; the vote it let through is not.
func TestVoteRateLimitIsCounted(t *testing.T) {
	saved := popularVoteLimiter
	t.Cleanup(func() { popularVoteLimiter = saved })
	popularVoteLimiter = ratelimit.NewLimiter(0, 1)
	withSigMode(t, true, false)
	s := newSite()

	rows := withFeatureCounter(t)
	var codes []int
	for range 2 {
		w := httptest.NewRecorder()
		s.PopularVoteAPI(w, voteRequest(http.MethodPost, devSig("vote-limit@b.com", "Legacy"), "x"))
		codes = append(codes, w.Code)
	}
	if !slices.Equal(codes, []int{http.StatusNoContent, http.StatusTooManyRequests}) {
		t.Fatalf("codes %v, want 204 then 429", codes)
	}
	got := find(rows.rows(), "ratelimit.reject")
	if len(got) != 1 || got[0].Value != "vote" || got[0].N != 1 {
		t.Errorf("ratelimit.reject rows = %+v, want one vote", got)
	}
}

// A tier the ACL does not name is stored as other; a real one is kept.
func TestUnknownTiersFoldToOther(t *testing.T) {
	signingEnabled(t, false)
	installAccess(t, `{"Any": {}, "Legacy": {}}`, `[]`)
	for tier, want := range map[string]string{"Legacy": "Legacy", "": "Any", "Any": "Any", "ROOT": "other", "Leg\x00acy": "other", "\xff": "other"} {
		r := httptest.NewRequest(http.MethodGet, "/search", nil)
		r.AddCookie(&http.Cookie{Name: "BAN_SIG", Value: signedAs(t, url.Values{"UserEmail": {"a@b.com"}, "UserTier": {tier}}, time.Now().Add(time.Hour))})
		if got := metricDims(r).Tier; got != want {
			t.Errorf("tier %q is stored as %q, want %q", tier, got, want)
		}
	}
	// The API's dims are set by a trusted caller and kept as they are.
	api := withMetricDims(httptest.NewRequest(http.MethodGet, "/api/v2/", nil), observability.Dims{Tier: "api"})
	if got := metricDims(api).Tier; got != "api" {
		t.Errorf("withMetricDims tier = %q, want api", got)
	}
}

// dimsSignature picks the signature verifiedRequestSignature picks on a GET.
func TestDimsSignatureAgreesWithVerifiedRequestSignature(t *testing.T) {
	signingEnabled(t, false)
	valid := signedAs(t, url.Values{"UserEmail": {"a@b.com"}, "UserTier": {"Legacy"}}, time.Now().Add(time.Hour))
	other := signedAs(t, url.Values{"UserEmail": {"c@d.com"}, "UserTier": {"Vintage"}}, time.Now().Add(time.Hour))
	expired := signedAs(t, url.Values{"UserEmail": {"a@b.com"}, "UserTier": {"Legacy"}}, time.Now().Add(-time.Hour))
	type sigCase struct{ name, cookie, legacy, query string }
	cases := []sigCase{
		{name: "cookie only", cookie: valid},
		{name: "query only", query: valid},
		{name: "both", cookie: valid, query: other},
		{name: "expired cookie, valid query", cookie: expired, query: valid},
		{name: "valid cookie, tampered query", cookie: valid, query: tampered(other)},
		{name: "legacy cookie", legacy: valid},
		{name: "expired cookie beside a legacy one", cookie: expired, legacy: other},
		{name: "nothing"},
	}
	build := func(c sigCase) *http.Request {
		target := "/search"
		if c.query != "" {
			target += "?sig=" + url.QueryEscape(c.query)
		}
		r := httptest.NewRequest(http.MethodGet, target, nil)
		if c.cookie != "" {
			r.AddCookie(&http.Cookie{Name: signatureCookie, Value: c.cookie})
		}
		if c.legacy != "" {
			r.AddCookie(&http.Cookie{Name: legacySignatureCookie, Value: c.legacy})
		}
		return r
	}
	for _, c := range cases {
		got := dimsSignature(build(c))
		if want := verifiedRequestSignature(build(c)); got != want {
			t.Errorf("%s: dimsSignature = %.12q, verifiedRequestSignature = %.12q", c.name, got, want)
		}
	}
}

// An unknown page is not counted as a view; its events row is unchanged.
func TestPageViewSkipsOther(t *testing.T) {
	prev := ObservabilityRecorder
	t.Cleanup(func() { ObservabilityRecorder = prev })
	ObservabilityRecorder = nil

	rows := withFeatureCounter(t)
	r := httptest.NewRequest(http.MethodGet, "/wp-login.php", nil)
	recordPageHit(r)
	got := rows.rows()
	if view := find(got, "page.view"); len(view) != 0 {
		t.Errorf("page.view rows = %+v, want none", view)
	}
	if rejected := find(got, "metrics.rejected"); len(rejected) != 0 {
		t.Errorf("metrics.rejected rows = %+v, want none", rejected)
	}
}

// statusRig serves a request through statusWrapper around the real signing,
// in front of a handler that emits nothing. A fetch is no page view, so
// signing emits nothing either.
func statusRig(rig *renewalRig, req *http.Request) {
	req.Header.Set("Sec-Fetch-Dest", "empty")
	mux := http.NewServeMux()
	mux.Handle("/limited", signing(rig.site, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), false))
	statusWrapper(mux, mux).ServeHTTP(httptest.NewRecorder(), req)
}

// After a renewal the status row names the renewed reader, not the cookie it came with.
func TestRenewedRequestStatusRowNamesTheRenewedReader(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	installAccess(t, `{"Any": {}, "Pioneer": {}, "Vintage": {}}`, `[]`)
	rig.stub.title = "VINTAGE"
	session := rig.session("")
	old := rig.sig("Pioneer", 9*day)

	rows := withFeatureCounter(t)
	statusRig(rig, rig.request(http.MethodGet, "/limited", browser(old, session)...))
	got := find(rows.rows(), "http.status")
	if len(got) != 1 || got[0].Tier != "Vintage" || !got[0].Signed {
		t.Errorf("http.status rows = %+v, want one for the renewed Vintage reader, signed", got)
	}
}

// A reader the renewal logs out is counted logged out, in every row.
func TestRenewalRefusedRowsAgree(t *testing.T) {
	rig := newRenewalRig(t, renewalBlock)
	installAccess(t, `{"Any": {}, "Legacy": {}}`, `[]`)
	rig.stub.title = ""
	session := rig.session("")
	old := rig.sig("Legacy", 9*day)

	rows := withFeatureCounter(t)
	statusRig(rig, rig.request(http.MethodGet, "/limited", browser(old, session)...))
	got := rows.rows()
	refuse, status := find(got, "auth.refuse"), find(got, "http.status")
	if len(refuse) != 1 || len(status) != 1 {
		t.Fatalf("auth.refuse rows = %+v, http.status rows = %+v, want one each", refuse, status)
	}
	if refuse[0].Dims != status[0].Dims || status[0].Tier != "Any" || status[0].Signed {
		t.Errorf("auth.refuse dims %+v, http.status dims %+v, want the same logged-out reader", refuse[0].Dims, status[0].Dims)
	}
}

// A Discord cleanup that spends the caller's context leaves the counter its own budget.
func TestShutdownGivesTheCounterItsBudgetAfterDiscord(t *testing.T) {
	prev := discordCleanup
	t.Cleanup(func() { discordCleanup = prev })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	discordCleanup = func() {
		observeJob("discord", "", "ratelimit.reject", "page")
		cancel() // as a cleanup that ran to the caller's deadline
	}

	rows := withFeatureCounter(t)
	(&site{}).shutdownTelemetry(ctx)
	if got := find(rows.store.snapshot(), "ratelimit.reject"); len(got) != 1 {
		t.Errorf("rows written by the shutdown = %+v, want the one Discord emitted", got)
	}
}
