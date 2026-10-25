package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/mtgban/mtgban-website/internal/access"
	"github.com/mtgban/mtgban-website/internal/infrastructure"
	"github.com/mtgban/mtgban-website/internal/pledge"
	"github.com/mtgban/mtgban-website/internal/poke"
	"github.com/mtgban/mtgban-website/ratelimit"
	"github.com/mtgban/mtgban-website/userstate"
)

// stubAnswer is a canned reply of the stub Patreon: a status and a body.
type stubAnswer struct {
	code int
	body string
}

// patreonStub is the Patreon a renewal reaches through the request's context.
// Like the real one it keeps one refresh token per account, rotated by every
// refresh and dead once spent, and answers the token, identity and membership
// endpoints from what it is told about the reader.
type patreonStub struct {
	server *httptest.Server
	db     *userstate.Client

	// What Patreon says about the reader
	email      string
	name       string
	verified   bool
	discord    string // the linked Discord id, none when empty
	membership bool   // whether the identity lists a membership of the campaign
	title      string // the tier title the pledge entitles; none when empty

	// A canned answer replaces the real one for its endpoint
	token, identity, member *stubAnswer
	// delay is how long the token answer takes; beforeToken runs before it
	delay       time.Duration
	beforeToken func()

	mu            sync.Mutex
	live          string   // the refresh token Patreon honours
	issued        []string // every token it has handed out or honoured
	refreshes     []string // the refresh tokens it was asked to spend
	identityCalls int
	memberCalls   int
	inUse         int // most database connections held while it was asked
	rotations     int
}

// newPatreonStub starts a stub that knows user as a patron of a LEGACY tier,
// whose refresh token is refresh-0.
func newPatreonStub(t *testing.T, db *userstate.Client, user *pledge.User) *patreonStub {
	t.Helper()
	p := &patreonStub{
		db:         db,
		email:      user.Email,
		name:       user.FullName,
		verified:   user.EmailVerified,
		membership: true,
		title:      "LEGACY",
		live:       "refresh-0",
		issued:     []string{"refresh-0"},
	}
	p.server = httptest.NewServer(p)
	t.Cleanup(p.server.Close)
	return p
}

func (p *patreonStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	held := p.db.DB().Stats().InUse
	if held > p.inUse {
		p.inUse = held
	}
	p.mu.Unlock()

	switch {
	case r.URL.Path == "/api/oauth2/token":
		p.serveToken(w, r)
	case r.URL.Path == "/api/oauth2/v2/identity":
		p.serveIdentity(w)
	case strings.HasPrefix(r.URL.Path, "/api/oauth2/v2/members/"):
		p.serveMember(w)
	default:
		http.NotFound(w, r)
	}
}

// reply writes a canned answer.
func reply(w http.ResponseWriter, a stubAnswer) {
	w.WriteHeader(a.code)
	w.Write([]byte(a.body))
}

func (p *patreonStub) serveToken(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	presented := r.PostForm.Get("refresh_token")
	p.mu.Lock()
	p.refreshes = append(p.refreshes, presented)
	canned, delay, before := p.token, p.delay, p.beforeToken
	p.mu.Unlock()

	if before != nil {
		before()
	}
	time.Sleep(delay)
	// A reader that gave up on the answer did not get the new token
	if r.Context().Err() != nil {
		return
	}
	if canned != nil {
		reply(w, *canned)
		return
	}

	p.mu.Lock()
	if presented != p.live {
		p.mu.Unlock()
		reply(w, stubAnswer{http.StatusUnauthorized, `{"error":"invalid_grant"}`})
		return
	}
	p.rotations++
	access := fmt.Sprintf("access-%d", p.rotations)
	p.live = fmt.Sprintf("refresh-%d", p.rotations)
	p.issued = append(p.issued, access, p.live)
	body := fmt.Sprintf(`{"access_token":%q,"refresh_token":%q,"expires_in":100,"scope":"identity","token_type":"Bearer"}`, access, p.live)
	p.mu.Unlock()
	reply(w, stubAnswer{http.StatusOK, body})
}

func (p *patreonStub) serveIdentity(w http.ResponseWriter) {
	p.mu.Lock()
	p.identityCalls++
	canned := p.identity
	p.mu.Unlock()
	if canned != nil {
		reply(w, *canned)
		return
	}

	var discord any
	if p.discord != "" {
		discord = map[string]string{"user_id": p.discord}
	}
	memberships := []map[string]string{}
	if p.membership {
		memberships = append(memberships, map[string]string{"id": "m1", "type": "member"})
	}
	body, err := json.Marshal(map[string]any{"data": map[string]any{
		"id": "u1",
		"attributes": map[string]any{
			"email":             p.email,
			"is_email_verified": p.verified,
			"full_name":         p.name,
			"social_connections": map[string]any{
				"discord": discord,
			},
		},
		"relationships": map[string]any{"memberships": map[string]any{"data": memberships}},
	}})
	if err != nil {
		panic(err)
	}
	reply(w, stubAnswer{http.StatusOK, string(body)})
}

func (p *patreonStub) serveMember(w http.ResponseWriter) {
	p.mu.Lock()
	p.memberCalls++
	canned := p.member
	p.mu.Unlock()
	if canned != nil {
		reply(w, *canned)
		return
	}
	if p.title == "" {
		reply(w, stubAnswer{http.StatusOK, `{"data":{"relationships":{"currently_entitled_tiers":{"data":[]}}}}`})
		return
	}
	body := fmt.Sprintf(`{"data":{"relationships":{"currently_entitled_tiers":{"data":[{"id":"t1","type":"tier"}]}}},"included":[{"id":"t1","type":"tier","attributes":{"title":%q}}]}`, p.title)
	reply(w, stubAnswer{http.StatusOK, body})
}

// viaStub sends every request to the stub, whatever address it names.
type viaStub struct {
	server *httptest.Server
}

func (v viaStub) RoundTrip(req *http.Request) (*http.Response, error) {
	target, err := url.Parse(v.server.URL)
	if err != nil {
		return nil, err
	}
	req = req.Clone(req.Context())
	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host
	return v.server.Client().Transport.RoundTrip(req)
}

// reach is req with a context whose Patreon calls go to the stub.
func (p *patreonStub) reach(req *http.Request) *http.Request {
	client := &http.Client{Transport: viaStub{p.server}}
	return req.WithContext(context.WithValue(req.Context(), oauth2.HTTPClient, client))
}

// calls is how many refreshes the stub was asked for.
func (p *patreonStub) calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.refreshes)
}

// liveToken is the refresh token the stub honours now.
func (p *patreonStub) liveToken() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.live
}

// spend makes token the only refresh token the stub honours, as another
// device's refresh would have.
func (p *patreonStub) spend(token string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.live = token
	p.issued = append(p.issued, token)
}

// renewalRig is a reader, a stub Patreon and the signing wrapper they meet in.
type renewalRig struct {
	t      *testing.T
	site   *site
	db     *userstate.Client
	stub   *patreonStub
	user   *pledge.User
	hash   string
	logged *strings.Builder
}

// day is a day, for ages and cookie lifetimes.
const day = 24 * time.Hour

// renewalBlock is the block the renewal tests run under unless they say.
var renewalBlock = infrastructure.PatreonRenewal{AfterDays: 8, GraceDays: 3, ClearOnNegative: true}

// newRenewalRig has signatures checked, the renewal on under block, a
// database to keep sessions in, and a stub Patreon that knows a new reader.
func newRenewalRig(t *testing.T, block infrastructure.PatreonRenewal) *renewalRig {
	t.Helper()
	signingEnabled(t, true)
	db := testUserStateDB(t)
	logged := captureAdminLog(t)
	renewalConfig(t, block, "client-id")
	savedLimiter := UserRateLimiter
	t.Cleanup(func() { UserRateLimiter = savedLimiter })
	UserRateLimiter = ratelimit.NewLimiter(1000, 1000)
	forgetRests(t)

	// The reader's rows are cleared by a client of its own, since a test may
	// close the one the site uses.
	user := sessionReader(t, openUserStateClient(t), "renew")
	return &renewalRig{
		t:      t,
		site:   testSite,
		db:     db,
		stub:   newPatreonStub(t, db, user),
		user:   user,
		hash:   userstate.HashEmail(user.Email),
		logged: logged,
	}
}

// session gives the reader another device: a session row holding token, the
// one Patreon honours when it is empty. It returns the session id.
func (rig *renewalRig) session(token string) string {
	rig.t.Helper()
	if token == "" {
		token = rig.stub.liveToken()
	}
	id, err := rig.db.CreatePatreonSession(rig.t.Context(), loginOf(rig.user, token), 0, 90*day)
	if err != nil {
		rig.t.Fatalf("CreatePatreonSession: %v", err)
	}
	return id
}

// sig is the reader's signature at tier, age days old: a login mints it
// DefaultSignatureDuration long.
func (rig *renewalRig) sig(tier string, age time.Duration) string {
	return sign(tier, rig.user, nil, DefaultSignatureDuration-age)
}

// request is a browser's request on mtgban.com holding cookies, whose Patreon
// calls go to the stub.
func (rig *renewalRig) request(method, target string, cookies ...*http.Cookie) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.Host = "mtgban.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return rig.stub.reach(req)
}

// form is a form posted from this site's own page, holding cookies.
func (rig *renewalRig) form(target string, fields url.Values, cookies ...*http.Cookie) *http.Request {
	req := rig.request(http.MethodPost, target, cookies...)
	req.Body = io.NopCloser(strings.NewReader(fields.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	return req
}

// browser is the cookies a reader's browser holds: a signature and a
// session, either left out when empty.
func browser(sig, session string) []*http.Cookie {
	var out []*http.Cookie
	if sig != "" {
		out = append(out, &http.Cookie{Name: signatureCookie, Value: sig})
	}
	if session != "" {
		out = append(out, &http.Cookie{Name: sessionCookie, Value: session})
	}
	return out
}

// served is what a handler behind the signing wrapper saw, and what the
// wrapper answered.
type served struct {
	rec     *httptest.ResponseRecorder
	reached bool
	sig     string // the signature the handler read
}

// expires is when the signature the handler read runs out.
func (s *served) expires() time.Time {
	return time.Unix(parseExpires(s.sig), 0)
}

func parseExpires(sig string) int64 {
	n, _ := strconv.ParseInt(GetParamFromSig(sig, "Expires"), 10, 64)
	return n
}

// serve runs req through the signing wrapper of a page, or of a /data/ route
// when script is set, in front of a handler that notes what it read.
func (rig *renewalRig) serve(req *http.Request, script bool) *served {
	rig.t.Helper()
	got := &served{rec: httptest.NewRecorder()}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.reached = true
		got.sig = verifiedSignature(r)
	})
	signing(rig.site, inner, script).ServeHTTP(got.rec, req)
	return got
}

// page is serve for a GET of a page that grants nothing special.
func (rig *renewalRig) page(cookies ...*http.Cookie) *served {
	rig.t.Helper()
	return rig.serve(rig.request(http.MethodGet, "/limited", cookies...), false)
}

// rows is the reader's session rows.
func (rig *renewalRig) rows() []sessionRow {
	rig.t.Helper()
	return sessionRowsOf(rig.t, rig.db, rig.hash)
}

// restingFor is how long, in seconds, a session waits before it may renew.
func (rig *renewalRig) restingFor(id string) float64 {
	rig.t.Helper()
	var wait float64
	err := rig.db.DB().QueryRowContext(rig.t.Context(),
		`SELECT extract(epoch FROM renew_after - now()) FROM patreon_sessions WHERE session_id = $1`, id).Scan(&wait)
	if err != nil {
		rig.t.Fatalf("reading session %s: %v", id, err)
	}
	return wait
}

// wantUntouched fails unless the request was served as it came: the handler
// read old and the response set no cookie at all.
func (rig *renewalRig) wantUntouched(got *served, old string) {
	rig.t.Helper()
	if !got.reached || got.sig != old {
		rig.t.Errorf("handler reached %v and read a signature that is old: %v, want it served on the old one", got.reached, got.sig == old)
	}
	cookies := got.rec.Header().Values("Set-Cookie")
	if len(cookies) != 0 {
		rig.t.Errorf("Set-Cookie %q, want none", cookies)
	}
}

// wantSessionDropped fails unless the request was served on old and the
// response cleared the session cookie, as a login sets it, and set nothing
// else.
func (rig *renewalRig) wantSessionDropped(got *served, req *http.Request, old string) {
	rig.t.Helper()
	if !got.reached || got.sig != old {
		rig.t.Errorf("handler reached %v and read the old signature: %v", got.reached, got.sig == old)
	}
	cleared := setCookies(got.rec)[sessionCookie]
	want := sessionCookieFor(req, "", -1)
	if len(got.rec.Result().Cookies()) != 1 || cleared == nil || cleared.MaxAge >= 0 || cleared.Value != "" ||
		cleared.Domain != want.Domain || cleared.Path != want.Path || !cleared.HttpOnly || !cleared.Secure || cleared.SameSite != want.SameSite {
		rig.t.Errorf("Set-Cookie %q, want the session cookie cleared and nothing else", got.rec.Header().Values("Set-Cookie"))
	}
}

// wantRenewed fails unless the request was served on a new signature, which
// the response set beside the session cookie, with the attributes a login
// gives them. It returns the new signature.
func (rig *renewalRig) wantRenewed(got *served, old, session string) string {
	rig.t.Helper()
	set := setCookies(got.rec)
	if len(got.rec.Result().Cookies()) != 2 || set[signatureCookie] == nil || set[sessionCookie] == nil {
		rig.t.Fatalf("Set-Cookie %q, want %s and %s", got.rec.Header().Values("Set-Cookie"), signatureCookie, sessionCookie)
	}
	fresh := set[signatureCookie]
	if !fresh.HttpOnly || !fresh.Secure || fresh.SameSite != http.SameSiteLaxMode || fresh.Path != "/" || fresh.Domain != "mtgban.com" {
		rig.t.Errorf("signature cookie %+v, want HttpOnly Secure Lax on mtgban.com at /", fresh)
	}
	left := time.Until(fresh.Expires)
	if left < 31*day-time.Minute || left > 31*day+time.Minute {
		rig.t.Errorf("signature cookie lasts %v, want 31 days", left)
	}
	_, valid := signatureIsValid(fresh.Value)
	if !valid || fresh.Value == old {
		rig.t.Errorf("signature cookie valid %v, unchanged %v; want a new valid one", valid, fresh.Value == old)
	}
	kept := set[sessionCookie]
	if kept.Value != session || kept.MaxAge != int(31*day/time.Second) || !kept.HttpOnly || !kept.Secure || kept.SameSite != http.SameSiteLaxMode || kept.Path != "/" || kept.Domain != "mtgban.com" {
		rig.t.Errorf("session cookie %+v, want the same id for 31 days with the login's attributes", kept)
	}
	if !got.reached || got.sig != fresh.Value {
		rig.t.Errorf("handler reached %v and read the new signature: %v", got.reached, got.sig == fresh.Value)
	}
	if got.expires().Sub(time.Now().Add(DefaultSignatureDuration)).Abs() > time.Minute {
		rig.t.Errorf("handler saw a signature running out %v, want about %v from now", got.expires(), DefaultSignatureDuration)
	}
	return fresh.Value
}

// wantNoTokens fails if the admin log holds any token the stub handed out or
// honoured.
func (rig *renewalRig) wantNoTokens() {
	rig.t.Helper()
	rig.stub.mu.Lock()
	issued := slices.Clone(rig.stub.issued)
	rig.stub.mu.Unlock()
	for _, token := range issued {
		if strings.Contains(rig.logged.String(), token) {
			rig.t.Errorf("admin log %q holds the token %q", rig.logged.String(), token)
		}
	}
}

// tampered is sig with the tier edited and the signature left as it was:
// it decodes, names the same reader, and does not check out.
func tampered(sig string) string {
	values := parseSig(sig)
	values.Set("UserTier", "Vintage")
	return base64.StdEncoding.EncodeToString([]byte(values.Encode()))
}

// installAccess serves the access table and grant list given as JSON for the
// test.
func installAccess(t *testing.T, table, grants string) {
	t.Helper()
	saved := Access
	t.Cleanup(func() { Access = saved })
	files := map[string]string{"acl": table, "grants": grants}
	Access = access.New(access.Hooks{
		Open: func(_ context.Context, path string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(files[path])), nil
		},
	})
	err := Access.Load(context.Background(), access.Sources{TablePath: "acl", GrantsPath: "grants"})
	if err != nil {
		t.Fatal(err)
	}
}

// forgetRests gives the test a process that has seen no session refuse a
// lease, as another site or a restart would be, and puts back the one it
// found.
func forgetRests(t *testing.T) {
	t.Helper()
	saved := restingSessions
	t.Cleanup(func() { restingSessions = saved })
	restingSessions = newSessionRests()
}

// freshPokes gives the test a poke set of its own, and puts back the one it
// found.
func freshPokes(t *testing.T) *poke.Set {
	t.Helper()
	saved := Pokes
	t.Cleanup(func() { Pokes = saved })
	Pokes = poke.New()
	return Pokes
}
