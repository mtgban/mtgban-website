package main

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mtgban/mtgban-website/apisig"
	"github.com/mtgban/mtgban-website/internal/access"
	"github.com/mtgban/mtgban-website/internal/pledge"
	"github.com/mtgban/mtgban-website/internal/siteorigin"
	"github.com/mtgban/mtgban-website/patreon"
	"github.com/mtgban/mtgban-website/ratelimit"
	"github.com/mtgban/mtgban-website/userstate"
)

const (
	ErrMsg        = "Join the BAN Community and gain access to exclusive tools!"
	ErrMsgPlus    = "Increase your pledge to gain access to this feature!"
	ErrMsgDenied  = "Something went wrong while accessing this page"
	ErrMsgExpired = "You've been logged out"
	ErrMsgRestart = "Website is restarting, please try again in a few minutes"
	ErrMsgUseAPI  = "Slow down, you're making too many requests! For heavy data use consider the BAN API"

	APIRequestsPerSec  = 10
	UserRequestsPerSec = 3
	// A screener refresh uses two requests; leave room for a quick follow-up.
	UserRequestBurst = 4
)

var APIRateLimiter = ratelimit.NewLimiter(APIRequestsPerSec, 2)

var UserRateLimiter = ratelimit.NewLimiter(UserRequestsPerSec, UserRequestBurst)

// Pledge resolves a Patreon login into a reader and a site tier, reading this
// deployment's grant list and admin log; see internal/pledge.
var Pledge = pledge.New(pledge.Hooks{
	Log: func() *log.Logger { return LogPages["Admin"] },
	GrantFor: func(email string) (access.Grant, bool) {
		return indexGrants(PatreonGrants()).find(userstate.HashEmail(email))
	},
})

// patreonTimeout is how long a login or a handoff waits on Patreon, its
// token exchange and lookups together.
const patreonTimeout = 10 * time.Second

func (s *site) Auth(w http.ResponseWriter, r *http.Request) {
	origin := siteorigin.Of(r)
	if origin == "" {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}

	// A handoff to the API gateway rather than a site login: it signs in
	// nobody here, and the token it mints is the gateway's. One that fails
	// before Patreon names the reader ends on the API page, as one that
	// fails after does.
	handoff, isHandoff := parseHandoffState(r.FormValue("state"))

	code := r.FormValue("code")
	if code == "" {
		if isHandoff {
			s.failAPIHandoff(w, r, handoff, "no code from Patreon")
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// The Patreon calls below share one deadline: their clients set none
	patreonCtx, cancelPatreon := context.WithTimeout(r.Context(), patreonTimeout)
	defer cancelPatreon()

	// Get the access token for this connection
	patreonConfig := Infrastructure().Patreon
	source := patreonConfig.Source
	clientID := patreonConfig.Client[source]
	secret := patreonConfig.Secret[source]
	exchanged := time.Now()
	tokens, err := patreon.GetAuthToken(patreonCtx, clientID, secret, origin, code)
	if err != nil {
		LogPages["Admin"].Println("getUserToken", err.Error())
		if isHandoff {
			s.failAPIHandoff(w, r, handoff, "token exchange failed")
			return
		}
		http.Redirect(w, r, "/?errmsg=TokenNotFound", http.StatusFound)
		return
	}

	// The client to interface with Patreon
	client := patreon.NewPatreonClient(patreonCtx, tokens.AccessToken)

	// Retrieve information about the user who just authenticated
	userData, err := Pledge.UserIDs(patreonCtx, client)
	if err != nil {
		LogPages["Admin"].Println("getUserId", err.Error())
		if isHandoff {
			s.failAPIHandoff(w, r, handoff, "identity lookup failed")
			return
		}
		http.Redirect(w, r, "/?errmsg=UserNotFound", http.StatusFound)
		return
	}

	tierTitle, overrides, granted, verdict, err := Pledge.Resolve(patreonCtx, client, userData)
	var tierErr error
	if verdict == pledge.Unknown && pledge.DidNotAnswer(patreonCtx, err) {
		tierErr = err
	}

	if isHandoff {
		s.finishAPIHandoff(w, r, handoff, userData, tierTitle, tierErr)
		return
	}

	// Handle error
	if verdict != pledge.Entitled {
		LogPages["Admin"].Printf("auth: no tier for %q: verdict=%v err=%v", userData.Email, verdict, err)
		http.Redirect(w, r, "/?errmsg=TierNotFound", http.StatusFound)
		return
	}

	LogPages["Admin"].Printf("auth: email=%q tier=%q", userData.Email, tierTitle)

	s.finishSiteLogin(w, r, r.FormValue("state"), userData, tierTitle, overrides, granted, patreonLogin{
		clientID:     clientID,
		refreshToken: tokens.RefreshToken,
		exchanged:    exchanged,
	})
}

// patreonLogin is the refresh token a login's code exchange returned, the
// client it was issued to, and when the exchange began.
type patreonLogin struct {
	clientID     string
	refreshToken string
	exchanged    time.Time
}

// finishSiteLogin signs in the reader Patreon just named, whose pledge gives
// tier: it signs their signature into the cookies and sends them on to where
// state says the login began. The refresh token login holds is kept in a
// patreon_sessions row, which the BAN_SESSION cookie names, when the site has
// a database and the token is not empty, dated from the exchange so that a
// token another device's renewal rotated to meanwhile is the newer one.
// A row that cannot be written is logged and the login goes on without it.
func (s *site) finishSiteLogin(w http.ResponseWriter, r *http.Request, state string, user *pledge.User, tier string, overrides map[string]map[string]string, granted bool, login patreonLogin) {
	s.signReaderIn(w, r, user, tier, overrides, granted)

	// The row that lets the site renew this signature later. Without one the
	// login still works and simply never renews. A browser logging in again
	// replaces the row its cookie names once the new one is written, so a
	// failed insert leaves it the row it had and logout always reaches one.
	if UserStateDB != nil && login.refreshToken != "" {
		sessionCtx, cancelSession := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancelSession()
		maxAge := Infrastructure().PatreonRenewal.MaxSession()
		sessionID, err := UserStateDB.CreatePatreonSession(sessionCtx, userstate.PatreonLogin{
			EmailHash:    userstate.HashEmail(user.Email),
			PatreonUser:  user.UserID,
			ClientID:     login.clientID,
			RefreshToken: login.refreshToken,
		}, time.Since(login.exchanged), maxAge)
		if err != nil {
			LogPages["Admin"].Println("CreatePatreonSession", err)
		} else {
			setSessionCookie(w, r, sessionID, signatureCookieDays*24*time.Hour)
			previous := readCookie(r, sessionCookie)
			if previous != "" {
				err = UserStateDB.DeletePatreonSession(sessionCtx, previous)
				if err != nil {
					LogPages["Admin"].Println("DeletePatreonSession", err)
				}
			}
		}
	}

	// Redirect to the URL indicated in this query param, or go to homepage.
	// Drop a stale error from the page that started the login flow now that
	// authentication succeeded.
	redir := authRedirect(state)

	// Redirect, we're done here
	http.Redirect(w, r, redir, http.StatusFound)
}

// signReaderIn signs the reader whose pledge gives tier into the BAN_SIG
// cookie, after recording what the login learned about them for alerts, and
// returns the signature. A login and a renewal both end here.
func (s *site) signReaderIn(w http.ResponseWriter, r *http.Request, user *pledge.User, tier string, overrides map[string]map[string]string, granted bool) string {
	// Sign our base URL with our tier and other data
	sig := sign(tier, user, overrides, DefaultSignatureDuration)

	// Whether this tier grants alerts at all, computed once rather than
	// re-parsing the signature just signed.
	allowed := alertContactAllowed(tier, overrides)
	channels := alertContactChannels(tier, overrides)

	// A grant's tier is not stored: the evaluator reads a live grant's own,
	// and a revoked one must not leave its tier behind until the next login.
	contactTier := tier
	if granted {
		contactTier = ""
	}
	alertCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	err := recordAlertContact(alertCtx, s.alertContacts(), user, contactTier, allowed, channels)
	if err != nil {
		LogPages["Admin"].Println("recordAlertContact", err)
	}

	// Keep it secret. Keep it safe.
	putSignatureInCookies(w, r, sig)
	return sig
}

func authRedirect(state string) string {
	redir := strings.Split(state, ";")[0]

	// Go back home if empty or if coming back from a logout.
	if redir == "" || strings.Contains(redir, "errmsg=logout") {
		return "/"
	}

	// The login templates put only the current path in state. Normalize
	// backslashes because browsers can treat them as URL separators, then
	// reject anything that could name another host or scheme.
	redir = strings.ReplaceAll(redir, `\`, "/")
	parsed, err := url.Parse(redir)
	if err != nil || parsed.Hostname() != "" || parsed.Scheme != "" || parsed.Opaque != "" || !strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(parsed.Path, "//") {
		return "/"
	}

	query := parsed.Query()
	query.Del("errmsg")
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func signHMACSHA1Base64(key []byte, data []byte) string {
	return apisig.Sign(key, data)
}

// unverifiedSignature is the request's signature, the cookie's (see
// cookieSignature) or else ?sig=, checked for nothing but its expiry. It is
// what the checks below start from; anything that acts on a grant reads
// verifiedSignature or verifiedRequestSignature instead.
func unverifiedSignature(r *http.Request) string {
	sig := cookieSignature(r)

	querySig := r.FormValue("sig")
	if sig == "" && querySig != "" {
		sig = querySig
	}

	if !signatureUnexpired(sig) {
		return ""
	}

	return sig
}

// signatureUnexpired says whether sig carries an Expires still ahead.
func signatureUnexpired(sig string) bool {
	expires, err := strconv.ParseInt(GetParamFromSig(sig, "Expires"), 10, 64)
	return err == nil && expires >= time.Now().Unix()
}

// cookieSignature is the signature the request's cookies carry: BAN_SIG,
// unless that is absent or has run out and the legacy cookie is there to
// read instead. All of the legacy fallback goes in the cleanup.
func cookieSignature(r *http.Request) string {
	sig := readCookie(r, signatureCookie)
	legacy := readCookie(r, legacySignatureCookie)
	if legacy != "" && !signatureUnexpired(sig) {
		return legacy
	}
	return sig
}

// signatureIsValid says whether sig is one this host wrote and has not yet
// expired, and hands back what it carries either way.
//
// It is enforceSigning's check without the branches deciding what to say
// about a failure, for the callers that only need to know whether a
// signature may be trusted: a handler reached without the middleware in
// front of it, or one looking at a request the middleware would refuse on
// method alone. Those callers used to carry their own copy of the HMAC,
// which is a copy of a security decision - the sort that goes on agreeing
// with the original right up until the day the scheme changes.
//
// The values come back even when the answer is no, so a caller can read a
// name off an untrusted signature to say who is being turned away. What it
// must not do is act on a grant it finds there.
func signatureIsValid(sig string) (url.Values, bool) {
	if sig == "" {
		return nil, false
	}
	v := parseSig(sig)
	if v == nil {
		return nil, false
	}
	// Development without a secret to sign with: anything that decodes is
	// taken at its word, which is what every other check here does too.
	if !SigCheck {
		return v, true
	}

	expires, err := strconv.ParseInt(v.Get("Expires"), 10, 64)
	if err != nil || !signatureMatches(v) || expires < time.Now().Unix() {
		return v, false
	}
	return v, true
}

// signatureMatches says whether v carries the HMAC this host writes over its
// signed fields, whether or not it has run out.
func signatureMatches(v url.Values) bool {
	q := url.Values{}
	for _, optional := range SignedFields {
		if val := v.Get(optional); val != "" {
			q.Set(optional, val)
		}
	}

	data := fmt.Sprintf("GET%s%s%s", v.Get("Expires"), signatureLink(), q.Encode())
	valid := signHMACSHA1Base64([]byte(os.Getenv("BAN_SECRET")), []byte(data))
	return hmac.Equal([]byte(valid), []byte(v.Get("Signature")))
}

// signedUserEmail returns the UserEmail off verifiedRequestSignature, else "".
func signedUserEmail(r *http.Request) string {
	return GetParamFromSig(verifiedRequestSignature(r), "UserEmail")
}

// verifiedSignature is the cookie signature when signatureIsValid accepts
// it, else "". Handlers reached through an ACL "Any" entry skip
// enforceSigning, so they call this before trusting who the reader is.
func verifiedSignature(r *http.Request) string {
	sig := unverifiedSignature(r)
	if _, ok := signatureIsValid(sig); !ok {
		return ""
	}
	return sig
}

// verifiedRequestSignature is verifiedSignature for a handler that also has to
// accept a signature named in the query, the way enforceSigning does: a link
// someone was sent carries its grant in ?sig= before any cookie exists for it.
// Whichever one it reads, it hands back only a signature signatureIsValid
// accepts, so a caller behind noSigning can read a grant off it.
func verifiedRequestSignature(r *http.Request) string {
	sig := unverifiedSignature(r)
	if querySig := r.FormValue("sig"); querySig != "" {
		sig = querySig
	}
	if _, ok := signatureIsValid(sig); !ok {
		return ""
	}
	return sig
}

// signatureCookieDays is how long the BAN_SIG cookie keeps a signature, and so
// the longest an invite link may last: one that outlived its cookie would be
// dropped by the browser while still valid.
const signatureCookieDays = 31

// Put signature in cookies for a month, all domains can access this
func putSignatureInCookies(w http.ResponseWriter, r *http.Request, sig string) {
	expires := time.Now().Add(signatureCookieDays * 24 * time.Hour)
	http.SetCookie(w, signatureCookieFor(r, signatureCookie, sig, expires))
}

// prunePatreonSessions deletes the sessions past their cap; nothing to do
// without a client.
func prunePatreonSessions() {
	if UserStateDB == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	n, err := UserStateDB.PrunePatreonSessions(ctx)
	if err != nil {
		log.Println("patreon sessions: prune:", err)
		backgroundJobs.Report(jobPatreonSessions, "", err.Error())
		return
	}
	backgroundJobs.Report(jobPatreonSessions, fmt.Sprintf("%d pruned", n), "")
}

// migrateSignatureCookie finishes the move off the legacy cookie for a reader
// whose cookie signature checks out: it is written as BAN_SIG when it was
// read from the legacy cookie, and the legacy cookie is expired either way.
// Only a page navigation does it. A script's fetch for JSON asks for
// something else, and the answer may sit in a shared cache, which must not
// hold a Set-Cookie carrying a reader's signature; the fallback serves it.
func migrateSignatureCookie(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || !strings.Contains(r.Header.Get("Accept"), "text/html") {
		return
	}
	if readCookie(r, legacySignatureCookie) == "" {
		return
	}
	sig := verifiedSignature(r)
	if sig == "" {
		return
	}
	if readCookie(r, signatureCookie) != sig {
		putSignatureInCookies(w, r, sig)
	}
	clearSignatureCookie(w, r, legacySignatureCookie)
}

// adminOnly hides the wrapped handler from signatures that do not carry
// the Admin grant, reading it off the signature enforceSigning checks, and
// checking it again itself. Non-admins get a plain 404 so the endpoint's
// existence is not advertised.
func adminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		canDo, _ := strconv.ParseBool(GetParamFromSig(verifiedRequestSignature(r), "Admin"))
		if !canDo && !(DevMode && !SigCheck) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// withSignatureCookie is r carrying sig as its BAN_SIG cookie, in place of the
// one the request came with. cookieSignature prefers it to a legacy cookie
// left beside it.
func withSignatureCookie(r *http.Request, sig string) *http.Request {
	out := r.Clone(r.Context())
	out.Header.Del("Cookie")
	for _, c := range r.Cookies() {
		if c.Name != signatureCookie {
			out.AddCookie(c)
		}
	}
	out.AddCookie(&http.Cookie{Name: signatureCookie, Value: sig})
	return out
}

// noSigning runs the handler it wraps without checking a signature; it only
// keeps the one an invite link carries in ?sig= as the cookie, once that
// checks out.
func noSigning(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer recoverPanic(r, w)

		querySig := r.FormValue("sig")
		_, signed := signatureIsValid(querySig)
		if signed {
			putSignatureInCookies(w, r, querySig)
		} else {
			migrateSignatureCookie(w, r)
		}

		next.ServeHTTP(w, r)
	})
}

// apiLimitAddress is the address the API limiter counts r against: the peer
// the nearest proxy saw, or the client in the header $BAN_CLIENT_IP_HEADER
// names, or for a request the API gateway signed, the client the gateway
// resolved, which it sends as the only X-Forwarded-For entry.
// An IPv6 address counts as its /64, the block one subscriber holds.
//
// $BAN_CLIENT_IP_HEADER is set on App Platform to DO-Connecting-IP, which
// its ingress writes; X-Forwarded-For there ends with a public hop of the
// ingress's own. Behind nginx it stays unset, since nginx passes any such
// header on as the client sent it.
func apiLimitAddress(r *http.Request) (net.IP, error) {
	ip, err := ratelimit.IPAddress(r)
	if err != nil {
		return nil, err
	}
	header := os.Getenv("BAN_CLIENT_IP_HEADER")
	if header != "" {
		client := net.ParseIP(strings.TrimSpace(r.Header.Get(header)))
		if client != nil {
			ip = client
		}
	}
	client := ratelimit.FirstForwarded(r)
	if client != nil && signedByGateway(r) {
		ip = client
	}
	if ip.To4() == nil {
		ip = ip.Mask(net.CIDRMask(64, 128))
	}
	return ip, nil
}

// signedByGateway reports whether r carries a live signature minted with
// the gateway's secret. The gateway puts sig in the query string, so the
// body, which this runs before the limiter, is never parsed for it.
func signedByGateway(r *http.Request) bool {
	secret := apiGatewaySecret()
	if secret == "" {
		return false
	}
	v, err := apisig.Decode(r.URL.Query().Get("sig"))
	if err != nil || v.Get("UserEmail") != apiGatewayUser {
		return false
	}
	return apisig.Verify([]byte(secret), r.Method, signatureLink(), v, OptionalFields, time.Now()) == nil
}

func enforceAPISigning(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer recoverPanic(r, w)

		w.Header().Add("RateLimit-Limit", fmt.Sprint(APIRequestsPerSec))

		ip, err := apiLimitAddress(r)
		if err != nil {
			log.Println(err)
			errorResponse(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
			return
		}

		if !APIRateLimiter.Allow(string(ip)) {
			errorResponse(w, http.StatusTooManyRequests, http.StatusText(http.StatusTooManyRequests))
			return
		}

		if len(GetSellers()) == 0 || len(GetVendors()) == 0 {
			errorResponse(w, http.StatusServiceUnavailable, http.StatusText(http.StatusServiceUnavailable))
			return
		}

		w.Header().Add("Content-Type", "application/json")

		sig := r.FormValue("sig")

		// If signature is empty let it pass through
		if sig == "" && !strings.HasPrefix(r.URL.Path, "/api/load") {
			next.ServeHTTP(w, r)
			return
		}

		v, err := apisig.Decode(sig)
		if SigCheck && err != nil {
			log.Println("API error, bad sig", err)
			errorResponse(w, http.StatusUnauthorized, "invalid signature")
			return
		}

		// Kept ungated to match the previous middleware exactly.
		if exp := v.Get("Expires"); exp != "" {
			if _, err := strconv.ParseInt(exp, 10, 64); err != nil {
				log.Println("API error", err.Error())
				errorResponse(w, http.StatusUnauthorized, "invalid or expired signature")
				return
			}
		}

		secret := os.Getenv("BAN_SECRET")
		userSecret, found := Config().APIUserSecrets[v.Get("UserEmail")]
		if found {
			secret = userSecret
		}

		err = apisig.Verify([]byte(secret), r.Method, signatureLink(), v, OptionalFields, time.Now())
		if SigCheck && err != nil {
			log.Println("API error, invalid", v.Get("UserEmail"), err)
			errorResponse(w, http.StatusUnauthorized, "invalid or expired signature")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// targetsSubPage reports whether r asks for the given subpage. Some
// subpages have a path of their own, others are a query parameter on the
// parent's path (the newspaper's pages all live under /newspaper and pick
// themselves with page=), so the path has to match and so does every
// parameter the link pins down. Matching the path alone would let the
// parent stand in for its own subpage.
func targetsSubPage(r *http.Request, link string) bool {
	target, err := url.Parse(link)
	if err != nil || target.Path != r.URL.Path {
		return false
	}
	query := r.URL.Query()
	for key, values := range target.Query() {
		if len(values) > 0 && query.Get(key) != values[0] {
			return false
		}
	}
	return true
}

// enforceSigning takes the site because it builds the nav (genPageNav) and
// checks ShouldHide, both of which read the site's current datastore. A
// refusal renders the error page.
func enforceSigning(s *site, next http.Handler) http.Handler {
	return signing(s, next, false)
}

// enforceDataSigning checks what enforceSigning checks, for /data/, which
// only the site's own scripts read: a refusal is a status and a JSON error
// the script can test, not a page served with 200.
func enforceDataSigning(s *site, next http.Handler) http.Handler {
	return signing(s, next, true)
}

// signingRefusal is why signing turned a request away.
type signingRefusal struct {
	status int
	title  string
	msg    string
	login  bool
}

// write answers the refused request: the JSON error for a script, the error
// page for a reader.
func (ref signingRefusal) write(w http.ResponseWriter, r *http.Request, s *site, sig string, script bool) {
	if script {
		errorResponse(w, ref.status, ref.msg)
		return
	}
	pageVars := genPageNav(s, r, "Error", sig)
	pageVars.Title = ref.title
	pageVars.ErrorMessage = ref.msg
	// genPageNav already offers it to a reader with no signature
	if ref.login {
		pageVars.PatreonLogin = true
	}
	render(w, "home.html", pageVars)
}

func signing(s *site, next http.Handler, script bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer recoverPanic(r, w)

		// Bound the body before anything below reads the form: FormValue
		// parses a multipart body whole, on every path through here.
		r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBodySize)

		// Check if this endpoint can be bypassed
		_, checkNoAuth := ACL()["Any"]
		if checkNoAuth {
			for key, nav := range ExtraNavs {
				if nav.Link == r.URL.Path || slices.ContainsFunc(nav.SubPages, func(p NavElem) bool {
					// The whole path, without the query params a Link may carry
					path, _, _ := strings.Cut(p.Link, "?")
					return path == r.URL.Path
				}) {
					_, noAuth := ACL()["Any"][key]
					if noAuth {
						recordPageHit(r)
						noSigning(next).ServeHTTP(w, r)
						return
					}
				}
			}
		}

		sig := unverifiedSignature(r)
		querySig := r.FormValue("sig")
		if querySig != "" {
			sig = querySig
			// Kept only once it checks out; one that does not is refused below
			_, signed := signatureIsValid(querySig)
			if signed {
				putSignatureInCookies(w, r, querySig)
			}
			// Handlers read the cookie first: give them the signature checked
			// here, not one the request carried beside it.
			r = withSignatureCookie(r, querySig)
		} else {
			migrateSignatureCookie(w, r)
		}

		switch r.Method {
		case "GET":
		case "POST":
			var ok bool
			for _, nav := range ExtraNavs {
				if nav.Link == r.URL.Path {
					ok = nav.CanPOST
				}
			}
			if !ok {
				http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
				return
			}
		default:
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		// The error nav is built lazily inside each failing branch: on the
		// happy path — nearly every request — it would be thrown away, and
		// the handler builds its own right after.
		// Limited by whom a checked signature names, or by the signature
		// itself for an invite, which names nobody. Anything unchecked shares
		// the bucket requests with no signature share, so a forged cookie
		// cannot spend somebody else's.
		limitKey := ""
		checked, ok := signatureIsValid(sig)
		// A cookie signature that ran out within grace_days is not sig any
		// more, but it still names its reader, to count and to renew.
		expired := graceSignature(r, sig, querySig)
		if expired != nil {
			checked, ok = expired, true
		}
		if ok {
			limitKey = checked.Get("UserEmail")
			if limitKey == "" {
				limitKey = checked.Get("Signature")
			}
		}
		if !UserRateLimiter.Allow(limitKey) && r.URL.Path != "/admin" {
			signingRefusal{status: http.StatusTooManyRequests, title: "Too Many Requests", msg: ErrMsgUseAPI}.write(w, r, s, sig, script)
			return
		}

		// A signature due for renewal is renewed here, and this request goes
		// on under the new one.
		renewed, refused := s.renewDue(w, r, checked, ok, querySig == "")
		if refused {
			// The pledge is gone: logged out, with the way back in
			ref := signingRefusal{status: http.StatusUnauthorized, title: "Unauthorized", msg: ErrMsgExpired, login: true}
			ref.write(w, withSignatureCookie(r, ""), s, "", script)
			return
		}
		if renewed != "" {
			sig = renewed
			r = withSignatureCookie(r, renewed)
		}

		raw, err := base64.StdEncoding.DecodeString(sig)
		if SigCheck && err != nil {
			ref := signingRefusal{status: http.StatusUnauthorized, title: "Unauthorized", msg: ErrMsg}
			if DevMode {
				ref.msg += " - " + err.Error()
			}
			ref.write(w, r, s, sig, script)
			return
		}

		v, err := url.ParseQuery(string(raw))
		if SigCheck && err != nil {
			ref := signingRefusal{status: http.StatusUnauthorized, title: "Unauthorized", msg: ErrMsg}
			if DevMode {
				ref.msg += " - " + err.Error()
			}
			ref.write(w, r, s, sig, script)
			return
		}

		q := url.Values{}
		for _, optional := range SignedFields {
			val := v.Get(optional)
			if val != "" {
				q.Set(optional, val)
			}
		}

		expectedSig := v.Get("Signature")
		exp := v.Get("Expires")

		link := signatureLink()
		data := fmt.Sprintf("GET%s%s%s", exp, link, q.Encode())
		valid := signHMACSHA1Base64([]byte(os.Getenv("BAN_SECRET")), []byte(data))
		signed := hmac.Equal([]byte(valid), []byte(expectedSig))
		expires, err := strconv.ParseInt(exp, 10, 64)
		if SigCheck && (err != nil || !signed || expires < time.Now().Unix()) {
			if r.Method != "GET" {
				http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
				return
			}
			ref := signingRefusal{status: http.StatusUnauthorized, title: "Unauthorized", msg: ErrMsg}
			if signed && expires < time.Now().Unix() {
				ref.msg = ErrMsgExpired
				ref.login = true
				if DevMode {
					ref.msg += " - sig expired"
				}
			}

			if DevMode {
				if err != nil {
					ref.msg += " - " + err.Error()
				} else {
					ref.msg += " - wrong host"
				}
			}

			ref.write(w, r, s, sig, script)
			return
		}

		for _, navName := range OrderNav {
			nav := ExtraNavs[navName]
			if r.URL.Path == nav.Link {
				param := GetParamFromSig(sig, navName)
				canDo, _ := strconv.ParseBool(param)
				if DevMode && nav.AlwaysOnForDev {
					canDo = true
				}
				if SigCheck && !canDo {
					pageVars := genPageNav(s, r, nav.Name, sig)
					pageVars.Title = "This feature is BANned"
					pageVars.ErrorMessage = ErrMsgPlus

					render(w, nav.Page, pageVars)
					return
				}

				// A section hidden from the nav is not reachable by typing its
				// url either, the same as its subpages below.
				if nav.ShouldHide != nil && nav.ShouldHide(s) {
					pageVars := genPageNav(s, r, "Error", sig)
					pageVars.Title = "Unauthorized"
					render(w, "home.html", pageVars)
					return
				}

				// Check if link is a subpage, and validate if viewing conditions are met
				for _, subPage := range nav.SubPages {
					if targetsSubPage(r, subPage.Link) &&
						subPage.ShouldHide != nil && subPage.ShouldHide(s) {
						pageVars := genPageNav(s, r, "Error", sig)
						pageVars.Title = "Unauthorized"
						render(w, "home.html", pageVars)
						return
					}
				}

				break
			}
		}

		recordPageHit(r)
		next.ServeHTTP(w, r)
	})
}

func recoverPanic(r *http.Request, w http.ResponseWriter) {
	errPanic := recover()
	if errPanic != nil {
		reportPanic(errPanic, "source request: "+r.URL.String())

		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

// applyACL sets each enabled page and its option values from table into v,
// overwriting whatever v already holds for them. Calling it a second time
// with a different table layers those values on top of the first call's -
// which is how a grant's own Overrides sit on top of its tier's table.
func applyACL(v url.Values, table map[string]map[string]string) {
	for _, page := range OrderNav {
		options, found := table[page]
		if !found {
			continue
		}
		v.Set(page, "true")

		for _, key := range OptionalFields {
			val, found := options[key]
			if !found {
				continue
			}
			v.Set(key, val)
		}
	}
}

// valuesForTierIn is a tier's ACL values against a given table, so callers
// that already hold one (or a test's literal one) don't have to go through
// ACL().
func valuesForTierIn(table access.Table, tierTitle string) url.Values {
	v := url.Values{}
	tier, found := table[tierTitle]
	if !found {
		return v
	}
	applyACL(v, tier)
	return v
}

// Every sig-encoded permission field in signing order: OrderNav then
// OptionalFields. Both lists are fixed at startup, so the concatenation the
// signing and verification paths walk is computed once instead of per request.
var SignedFields = slices.Concat(OrderNav, OptionalFields)

// signatureLink is the identity covered by a signed link. It is deliberately
// independent of the request origin: production callers sign for the public
// API identity, while local development keeps the historical localhost link.
func signatureLink() string {
	if DevMode {
		return "http://localhost:" + fmt.Sprint(Config().Port)
	}
	return DefaultServerURL
}

// aclValues is what a tier grants, with a grant's own overrides on top.
func aclValues(tier string, overrides map[string]map[string]string) url.Values {
	return aclValuesIn(ACL(), tier, overrides)
}

// sign encodes tierTitle's ACL values into a signature, with overrides -
// a grant's own values for this one user - layered on top afterward so
// they win over anything the tier itself set.
//
// The duration is the caller's: a login asks for DefaultSignatureDuration, an
// invite link for however long it was cut for. There is no unexpiring answer -
// signatureIsValid refuses a sig whose Expires will not parse as readily as
// one whose Expires has passed.
func sign(tierTitle string, userData *pledge.User, overrides map[string]map[string]string, duration time.Duration) string {
	v := aclValues(tierTitle, overrides)
	if userData != nil {
		v.Set("UserName", userData.FullName)
		v.Set("UserEmail", userData.Email)
		v.Set("UserTier", tierTitle)
		// The API gateway signs in whoever the email names, so one Patreon
		// has not confirmed says so; only those carry the extra field.
		if !userData.EmailVerified {
			v.Set("UserEmailUnverified", "true")
		}
	}

	link := signatureLink()
	expires := time.Now().Add(duration)
	data := fmt.Sprintf("GET%d%s%s", expires.Unix(), link, v.Encode())
	key := os.Getenv("BAN_SECRET")
	sig := signHMACSHA1Base64([]byte(key), []byte(data))

	v.Set("Expires", fmt.Sprintf("%d", expires.Unix()))
	v.Set("Signature", sig)
	str := base64.StdEncoding.EncodeToString([]byte(v.Encode()))

	return str
}

// parseSig decodes the query values packed in a signature. A sig that doesn't
// decode returns nil, which behaves as an empty url.Values on Get. Decoding
// the full ~2KB sig costs a few microseconds, so code reading several params
// (like genPageNav's feature loop) should parse once and Get from the result
// rather than calling GetParamFromSig per param.
func parseSig(sig string) url.Values {
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return nil
	}
	v, err := url.ParseQuery(string(raw))
	if err != nil {
		return nil
	}
	return v
}

func GetParamFromSig(sig, param string) string {
	return parseSig(sig).Get(param)
}
