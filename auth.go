package main

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mtgban/mtgban-website/apisig"
	"github.com/mtgban/mtgban-website/internal/access"
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

type PatreonConfig struct {
	Source string            `json:"source"`
	Client map[string]string `json:"client"`
	Secret map[string]string `json:"secret"`
}

type PatreonUserData struct {
	UserID        string
	MembershipID  string
	FullName      string
	Email         string
	EmailVerified bool
	DiscordID     string
	// DiscordKnown is true when this login's Patreon answer had an opinion
	// (linked or explicitly unlinked) on the Discord id.
	DiscordKnown bool
}

// patreonUserFromData maps a decoded Patreon identity answer to what the
// site keeps. Pure, so it's testable without a Patreon client.
func patreonUserFromData(userData *patreon.UserData) *PatreonUserData {
	// Look for the membership id of the user and this account
	membershipID := ""
	for _, memberData := range userData.Data.Relationships.Memberships.Data {
		if memberData.Type == "member" {
			membershipID = memberData.ID
			break
		}
	}

	discordID, discordKnown := userData.DiscordUserID()

	return &PatreonUserData{
		UserID:        userData.Data.IDV1,
		MembershipID:  membershipID,
		FullName:      userData.Data.Attributes.FullName,
		Email:         strings.ToLower(userData.Data.Attributes.Email),
		EmailVerified: userData.Data.Attributes.IsEmailVerified,
		DiscordID:     discordID,
		DiscordKnown:  discordKnown,
	}
}

func getUserIDs(ctx context.Context, client *patreon.Client) (*PatreonUserData, error) {
	userData, err := client.GetUserData(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot retrieve user data: %w", err)
	}

	LogPages["Admin"].Printf("getUserIds: email=%s name=%s memberships=%d",
		userData.Data.Attributes.Email, userData.Data.Attributes.FullName,
		len(userData.Data.Relationships.Memberships.Data))
	if len(userData.Errors) > 0 {
		return nil, fmt.Errorf("user data error: %q", userData.Errors)
	}

	return patreonUserFromData(userData), nil
}

func getUserTier(ctx context.Context, client *patreon.Client, userID string) (string, error) {
	membershipData, err := client.GetMembershipData(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("cannot decode membership data: %w", err)
	}

	LogPages["Admin"].Println("getUserTier:", membershipData)
	if len(membershipData.Errors) > 0 {
		return "", fmt.Errorf("user data error: %q", membershipData.Errors)
	}

	// Look for the tier id of the user
	tierID := ""
	for _, tierData := range membershipData.Data.Relationships.CurrentlyEntitledTiers.Data {
		if tierData.Type == "tier" {
			tierID = tierData.ID
			break
		}
	}

	// Get a human-readable name for the tier
	tierTitle := ""
	for _, tierData := range membershipData.Included {
		if tierData.Type == "tier" && tierID == tierData.ID {
			tierTitle = tierData.Attributes.Title
		}
	}

	if tierTitle == "" {
		return "", errors.New("empty tier title")
	}

	return tierTitle, nil
}

// requestOrigin returns the public origin for this request. The proxy must
// overwrite the forwarded headers before they reach the application; the
// hostname check prevents an arbitrary Host value from becoming a redirect or
// OAuth target.
func requestOrigin(r *http.Request) string {
	if r == nil {
		return ""
	}

	scheme := firstForwardedValue(r.Header.Get("X-Forwarded-Proto"))
	if scheme == "" {
		scheme = "http"
		if r.TLS != nil {
			scheme = "https"
		}
	}
	if scheme != "http" && scheme != "https" {
		return ""
	}

	host := requestHost(r)
	if !trustedHostname(host) {
		return ""
	}

	return scheme + "://" + host
}

func firstForwardedValue(value string) string {
	// The edge must strip/overwrite client-supplied values, or prepend its own
	// value. An edge that appends instead leaves the client in control of the
	// first hop, so that proxy contract must be enforced outside the app.
	if comma := strings.IndexByte(value, ','); comma >= 0 {
		value = value[:comma]
	}
	return strings.TrimSpace(value)
}

func requestHost(r *http.Request) string {
	host := firstForwardedValue(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = r.Host
	}
	return host
}

// trustedHostname reports whether a host belongs to this site: localhost in
// dev, or an mtgban.com host in production. Matched on the hostname exactly
// (dropping any :port) and by suffix rather than substring, so a spoofed
// "…mtgban.com.evil.tld" can't slip through.
func trustedHostname(host string) bool {
	name, ok := validHostname(firstForwardedValue(host))
	if !ok {
		return false
	}
	return name == "localhost" || name == "mtgban.com" || strings.HasSuffix(name, ".mtgban.com")
}

func validHostname(host string) (string, bool) {
	if strings.Count(host, ":") == 1 {
		name, port, _ := strings.Cut(host, ":")
		if port == "" {
			return "", false
		}
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return "", false
		}
		host = name
	} else if strings.Contains(host, ":") {
		return "", false
	}

	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return "", false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return "", false
			}
		}
	}
	return host, true
}

func (s *site) Auth(w http.ResponseWriter, r *http.Request) {
	origin := requestOrigin(r)
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
			s.failAPIHandoff(w, r, ErrMsgAPIHandoffNoAnswer)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Get the access token for this connection
	source := Config().Patreon.Source
	clientID := Config().Patreon.Client[source]
	secret := Config().Patreon.Secret[source]
	tokens, err := patreon.GetAuthToken(r.Context(), clientID, secret, origin, code)
	if err != nil {
		LogPages["Admin"].Println("getUserToken", err.Error())
		if isHandoff {
			s.failAPIHandoff(w, r, ErrMsgAPIHandoffNoAnswer)
			return
		}
		http.Redirect(w, r, "/?errmsg=TokenNotFound", http.StatusFound)
		return
	}

	// The client to interface with Patreon
	client := patreon.NewPatreonClient(r.Context(), tokens.AccessToken)

	// Retrieve information about the user who just authenticated
	userData, err := getUserIDs(r.Context(), client)
	if err != nil {
		LogPages["Admin"].Println("getUserId", err.Error())
		if isHandoff {
			s.failAPIHandoff(w, r, ErrMsgAPIHandoffNoAnswer)
			return
		}
		http.Redirect(w, r, "/?errmsg=UserNotFound", http.StatusFound)
		return
	}

	tierTitle := ""
	var overrides map[string]map[string]string
	// If user is in the allowed list, load the tier from here
	grant, found := indexGrants(PatreonGrants()).find(userstate.HashEmail(userData.Email))
	if found {
		tierTitle = grant.Tier
		overrides = grant.Overrides
		LogPages["Admin"].Printf("Granted %s (%s) %s tier for %s", grant.Name, grant.Email, grant.Tier, grant.Category)
	}

	// Else, load the tier from the API
	if tierTitle == "" {
		foundTitle, err := getUserTier(r.Context(), client, userData.MembershipID)
		if err != nil {
			LogPages["Admin"].Println("getUserTier error", err)
		}
		switch foundTitle {
		case "PIONEER", "PIONEER (Early Adopters)", "STANDARD":
			tierTitle = "Pioneer"
		case "MODERN", "MODERN (Early Adopters)":
			tierTitle = "Modern"
		case "LEGACY", "LEGACY (Early Adopters)":
			tierTitle = "Legacy"
		case "VINTAGE", "VINTAGE (Early Adopters)", "TYPE ONE":
			tierTitle = "Vintage"
		}
	}

	if isHandoff {
		s.finishAPIHandoff(w, r, handoff, userData, tierTitle)
		return
	}

	// Handle error
	if tierTitle == "" {
		LogPages["Admin"].Println("getUserTier returned an empty tier")
		http.Redirect(w, r, "/?errmsg=TierNotFound", http.StatusFound)
		return
	}

	LogPages["Admin"].Printf("auth: email=%s tier=%s", userData.Email, tierTitle)

	// Sign our base URL with our tier and other data
	sig := sign(tierTitle, userData, overrides, DefaultSignatureDuration)

	// Whether this tier grants alerts at all, computed once rather than
	// re-parsing the signature just signed.
	allowed := alertContactAllowed(tierTitle, overrides)
	channels := alertContactChannels(tierTitle, overrides)

	// A grant's tier is not stored: the evaluator reads a live grant's own,
	// and a revoked one must not leave its tier behind until the next login.
	contactTier := tierTitle
	if found && grant.Tier != "" {
		contactTier = ""
	}
	alertCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	err = recordAlertContact(alertCtx, s.alertContacts(), userData, contactTier, allowed, channels)
	if err != nil {
		LogPages["Admin"].Println("recordAlertContact", err)
	}

	// Keep it secret. Keep it safe.
	putSignatureInCookies(w, r, sig)

	// Redirect to the URL indicated in this query param, or go to homepage.
	// Drop a stale error from the page that started the login flow now that
	// authentication succeeded.
	redir := authRedirect(r.FormValue("state"))

	// Redirect, we're done here
	http.Redirect(w, r, redir, http.StatusFound)
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

// unverifiedSignature is the request's signature, the MTGBAN cookie or else
// ?sig=, checked for nothing but its expiry. It is what the checks below
// start from; anything that acts on a grant reads verifiedSignature or
// verifiedRequestSignature instead.
func unverifiedSignature(r *http.Request) string {
	sig := readCookie(r, "MTGBAN")

	querySig := r.FormValue("sig")
	if sig == "" && querySig != "" {
		sig = querySig
	}

	exp := GetParamFromSig(sig, "Expires")
	if exp == "" {
		return ""
	}
	expires, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || expires < time.Now().Unix() {
		return ""
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

	q := url.Values{}
	for _, optional := range SignedFields {
		if val := v.Get(optional); val != "" {
			q.Set(optional, val)
		}
	}

	exp := v.Get("Expires")
	data := fmt.Sprintf("GET%s%s%s", exp, signatureLink(), q.Encode())
	valid := signHMACSHA1Base64([]byte(os.Getenv("BAN_SECRET")), []byte(data))
	expires, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || !hmac.Equal([]byte(valid), []byte(v.Get("Signature"))) || expires < time.Now().Unix() {
		return v, false
	}
	return v, true
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

// signatureCookieDays is how long the MTGBAN cookie keeps a signature, and so
// the longest an invite link may last: one that outlived its cookie would be
// dropped by the browser while still valid.
const signatureCookieDays = 31

// Put signature in cookies for a month, all domains can access this
func putSignatureInCookies(w http.ResponseWriter, r *http.Request, sig string) {
	expires := time.Now().Add(signatureCookieDays * 24 * time.Hour)
	setCookie(w, r, "MTGBAN", sig, expires, true)
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

// withSignatureCookie is r carrying sig as its MTGBAN cookie, in place of
// any the request came with.
func withSignatureCookie(r *http.Request, sig string) *http.Request {
	out := r.Clone(r.Context())
	out.Header.Del("Cookie")
	for _, c := range r.Cookies() {
		if c.Name != "MTGBAN" {
			out.AddCookie(c)
		}
	}
	out.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sig})
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
		}

		next.ServeHTTP(w, r)
	})
}

func enforceAPISigning(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer recoverPanic(r, w)

		w.Header().Add("RateLimit-Limit", fmt.Sprint(APIRequestsPerSec))

		ip, err := ratelimit.IPAddress(r)
		if err != nil {
			log.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if !APIRateLimiter.Allow(string(ip)) {
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}

		if len(GetSellers()) == 0 || len(GetVendors()) == 0 {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
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
			w.Write([]byte(`{"error": "invalid signature"}`))
			return
		}

		// Kept ungated to match the previous middleware exactly.
		if exp := v.Get("Expires"); exp != "" {
			if _, err := strconv.ParseInt(exp, 10, 64); err != nil {
				log.Println("API error", err.Error())
				w.Write([]byte(`{"error": "invalid or expired signature"}`))
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
			w.Write([]byte(`{"error": "invalid or expired signature"}`))
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
// checks ShouldHide, both of which read the site's current datastore.
func enforceSigning(s *site, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer recoverPanic(r, w)

		// Check if this endpoint can be bypassed
		_, checkNoAuth := ACL()["Any"]
		if checkNoAuth {
			for key, nav := range ExtraNavs {
				if nav.Link == r.URL.Path || slices.ContainsFunc(nav.SubPages, func(p NavElem) bool {
					// Check prefix because Link may contain query params
					return strings.HasPrefix(p.Link, r.URL.Path)
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
		if ok {
			limitKey = checked.Get("UserEmail")
			if limitKey == "" {
				limitKey = checked.Get("Signature")
			}
		}
		if !UserRateLimiter.Allow(limitKey) && r.URL.Path != "/admin" {
			pageVars := genPageNav(s, r, "Error", sig)
			pageVars.Title = "Too Many Requests"
			pageVars.ErrorMessage = ErrMsgUseAPI

			render(w, "home.html", pageVars)
			return
		}

		raw, err := base64.StdEncoding.DecodeString(sig)
		if SigCheck && err != nil {
			pageVars := genPageNav(s, r, "Error", sig)
			pageVars.Title = "Unauthorized"
			pageVars.ErrorMessage = ErrMsg
			if DevMode {
				pageVars.ErrorMessage += " - " + err.Error()
			}

			render(w, "home.html", pageVars)
			return
		}

		v, err := url.ParseQuery(string(raw))
		if SigCheck && err != nil {
			pageVars := genPageNav(s, r, "Error", sig)
			pageVars.Title = "Unauthorized"
			pageVars.ErrorMessage = ErrMsg
			if DevMode {
				pageVars.ErrorMessage += " - " + err.Error()
			}

			render(w, "home.html", pageVars)
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
			pageVars := genPageNav(s, r, "Error", sig)
			pageVars.Title = "Unauthorized"
			pageVars.ErrorMessage = ErrMsg
			if signed && expires < time.Now().Unix() {
				pageVars.ErrorMessage = ErrMsgExpired
				pageVars.PatreonLogin = true
				if DevMode {
					pageVars.ErrorMessage += " - sig expired"
				}
			}

			if DevMode {
				if err != nil {
					pageVars.ErrorMessage += " - " + err.Error()
				} else {
					pageVars.ErrorMessage += " - wrong host"
				}
			}

			render(w, "home.html", pageVars)
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
func sign(tierTitle string, userData *PatreonUserData, overrides map[string]map[string]string, duration time.Duration) string {
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
