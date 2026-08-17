package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mtgban/mtgban-website/patreon"
	"github.com/mtgban/mtgban-website/ratelimit"
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
)

var APIRateLimiter = ratelimit.NewLimiter(APIRequestsPerSec, 2)

var UserRateLimiter = ratelimit.NewLimiter(UserRequestsPerSec, 1)

type PatreonGrant struct {
	Category string `json:"category"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Tier     string `json:"tier"`
}

type PatreonConfig struct {
	Source string            `json:"source"`
	Client map[string]string `json:"client"`
	Secret map[string]string `json:"secret"`
	Grants []PatreonGrant    `json:"grants"`
}

type PatreonUserData struct {
	UserId       string
	MembershipId string
	FullName     string
	Email        string
}

func getUserIds(ctx context.Context, client *patreon.Client) (*PatreonUserData, error) {
	userData, err := client.GetUserData(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot retrieve user data: %w", err)
	}

	LogPages["Admin"].Println("getUserIds:", userData)
	if len(userData.Errors) > 0 {
		return nil, fmt.Errorf("user data error: %q", userData.Errors)
	}

	// Look for the membership id of the user and this account
	membershipId := ""
	for _, memberData := range userData.Data.Relationships.Memberships.Data {
		if memberData.Type == "member" {
			membershipId = memberData.Id
			break
		}
	}

	return &PatreonUserData{
		UserId:       userData.Data.IdV1,
		MembershipId: membershipId,
		FullName:     userData.Data.Attributes.FullName,
		Email:        strings.ToLower(userData.Data.Attributes.Email),
	}, nil
}

func getUserTier(ctx context.Context, client *patreon.Client, userId string) (string, error) {
	membershipData, err := client.GetMembershipData(ctx, userId)
	if err != nil {
		return "", fmt.Errorf("cannot decode membership data: %w", err)
	}

	LogPages["Admin"].Println("getUserTier:", membershipData)
	if len(membershipData.Errors) > 0 {
		return "", fmt.Errorf("user data error: %q", membershipData.Errors)
	}

	// Look for the tier id of the user
	tierId := ""
	for _, tierData := range membershipData.Data.Relationships.CurrentlyEntitledTiers.Data {
		if tierData.Type == "tier" {
			tierId = tierData.Id
			break
		}
	}

	// Get a human-readable name for the tier
	tierTitle := ""
	for _, tierData := range membershipData.Included {
		if tierData.Type == "tier" && tierId == tierData.Id {
			tierTitle = tierData.Attributes.Title
		}
	}

	if tierTitle == "" {
		return "", errors.New("empty tier title")
	}

	return tierTitle, nil
}

// Retrieve the main url, mostly for Patron auth -- we can't use the one provided
// by the url since it can be relative and thus empty
func getServerURL(r *http.Request) string {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		scheme = "http"
		if r.TLS != nil {
			scheme = "https"
		}
	}

	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}

	return scheme + "://" + host
}

// initServerURL latches the external ServerURL from the first request on a host
// we trust — localhost in dev, any *.mtgban.com in production. Requests on any
// other host are ignored, notably the raw *.ondigitalocean.app app URL that a
// platform health check hits before any custom-domain traffic: latching that
// would pin ServerURL to a hostname that isn't a registered Patreon redirect
// target and then leak into every redirect, embed, and OAuth link.
func initServerURL(r *http.Request) {
	if ServerURL != "" {
		return
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	// Match the hostname exactly (dropping any :port) so only localhost in dev
	// or an mtgban.com host in prod can latch ServerURL — a suffix check, not a
	// substring one, so a spoofed "…mtgban.com.evil.tld" Host can't slip through.
	name, _, _ := strings.Cut(host, ":")
	name = strings.ToLower(name)
	if name != "localhost" && name != "mtgban.com" && !strings.HasSuffix(name, ".mtgban.com") {
		return
	}
	ServerURL = getServerURL(r)
	log.Println("Setting server URL as", ServerURL)
}

func Auth(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	if code == "" {
		http.Redirect(w, r, ServerURL, http.StatusFound)
		return
	}

	// Get the access token for this connection
	source := Config.Patreon.Source
	clientId := Config.Patreon.Client[source]
	secret := Config.Patreon.Secret[source]
	tokens, err := patreon.GetAuthToken(r.Context(), clientId, secret, ServerURL, code)
	if err != nil {
		LogPages["Admin"].Println("getUserToken", err.Error())
		http.Redirect(w, r, ServerURL+"?errmsg=TokenNotFound", http.StatusFound)
		return
	}

	// The client to interface with Patreon
	client := patreon.NewPatreonClient(r.Context(), tokens.AccessToken)

	// Retrieve information about the user who just authenticated
	userData, err := getUserIds(r.Context(), client)
	if err != nil {
		LogPages["Admin"].Println("getUserId", err.Error())
		http.Redirect(w, r, ServerURL+"?errmsg=UserNotFound", http.StatusFound)
		return
	}

	tierTitle := ""
	// If user is in the allowed list, load the tier from here
	for _, grant := range Config.Patreon.Grants {
		if strings.ToLower(grant.Email) == userData.Email {
			tierTitle = grant.Tier
			LogPages["Admin"].Printf("Granted %s (%s) %s tier for %s", grant.Name, grant.Email, grant.Tier, grant.Category)
			break
		}
	}

	// Else, load the tier from the API
	if tierTitle == "" {
		foundTitle, err := getUserTier(r.Context(), client, userData.MembershipId)
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

	// Handle error
	if tierTitle == "" {
		LogPages["Admin"].Println("getUserTier returned an empty tier")
		http.Redirect(w, r, ServerURL+"?errmsg=TierNotFound", http.StatusFound)
		return
	}

	LogPages["Admin"].Println(userData)
	LogPages["Admin"].Println(tierTitle)

	// Sign our base URL with our tier and other data
	sig := sign(tierTitle, userData)

	// Keep it secret. Keep it safe.
	putSignatureInCookies(w, sig)

	// Redirect, we're done here
	redirectAfterAuth(w, r)
}

// redirectAfterAuth returns the visitor to the page indicated in the state
// query param, or to the homepage.
//
// State rides through Patreon untouched and comes back as whatever the link
// that opened the flow put there, so a crafted authorize URL names any site it
// likes - and by the time we read it the session cookie is already set.
// isLocalRedirect is no help here: templates build state out of
// window.location.href, so a legitimate one is absolute.
func redirectAfterAuth(w http.ResponseWriter, r *http.Request) {
	redir := strings.Split(r.FormValue("state"), ";")[0]

	// Go back home when coming back from a logout, and whenever the target is
	// not ours - which is also how the empty state lands there
	if strings.Contains(redir, "errmsg=logout") || !isServerOrigin(redir) {
		redir = ServerURL
	}

	http.Redirect(w, r, redir, http.StatusFound)
}

// isServerOrigin reports whether target is an absolute URL on this very site,
// naming both the scheme and the host that ServerURL does.
//
// Comparing the parsed host is what refuses the spellings that only look like
// ours: "https://www.mtgban.com@evil.com" parses with evil.com as the host,
// and the schemeless, backslash and scheme-only forms parse with no host at
// all. An unset ServerURL matches nothing, since without it there is no origin
// to be part of.
func isServerOrigin(target string) bool {
	server, err := url.Parse(ServerURL)
	if err != nil || server.Host == "" {
		return false
	}
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	return u.Scheme == server.Scheme && u.Host == server.Host
}

func signHMACSHA1Base64(key []byte, data []byte) string {
	h := hmac.New(sha1.New, key)
	h.Write(data)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func getSignatureFromCookies(r *http.Request) string {
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

// signedUserEmail returns the UserEmail from a validly-signed, unexpired cookie/sig, else "". Mirrors enforceSigning's HMAC check but allows any method.
func signedUserEmail(r *http.Request) string {
	sig := getSignatureFromCookies(r)
	if querySig := r.FormValue("sig"); querySig != "" {
		sig = querySig
	}
	if sig == "" {
		return ""
	}

	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return ""
	}
	v, err := url.ParseQuery(string(raw))
	if err != nil {
		return ""
	}

	if !SigCheck {
		return v.Get("UserEmail")
	}

	q := url.Values{}
	for _, optional := range SignedFields {
		if val := v.Get(optional); val != "" {
			q.Set(optional, val)
		}
	}

	link := DefaultServerURL
	if !strings.HasSuffix(ServerURL, "mtgban.com") {
		link = "http://localhost:" + fmt.Sprint(Config.Port)
	}
	exp := v.Get("Expires")
	data := fmt.Sprintf("GET%s%s%s", exp, link, q.Encode())
	valid := signHMACSHA1Base64([]byte(os.Getenv("BAN_SECRET")), []byte(data))
	expires, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || valid != v.Get("Signature") || expires < time.Now().Unix() {
		return ""
	}
	return v.Get("UserEmail")
}

// Put signature in cookies for one month, all domains can access this
func putSignatureInCookies(w http.ResponseWriter, sig string) {
	oneMonth := time.Now().Add(31 * 24 * 60 * 60 * time.Second)
	setCookie(w, "MTGBAN", sig, oneMonth, true)
}

// adminOnly hides the wrapped handler from signatures that do not carry
// the Admin grant. It performs no validation of its own: it must sit
// behind enforceSigning, which authenticates the signature before any of
// its parameters can be trusted. Non-admins get a plain 404 so the
// endpoint's existence is not advertised.
func adminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		canDo, _ := strconv.ParseBool(GetParamFromSig(getSignatureFromCookies(r), "Admin"))
		if !canDo && !(DevMode && !SigCheck) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// This function is mostly here only for initializing the host
// and the signature from invite links
func noSigning(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer recoverPanic(r, w)

		initServerURL(r)

		querySig := r.FormValue("sig")
		if querySig != "" {
			putSignatureInCookies(w, querySig)
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

		raw, err := base64.StdEncoding.DecodeString(sig)
		if SigCheck && err != nil {
			log.Println("API error, no sig", err)
			w.Write([]byte(`{"error": "invalid signature"}`))
			return
		}

		v, err := url.ParseQuery(string(raw))
		if SigCheck && err != nil {
			log.Println("API error, no b64", err)
			w.Write([]byte(`{"error": "invalid b64 signature"}`))
			return
		}

		q := url.Values{}
		q.Set("API", v.Get("API"))

		for _, optional := range OptionalFields {
			val := v.Get(optional)
			if val != "" {
				q.Set(optional, val)
			}
		}

		sig = v.Get("Signature")
		exp := v.Get("Expires")

		secret := os.Getenv("BAN_SECRET")
		apiUsersMutex.RLock()
		user_secret, found := Config.ApiUserSecrets[v.Get("UserEmail")]
		apiUsersMutex.RUnlock()
		if found {
			secret = user_secret
		}

		var expires int64
		if exp != "" {
			expires, err = strconv.ParseInt(exp, 10, 64)
			if err != nil {
				log.Println("API error", err.Error())
				w.Write([]byte(`{"error": "invalid or expired signature"}`))
				return
			}
			q.Set("Expires", exp)
		}

		link := DefaultServerURL
		if !strings.HasSuffix(ServerURL, "mtgban.com") {
			link = "http://localhost:" + fmt.Sprint(Config.Port)
		}
		data := fmt.Sprintf("%s%s%s%s", r.Method, exp, link, q.Encode())
		valid := signHMACSHA1Base64([]byte(secret), []byte(data))

		if SigCheck && (valid != sig || (exp != "" && (expires < time.Now().Unix()))) {
			log.Println("API error, invalid", data)
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

func enforceSigning(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer recoverPanic(r, w)

		initServerURL(r)

		// Check if this endpoint can be bypassed
		_, checkNoAuth := Config.ACL["Any"]
		if checkNoAuth {
			for _, nav := range ExtraNavs {
				if nav.Link == r.URL.Path || slices.ContainsFunc(nav.SubPages, func(p NavElem) bool {
					// Check prefix because Link may contain query params
					return strings.HasPrefix(p.Link, r.URL.Path)
				}) {
					_, noAuth := Config.ACL["Any"][nav.Name]
					if noAuth {
						recordPageHit(r)
						noSigning(next).ServeHTTP(w, r)
						return
					}
				}
			}
		}

		sig := getSignatureFromCookies(r)
		querySig := r.FormValue("sig")
		if querySig != "" {
			sig = querySig
			putSignatureInCookies(w, querySig)
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
		if !UserRateLimiter.Allow(GetParamFromSig(sig, "UserEmail")) && r.URL.Path != "/admin" {
			pageVars := genPageNav("Error", sig)
			pageVars.Title = "Too Many Requests"
			pageVars.ErrorMessage = ErrMsgUseAPI

			render(w, "home.html", pageVars)
			return
		}

		raw, err := base64.StdEncoding.DecodeString(sig)
		if SigCheck && err != nil {
			pageVars := genPageNav("Error", sig)
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
			pageVars := genPageNav("Error", sig)
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

		link := DefaultServerURL
		if !strings.HasSuffix(ServerURL, "mtgban.com") {
			link = "http://localhost:" + fmt.Sprint(Config.Port)
		}
		data := fmt.Sprintf("GET%s%s%s", exp, link, q.Encode())
		valid := signHMACSHA1Base64([]byte(os.Getenv("BAN_SECRET")), []byte(data))
		expires, err := strconv.ParseInt(exp, 10, 64)
		if SigCheck && (err != nil || valid != expectedSig || expires < time.Now().Unix()) {
			if r.Method != "GET" {
				http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
				return
			}
			pageVars := genPageNav("Error", sig)
			pageVars.Title = "Unauthorized"
			pageVars.ErrorMessage = ErrMsg
			if valid == expectedSig && expires < time.Now().Unix() {
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
					pageVars := genPageNav(nav.Name, sig)
					pageVars.Title = "This feature is BANned"
					pageVars.ErrorMessage = ErrMsgPlus

					render(w, nav.Page, pageVars)
					return
				}

				// Check if link is a subpage, and validate if viewing conditions are met
				for _, subPage := range nav.SubPages {
					if targetsSubPage(r, subPage.Link) &&
						subPage.ShouldHide != nil && subPage.ShouldHide() {
						pageVars := genPageNav("Error", sig)
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
		log.Println("panic occurred:", errPanic)

		// Restrict stack size to fit into discord message
		buf := make([]byte, 1<<16)
		runtime.Stack(buf, true)
		if len(buf) > 1024 {
			buf = buf[:1024]
		}

		var msg string
		err, ok := errPanic.(error)
		if ok {
			msg = err.Error()
		} else {
			msg = "unknown error"
		}
		ServerNotify("panic", msg, true)
		ServerNotify("panic", string(buf))
		ServerNotify("panic", "source request: "+r.URL.String())

		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func getValuesForTier(tierTitle string) url.Values {
	v := url.Values{}
	tier, found := Config.ACL[tierTitle]
	if !found {
		return v
	}
	for _, page := range OrderNav {
		options, found := tier[page]
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
	return v
}

// Every sig-encoded permission field in signing order: OrderNav then
// OptionalFields. Both lists are fixed at startup, so the concatenation the
// signing and verification paths walk is computed once instead of per request.
var SignedFields = slices.Concat(OrderNav, OptionalFields)

func sign(tierTitle string, userData *PatreonUserData) string {
	v := getValuesForTier(tierTitle)
	if userData != nil {
		v.Set("UserName", userData.FullName)
		v.Set("UserEmail", userData.Email)
		v.Set("UserTier", tierTitle)
	}

	// This is constant or localhost for legacy reason
	link := DefaultServerURL
	if !strings.HasSuffix(ServerURL, "mtgban.com") {
		link = "http://localhost:" + fmt.Sprint(Config.Port)
	}
	expires := time.Now().Add(DefaultSignatureDuration)
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
