package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
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

	"github.com/NYTimes/gziphandler"
	"github.com/hashicorp/go-cleanhttp"
	"golang.org/x/oauth2"
)

const (
	PatreonTokenURL    = "https://www.patreon.com/api/oauth2/token"
	PatreonIdentityURL = "https://www.patreon.com/api/oauth2/v2/identity?include=memberships&fields%5Buser%5D=email,first_name,full_name,image_url,last_name,social_connections,thumb_url,url,vanity"
	PatreonMemberURL   = "https://www.patreon.com/api/oauth2/v2/members/"
	PatreonMemberOpts  = "?include=currently_entitled_tiers&fields%5Btier%5D=title"
)

const (
	ErrMsg        = "Join the BAN Community and gain access to exclusive tools!"
	ErrMsgPlus    = "Increase your pledge to gain access to this feature!"
	ErrMsgDenied  = "Something went wrong while accessing this page"
	ErrMsgExpired = "You've been logged out"
	ErrMsgRestart = "Website is restarting, please try again in a few minutes"
	ErrMsgUseAPI  = "Slow down, you're making too many requests! For heavy data use consider the BAN API"
)

type PatreonConfig struct {
	Client map[string]string `json:"client"`
	Secret map[string]string `json:"secret"`
	Grants []struct {
		Category string `json:"category"`
		Email    string `json:"email"`
		Name     string `json:"name"`
		Tier     string `json:"tier"`
	} `json:"grants"`
}

func getUserToken(code, baseURL, ref string) (string, error) {
	source := "ban"

	// ref might point to a different patreon configuration
	refs := strings.Split(ref, ";")
	if len(refs) > 1 {
		source = refs[1]
	}

	clientId, found := Config.Patreon.Client[source]
	if !found {
		return "", fmt.Errorf("missing client id for %s", source)
	}
	secret, found := Config.Patreon.Secret[source]
	if !found {
		return "", fmt.Errorf("missing secret for %s", source)
	}

	resp, err := cleanhttp.DefaultClient().PostForm(PatreonTokenURL, url.Values{
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"client_id":     {clientId},
		"client_secret": {secret},
		"redirect_uri":  {baseURL + "/auth"},
	})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var userTokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Expires      int    `json:"expires_in"`
		Scope        string `json:"scope"`
		TokenType    string `json:"token_type"`
	}
	err = json.NewDecoder(resp.Body).Decode(&userTokens)
	if err != nil {
		return "", fmt.Errorf("cannot decode user tokens: %w", err)
	}

	return userTokens.AccessToken, nil
}

type PatreonUserData struct {
	UserIds  []string
	FullName string
	Email    string
}

// Retrieve a user id for each membership of the current user
func getUserIds(tc *http.Client) (*PatreonUserData, error) {
	resp, err := tc.Get(PatreonIdentityURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var userData struct {
		Errors []struct {
			Title    string `json:"title"`
			CodeName string `json:"code_name"`
		} `json:"errors"`
		Data struct {
			Attributes struct {
				Email    string `json:"email"`
				FullName string `json:"full_name"`
			} `json:"attributes"`
			Relationships struct {
				Memberships struct {
					Data []struct {
						Id   string `json:"id"`
						Type string `json:"type"`
					} `json:"data"`
				} `json:"memberships"`
			} `json:"relationships"`
			IdV1 string `json:"id"`
		} `json:"data"`
	}

	err = json.NewDecoder(resp.Body).Decode(&userData)
	if err != nil {
		return nil, fmt.Errorf("cannot decode user data: %w", err)
	}
	LogPages["Admin"].Println("getUserIds:", userData)
	if len(userData.Errors) > 0 {
		return nil, errors.New(userData.Errors[0].CodeName)
	}

	userIds := []string{userData.Data.IdV1}
	for _, memberData := range userData.Data.Relationships.Memberships.Data {
		if memberData.Type == "member" {
			userIds = append(userIds, memberData.Id)
			break
		}
	}

	return &PatreonUserData{
		UserIds:  userIds,
		FullName: userData.Data.Attributes.FullName,
		Email:    strings.ToLower(userData.Data.Attributes.Email),
	}, nil
}

func getUserTier(tc *http.Client, userId string) (string, error) {
	resp, err := tc.Get(PatreonMemberURL + userId + PatreonMemberOpts)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var membershipData struct {
		Errors []struct {
			Title    string `json:"title"`
			CodeName string `json:"code_name"`
			Detail   string `json:"detail"`
		} `json:"errors"`
		Data struct {
			Relationships struct {
				CurrentlyEntitledTiers struct {
					Data []struct {
						Id   string `json:"id"`
						Type string `json:"type"`
					} `json:"data"`
				} `json:"currently_entitled_tiers"`
			} `json:"relationships"`
		} `json:"data"`
		Included []struct {
			Attributes struct {
				Title string `json:"title"`
			} `json:"attributes"`
			Id   string `json:"id"`
			Type string `json:"type"`
		} `json:"included"`
	}
	tierId := ""
	tierTitle := ""
	err = json.NewDecoder(resp.Body).Decode(&membershipData)
	if err != nil {
		return "", fmt.Errorf("cannot decode membership data: %w", err)
	}
	LogPages["Admin"].Println("getUserTier:", membershipData)
	if len(membershipData.Errors) > 0 {
		return "", errors.New(membershipData.Errors[0].Detail)
	}

	for _, tierData := range membershipData.Data.Relationships.CurrentlyEntitledTiers.Data {
		if tierData.Type == "tier" {
			tierId = tierData.Id
			break
		}
	}
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

func Auth(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	if code == "" {
		http.Redirect(w, r, ServerURL, http.StatusFound)
		return
	}

	token, err := getUserToken(code, ServerURL, r.FormValue("state"))
	if err != nil {
		LogPages["Admin"].Println("getUserToken", err.Error())
		http.Redirect(w, r, ServerURL+"?errmsg=TokenNotFound", http.StatusFound)
		return
	}

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(r.Context(), ts)

	userData, err := getUserIds(tc)
	if err != nil {
		LogPages["Admin"].Println("getUserId", err.Error())
		http.Redirect(w, r, ServerURL+"?errmsg=UserNotFound", http.StatusFound)
		return
	}

	tierTitle := ""
	for _, grant := range Config.Patreon.Grants {
		if grant.Email == userData.Email {
			tierTitle = grant.Tier
			LogPages["Admin"].Printf("Granted %s (%s) %s tier for %s", grant.Name, grant.Email, grant.Tier, grant.Category)
			break
		}
	}

	if tierTitle == "" {
		for _, userId := range userData.UserIds[1:] {
			foundTitle, _ := getUserTier(tc, userId)
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
	}

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

	// Redirect to the URL indicated in this query param, or go to homepage
	redir := strings.Split(r.FormValue("state"), ";")[0]

	// Go back home if empty or if coming back from a logout
	if redir == "" || strings.Contains(redir, "errmsg=logout") {
		redir = ServerURL
	}

	// Redirect, we're done here
	http.Redirect(w, r, redir, http.StatusFound)
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

// Put signature in cookies for one month, all domains can access this
func putSignatureInCookies(w http.ResponseWriter, sig string) {
	oneMonth := time.Now().Add(31 * 24 * 60 * 60 * time.Second)
	setCookie(w, "MTGBAN", sig, oneMonth, true)
}

// This function is mostly here only for initializing the host
// and the signature from invite links
func noSigning(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer recoverPanic(r, w)

		if ServerURL == "" {
			ServerURL = getServerURL(r)
			log.Println("Setting server URL as", ServerURL)
		}

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

		ip, err := IpAddress(r)
		if err != nil {
			log.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if !APIRateLimiter.allow(string(ip)) {
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}

		if len(Sellers) == 0 || len(Vendors) == 0 {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}

		w.Header().Add("Content-Type", "application/json")

		sig := r.FormValue("sig")

		// If signature is empty let it pass through
		if sig == "" && !strings.HasPrefix(r.URL.Path, "/api/load") {
			gziphandler.GzipHandler(next).ServeHTTP(w, r)
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

		gziphandler.GzipHandler(next).ServeHTTP(w, r)
	})
}

func enforceSigning(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer recoverPanic(r, w)

		if ServerURL == "" {
			ServerURL = getServerURL(r)
			log.Println("Setting server URL as", ServerURL)
		}

		// Check if this endpoint can be bypassed
		_, checkNoAuth := Config.ACL["Any"]
		if checkNoAuth {
			for _, nav := range ExtraNavs {
				if nav.Link == r.URL.Path || slices.Contains(nav.SubPages, r.URL.Path) {
					_, noAuth := Config.ACL["Any"][nav.Name]
					if noAuth {
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

		pageVars := genPageNav("Error", sig)

		if !UserRateLimiter.allow(GetParamFromSig(sig, "UserEmail")) && r.URL.Path != "/admin" {
			pageVars.Title = "Too Many Requests"
			pageVars.ErrorMessage = ErrMsgUseAPI

			render(w, "home.html", pageVars)
			return
		}

		raw, err := base64.StdEncoding.DecodeString(sig)
		if SigCheck && err != nil {
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
			pageVars.Title = "Unauthorized"
			pageVars.ErrorMessage = ErrMsg
			if DevMode {
				pageVars.ErrorMessage += " - " + err.Error()
			}

			render(w, "home.html", pageVars)
			return
		}

		q := url.Values{}
		for _, optional := range append(OrderNav, OptionalFields...) {
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
					pageVars = genPageNav(nav.Name, sig)
					pageVars.Title = "This feature is BANned"
					pageVars.ErrorMessage = ErrMsgPlus

					render(w, nav.Page, pageVars)
					return
				}
				break
			}
		}

		gziphandler.GzipHandler(next).ServeHTTP(w, r)
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

func GetParamFromSig(sig, param string) string {
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return ""
	}
	v, err := url.ParseQuery(string(raw))
	if err != nil {
		return ""
	}
	return v.Get(param)
}
