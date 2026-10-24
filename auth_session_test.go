package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/internal/infrastructure"
	"github.com/mtgban/mtgban-website/internal/pledge"
	"github.com/mtgban/mtgban-website/userstate"
)

// openUserStateClient opens the Postgres the userstate tests use, when
// USERSTATE_TEST is set, and closes it after the test.
func openUserStateClient(t *testing.T) *userstate.Client {
	t.Helper()
	if os.Getenv("USERSTATE_TEST") == "" {
		t.Skip("USERSTATE_TEST not set; skipping DB integration test")
	}
	// USERSTATE_TEST_HOST, _PORT, _USER, _PASSWORD and _DB name the server,
	// each defaulting to the local one's.
	port, err := strconv.Atoi(userStateTestEnv("USERSTATE_TEST_PORT", "5432"))
	if err != nil {
		t.Fatalf("USERSTATE_TEST_PORT: %v", err)
	}
	client, err := userstate.NewClient(userstate.SQLConfig{
		Host: userStateTestEnv("USERSTATE_TEST_HOST", "127.0.0.1"), Port: port, User: userStateTestEnv("USERSTATE_TEST_USER", "mtgban"),
		Password: userStateTestEnv("USERSTATE_TEST_PASSWORD", "mtgban"), DBName: userStateTestEnv("USERSTATE_TEST_DB", "user_state"), SSLMode: "disable",
	})
	if err != nil {
		t.Fatalf("userstate.NewClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

// testUserStateDB serves the test's own client as UserStateDB for the test.
func testUserStateDB(t *testing.T) *userstate.Client {
	t.Helper()
	client := openUserStateClient(t)
	saved := UserStateDB
	UserStateDB = client
	t.Cleanup(func() { UserStateDB = saved })
	return client
}

// userStateTestEnv is the named variable when it is set, empty included, else def.
func userStateTestEnv(name, def string) string {
	v, ok := os.LookupEnv(name)
	if !ok {
		return def
	}
	return v
}

// captureAdminLog sends the admin log to the returned builder for the test.
func captureAdminLog(t *testing.T) *strings.Builder {
	t.Helper()
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	saved := LogPages["Admin"]
	t.Cleanup(func() { LogPages["Admin"] = saved })
	var logged strings.Builder
	LogPages["Admin"] = log.New(&logged, "", 0)
	return &logged
}

// sessionReader is a Patreon reader no other test shares a row with; the
// rows their logins leave are deleted after the test.
func sessionReader(t *testing.T, db *userstate.Client, name string) *pledge.User {
	t.Helper()
	user := &pledge.User{
		Email:         fmt.Sprintf("%s-%d@example.com", name, time.Now().UnixNano()),
		FullName:      "Session " + name,
		EmailVerified: true,
	}
	if db != nil {
		t.Cleanup(func() {
			// t.Context() is already canceled when a cleanup runs
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := db.DeletePatreonSessions(ctx, userstate.HashEmail(user.Email))
			if err != nil {
				t.Errorf("deleting %s's sessions: %v", name, err)
			}
		})
	}
	return user
}

// siteRequest is a browser's request for path on mtgban.com.
func siteRequest(path string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "mtgban.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	return req
}

// siteLogin runs the callback's site half for the reader Patreon named,
// as a browser on mtgban.com that started the login at state, holding
// cookies.
func siteLogin(t *testing.T, state string, user *pledge.User, refreshToken string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	signingEnabled(t, false)
	req := siteRequest("/auth?code=x")
	for _, c := range cookies {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	rec := httptest.NewRecorder()
	testSite.finishSiteLogin(rec, req, state, user, "Legacy", nil, false, refreshToken)
	return rec
}

// siteLogout is the browser on mtgban.com asking for the logout page while
// it holds cookies.
func siteLogout(t *testing.T, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := siteRequest("/?errmsg=logout")
	for _, c := range cookies {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	rec := httptest.NewRecorder()
	testSite.Home(rec, req)
	return rec
}

// setCookies is the Set-Cookie headers rec carries, by cookie name.
func setCookies(rec *httptest.ResponseRecorder) map[string]*http.Cookie {
	cookies := map[string]*http.Cookie{}
	for _, c := range rec.Result().Cookies() {
		cookies[c.Name] = c
	}
	return cookies
}

// sessionRow is a patreon_sessions row as the login left it.
type sessionRow struct {
	id, token string
	daysLeft  float64
}

// sessionRowsOf is the sessions emailHash holds.
func sessionRowsOf(t *testing.T, db *userstate.Client, emailHash string) []sessionRow {
	t.Helper()
	rows, err := db.DB().QueryContext(t.Context(), `
		SELECT session_id, refresh_token, extract(epoch FROM expires_at - now()) / 86400
		  FROM patreon_sessions WHERE email_hash = $1`, emailHash)
	if err != nil {
		t.Fatalf("reading the sessions: %v", err)
	}
	defer rows.Close()
	var got []sessionRow
	for rows.Next() {
		var row sessionRow
		err = rows.Scan(&row.id, &row.token, &row.daysLeft)
		if err != nil {
			t.Fatalf("scanning a session: %v", err)
		}
		got = append(got, row)
	}
	if rows.Err() != nil {
		t.Fatalf("reading the sessions: %v", rows.Err())
	}
	return got
}

// sessionCookieWant checks the BAN_SESSION cookie a login set, and returns it.
func sessionCookieWant(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	cookie := setCookies(rec)[sessionCookie]
	if cookie == nil {
		t.Fatalf("no %s cookie in %v", sessionCookie, rec.Header()["Set-Cookie"])
	}
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.Domain != "mtgban.com" {
		t.Errorf("session cookie %+v, want HttpOnly Secure Lax on mtgban.com at /", cookie)
	}
	if cookie.MaxAge != signatureCookieDays*24*60*60 {
		t.Errorf("session cookie lives %ds, want %d days", cookie.MaxAge, signatureCookieDays)
	}
	if cookie.Value == "" {
		t.Error("session cookie holds no id")
	}
	return cookie
}

// A login with a refresh token keeps a row for it and binds the browser to
// the row with an HttpOnly cookie beside the signature.
func TestFinishSiteLoginKeepsASession(t *testing.T) {
	db := testUserStateDB(t)
	captureAdminLog(t)
	user := sessionReader(t, db, "keeps")

	rec := siteLogin(t, "/upload", user, "refresh-keeps")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/upload" {
		t.Errorf("status %d to %q, want a redirect to /upload", rec.Code, rec.Header().Get("Location"))
	}
	cookies := setCookies(rec)
	if cookies[signatureCookie] == nil || len(rec.Result().Cookies()) != 2 {
		t.Fatalf("cookies %v, want %s and %s", rec.Header()["Set-Cookie"], signatureCookie, sessionCookie)
	}
	values, ok := signatureIsValid(cookies[signatureCookie].Value)
	if !ok || values.Get("UserEmail") != user.Email {
		t.Errorf("signature %v (valid %v) does not name %s", values, ok, user.Email)
	}
	session := sessionCookieWant(t, rec)

	rows := sessionRowsOf(t, db, userstate.HashEmail(user.Email))
	if len(rows) != 1 {
		t.Fatalf("%d rows for the reader, want 1", len(rows))
	}
	if rows[0].id != session.Value || rows[0].token != "refresh-keeps" {
		t.Errorf("row %+v does not match the cookie %q and the token", rows[0], session.Value)
	}
	if rows[0].daysLeft < 89 || rows[0].daysLeft > 90 {
		t.Errorf("row has %.1f days left, want the default 90", rows[0].daysLeft)
	}
}

// The deployment's max_session_days sets how long the row lasts.
func TestFinishSiteLoginSessionLastsMaxSessionDays(t *testing.T) {
	db := testUserStateDB(t)
	captureAdminLog(t)
	saved := Config().Config.PatreonRenewal
	t.Cleanup(func() { Config().Config.PatreonRenewal = saved })
	Config().Config.PatreonRenewal = infrastructure.PatreonRenewal{MaxSessionDays: 30}
	user := sessionReader(t, db, "capped")

	siteLogin(t, "", user, "refresh-capped")
	rows := sessionRowsOf(t, db, userstate.HashEmail(user.Email))
	if len(rows) != 1 || rows[0].daysLeft < 29 || rows[0].daysLeft > 30 {
		t.Errorf("rows %+v, want one with 30 days left", rows)
	}
}

// Each login is a session of its own.
func TestFinishSiteLoginKeepsOneSessionPerLogin(t *testing.T) {
	db := testUserStateDB(t)
	captureAdminLog(t)
	user := sessionReader(t, db, "twice")

	first := sessionCookieWant(t, siteLogin(t, "", user, "refresh-one"))
	second := sessionCookieWant(t, siteLogin(t, "", user, "refresh-two"))
	if first.Value == second.Value {
		t.Error("two logins share a session id")
	}
	rows := sessionRowsOf(t, db, userstate.HashEmail(user.Email))
	if len(rows) != 2 {
		t.Errorf("%d rows after two logins, want 2", len(rows))
	}
}

// A browser that logs in again gets a new session and loses the one its
// cookie named, so logout always has one row per browser to reach.
func TestFinishSiteLoginReplacesTheBrowsersSession(t *testing.T) {
	db := testUserStateDB(t)
	captureAdminLog(t)
	user := sessionReader(t, db, "relogin")

	first := sessionCookieWant(t, siteLogin(t, "", user, "refresh-first"))
	second := sessionCookieWant(t, siteLogin(t, "", user, "refresh-second", first))
	if first.Value == second.Value {
		t.Error("the re-login kept the old session id")
	}
	rows := sessionRowsOf(t, db, userstate.HashEmail(user.Email))
	if len(rows) != 1 || rows[0].id != second.Value || rows[0].token != "refresh-second" {
		t.Errorf("rows %+v, want only the re-login's", rows)
	}
}

// Without a database the login still signs the reader in, with the
// signature alone.
func TestFinishSiteLoginWithoutADatabase(t *testing.T) {
	captureAdminLog(t)
	saved := UserStateDB
	t.Cleanup(func() { UserStateDB = saved })
	UserStateDB = nil

	rec := siteLogin(t, "", sessionReader(t, nil, "nodb"), "refresh-nodb")
	cookies := rec.Result().Cookies()
	if rec.Code != http.StatusFound || len(cookies) != 1 || cookies[0].Name != signatureCookie {
		t.Errorf("status %d with cookies %v, want a redirect setting only %s", rec.Code, rec.Header()["Set-Cookie"], signatureCookie)
	}
}

// A login that carries no refresh token has nothing to keep.
func TestFinishSiteLoginWithoutARefreshToken(t *testing.T) {
	db := testUserStateDB(t)
	captureAdminLog(t)
	user := sessionReader(t, db, "notoken")

	rec := siteLogin(t, "", user, "")
	cookies := rec.Result().Cookies()
	if rec.Code != http.StatusFound || len(cookies) != 1 || cookies[0].Name != signatureCookie {
		t.Errorf("status %d with cookies %v, want a redirect setting only %s", rec.Code, rec.Header()["Set-Cookie"], signatureCookie)
	}
	rows := sessionRowsOf(t, db, userstate.HashEmail(user.Email))
	if len(rows) != 0 {
		t.Errorf("rows %+v, want none", rows)
	}
}

// A database that cannot take the row costs the login its session and
// nothing else: it is logged, without the token.
func TestFinishSiteLoginWithTheDatabaseDown(t *testing.T) {
	down := testUserStateDB(t)
	spare := openUserStateClient(t)
	logged := captureAdminLog(t)
	user := sessionReader(t, spare, "down")
	down.Close()

	rec := siteLogin(t, "", user, "refresh-down-secret")
	cookies := rec.Result().Cookies()
	if rec.Code != http.StatusFound || len(cookies) != 1 || cookies[0].Name != signatureCookie {
		t.Errorf("status %d with cookies %v, want a redirect setting only %s", rec.Code, rec.Header()["Set-Cookie"], signatureCookie)
	}
	if !strings.Contains(logged.String(), "CreatePatreonSession") {
		t.Errorf("log %q does not name the failure", logged.String())
	}
	if strings.Contains(logged.String(), "refresh-down-secret") {
		t.Errorf("log %q holds the refresh token", logged.String())
	}
	rows := sessionRowsOf(t, spare, userstate.HashEmail(user.Email))
	if len(rows) != 0 {
		t.Errorf("rows %+v, want none", rows)
	}
}

// Logging out deletes the row the browser's cookie names, and only that one,
// and clears the cookies with the attributes they were set with.
func TestLogoutDeletesTheSession(t *testing.T) {
	db := testUserStateDB(t)
	captureAdminLog(t)
	user := sessionReader(t, db, "logout")
	hash := userstate.HashEmail(user.Email)

	login := siteLogin(t, "", user, "refresh-here")
	siteLogin(t, "", user, "refresh-elsewhere")
	set := setCookies(login)
	session := sessionCookieWant(t, login)

	rec := siteLogout(t, set[signatureCookie], session)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Errorf("status %d to %q, want a redirect home", rec.Code, rec.Header().Get("Location"))
	}
	rows := sessionRowsOf(t, db, hash)
	if len(rows) != 1 || rows[0].token != "refresh-elsewhere" {
		t.Errorf("rows %+v, want only the other login's", rows)
	}
	checkLogoutClears(t, rec, set)
}

// checkLogoutClears expects the logout to drop each cookie a login set, and
// the legacy signature cookie, by the name, domain and path that set it.
func checkLogoutClears(t *testing.T, rec *httptest.ResponseRecorder, set map[string]*http.Cookie) {
	t.Helper()
	cleared := setCookies(rec)
	if len(rec.Result().Cookies()) != 3 {
		t.Errorf("cookies %v, want a clear each for %s, %s and %s", rec.Header()["Set-Cookie"], signatureCookie, sessionCookie, legacySignatureCookie)
	}
	for _, name := range []string{signatureCookie, sessionCookie, legacySignatureCookie} {
		dropped := cleared[name]
		if dropped == nil {
			t.Errorf("no clear for %s in %v", name, rec.Header()["Set-Cookie"])
			continue
		}
		if dropped.MaxAge >= 0 || dropped.Value != "" {
			t.Errorf("%s clear %+v does not drop the cookie", name, dropped)
		}
		want := set[signatureCookie]
		if name == sessionCookie {
			want = set[sessionCookie]
		}
		if dropped.Domain != want.Domain || dropped.Path != want.Path || dropped.Secure != want.Secure || dropped.HttpOnly != want.HttpOnly || dropped.SameSite != want.SameSite {
			t.Errorf("%s clear %+v does not match what set it, %+v", name, dropped, want)
		}
	}
}

// With the database down, logging out still clears the browser's cookies,
// and the row waits for the prune.
func TestLogoutWithTheDatabaseDown(t *testing.T) {
	down := testUserStateDB(t)
	spare := openUserStateClient(t)
	logged := captureAdminLog(t)
	user := sessionReader(t, spare, "logoutdown")
	login := siteLogin(t, "", user, "refresh-logoutdown")
	set := setCookies(login)
	session := sessionCookieWant(t, login)
	down.Close()

	rec := siteLogout(t, set[signatureCookie], session)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Errorf("status %d to %q, want a redirect home", rec.Code, rec.Header().Get("Location"))
	}
	checkLogoutClears(t, rec, set)
	if !strings.Contains(logged.String(), "DeletePatreonSession") {
		t.Errorf("log %q does not name the failure", logged.String())
	}
	rows := sessionRowsOf(t, spare, userstate.HashEmail(user.Email))
	if len(rows) != 1 {
		t.Errorf("rows %+v, want the one the prune will reclaim", rows)
	}
}

// A browser with no session, or a site with no database, is logged out all
// the same.
func TestLogoutWithoutASession(t *testing.T) {
	captureAdminLog(t)
	saved := UserStateDB
	t.Cleanup(func() { UserStateDB = saved })
	UserStateDB = nil

	set := setCookies(siteLogin(t, "", sessionReader(t, nil, "nosession"), ""))
	set[sessionCookie] = sessionCookieFor(siteRequest("/"), "an-id", 60)

	rec := siteLogout(t, set[signatureCookie], &http.Cookie{Name: sessionCookie, Value: "an-id-with-no-database"})
	checkLogoutClears(t, rec, set)
	rec = siteLogout(t, set[signatureCookie])
	checkLogoutClears(t, rec, set)
}

// The prune job deletes the sessions past their cap and keeps the rest.
func TestPrunePatreonSessionsKeepsLiveSessions(t *testing.T) {
	db := testUserStateDB(t)
	setTestJobs(t)
	expired := sessionReader(t, db, "expired")
	live := sessionReader(t, db, "live")
	_, err := db.DB().ExecContext(t.Context(), `
		INSERT INTO patreon_sessions (session_id, email_hash, refresh_token, expires_at)
		VALUES ('expired-session-id', $1, 'refresh-expired', now() - interval '1 hour')`,
		userstate.HashEmail(expired.Email))
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.CreatePatreonSession(t.Context(), userstate.HashEmail(live.Email), "refresh-live", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	prunePatreonSessions()

	expiredRows := sessionRowsOf(t, db, userstate.HashEmail(expired.Email))
	if len(expiredRows) != 0 {
		t.Errorf("expired session survived: %+v", expiredRows)
	}
	liveRows := sessionRowsOf(t, db, userstate.HashEmail(live.Email))
	if len(liveRows) != 1 {
		t.Errorf("live session pruned: %+v", liveRows)
	}
	row := jobRow(t, jobPatreonSessions)
	if !regexp.MustCompile(`^[1-9][0-9]* pruned$`).MatchString(row.Result) || row.Problem != "" {
		t.Errorf("job reported %q, problem %q, want a count of at least one", row.Result, row.Problem)
	}
}

// Without a database the prune job has nothing to do.
func TestPrunePatreonSessionsWithoutADatabase(t *testing.T) {
	setTestJobs(t)
	saved := UserStateDB
	t.Cleanup(func() { UserStateDB = saved })
	UserStateDB = nil

	prunePatreonSessions()
	for _, row := range backgroundJobs.Rows() {
		if row.Name == jobPatreonSessions {
			t.Errorf("job reported without a database: %+v", row)
		}
	}
}

// The prune is scheduled where the site has a database, beside the upload
// shares', and nowhere else.
func TestPatreonSessionsPruneIsScheduledWithADatabase(t *testing.T) {
	saved := UserStateDB
	t.Cleanup(func() { UserStateDB = saved })

	for _, tc := range []struct {
		name string
		db   *userstate.Client
		want bool
	}{
		{"with a database", &userstate.Client{}, true},
		{"without one", nil, false},
	} {
		setTestJobs(t)
		UserStateDB = tc.db
		testSite.scheduleCrons()

		scheduled := map[string]bool{}
		for _, row := range backgroundJobs.Rows() {
			scheduled[row.Name] = true
		}
		if scheduled[jobPatreonSessions] != tc.want || scheduled[jobUploadShares] != tc.want {
			t.Errorf("%s: patreon sessions %v, upload shares %v, want both %v", tc.name, scheduled[jobPatreonSessions], scheduled[jobUploadShares], tc.want)
		}
		if !scheduled[jobStaleness] {
			t.Errorf("%s: the schedule is missing the jobs every site runs", tc.name)
		}
	}
}
