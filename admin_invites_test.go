package main

import (
	"context"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/internal/pledge"
	"github.com/mtgban/mtgban-website/userstate"
)

const inviteAdminTestACL = `{
	"Any": {"Search": {}},
	"Pioneer": {"Search": {"SearchDownloadCSV": "false"}},
	"Legacy": {"Search": {"SearchDownloadCSV": "true"}, "Newspaper": {"NewsLarge": "true"}},
	"Root": {"Search": {}, "Admin": {}}
}`

// fakeInviteAdminStore records what the tab mints and revokes.
type fakeInviteAdminStore struct {
	created []userstate.Invite
	taken   int
	revoked []string
	rows    []userstate.Invite
	reds    map[string][]userstate.Redemption
}

func (f *fakeInviteAdminStore) CreateInvite(_ context.Context, inv userstate.Invite) (userstate.Invite, error) {
	if f.taken > 0 {
		f.taken--
		return userstate.Invite{}, userstate.ErrInviteCodeTaken
	}
	f.created = append(f.created, inv)
	return inv, nil
}

func (f *fakeInviteAdminStore) Invites(context.Context, int) ([]userstate.Invite, error) {
	return f.rows, nil
}

func (f *fakeInviteAdminStore) InviteRedemptions(context.Context, []string) (map[string][]userstate.Redemption, error) {
	return f.reds, nil
}

func (f *fakeInviteAdminStore) RevokeInvite(_ context.Context, code, _ string) error {
	f.revoked = append(f.revoked, code)
	return nil
}

// adminPost is a same-origin POST to the Invites tab, by a signed-in admin
// when email is set.
func adminPost(form url.Values, email string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/admin?page=invites", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("User-Agent", "admin-browser")
	req.RemoteAddr = "198.51.100.9:4000"
	if email != "" {
		sig := sign("Root", &pledge.User{FullName: "Admin", Email: email, EmailVerified: true}, nil, time.Hour)
		req.AddCookie(&http.Cookie{Name: signatureCookie, Value: sig})
	}
	return req
}

func mintForm(tier string) url.Values {
	return url.Values{
		"inviteAction":                          {"mint"},
		"inviteTier":                            {tier},
		"inviteUses":                            {"3"},
		"inviteOpenFor":                         {"24"},
		"inviteAccess":                          {"5"},
		"inviteNote":                            {"for a tester"},
		"inviteOption.Search.SearchDownloadCSV": {"false"},
	}
}

func inviteAdminTestEnv(t *testing.T) {
	t.Helper()
	inviteTestEnv(t)
	withACL(t, inviteAdminTestACL)
}

// Minting stores only what the form adds to the tier, who minted it and
// from where, and the redirect back carries no code.
func TestAdminMintsAnInvite(t *testing.T) {
	inviteAdminTestEnv(t)
	s := newSite()
	store := &fakeInviteAdminStore{taken: 1}
	form := mintForm("Pioneer")
	form.Set("invitePage", "Newspaper")
	form.Set("inviteOption.Newspaper.NewsLarge", "true")

	rec := httptest.NewRecorder()
	if !s.adminInviteActions(rec, adminPost(form, "admin@example.com"), store) {
		t.Fatal("mint did not redirect")
	}
	if len(store.created) != 1 {
		t.Fatalf("created %d invites", len(store.created))
	}
	inv := store.created[0]
	want := map[string]map[string]string{"Newspaper": {"NewsLarge": "true"}}
	if !maps.EqualFunc(inv.Overrides, want, maps.Equal) {
		t.Errorf("overrides %v, want %v", inv.Overrides, want)
	}
	if inv.Tier != "Pioneer" || inv.MaxUses != 3 || inv.AccessDays != 5 || inv.Note != "for a tester" {
		t.Errorf("minted %+v", inv)
	}
	if d := time.Until(inv.OpenUntil); d < 23*time.Hour || d > 24*time.Hour {
		t.Errorf("open for %v, want a day", d)
	}
	if inv.CreatedBy != "admin@example.com" || inv.CreatedIP != "198.51.100.9" || inv.CreatedUA != "admin-browser" || inv.CreatedSite == "" {
		t.Errorf("minted by %q from %q %q on %q", inv.CreatedBy, inv.CreatedIP, inv.CreatedUA, inv.CreatedSite)
	}
	location := rec.Header().Get("Location")
	if !strings.Contains(location, "page=invites") || strings.Contains(location, inv.Code) {
		t.Errorf("redirect %q", location)
	}
}

func TestAdminMintRefuses(t *testing.T) {
	inviteAdminTestEnv(t)
	s := newSite()
	cases := map[string]struct {
		form  url.Values
		email string
	}{
		"admin tier":     {mintForm("Root"), "admin@example.com"},
		"open entry":     {mintForm("Any"), "admin@example.com"},
		"admin ticked":   {func() url.Values { f := mintForm("Pioneer"); f.Set("invitePage", "Admin"); return f }(), "admin@example.com"},
		"too many uses":  {func() url.Values { f := mintForm("Pioneer"); f.Set("inviteUses", "26"); return f }(), "admin@example.com"},
		"nameless admin": {mintForm("Pioneer"), ""},
	}
	for name, c := range cases {
		store := &fakeInviteAdminStore{}
		rec := httptest.NewRecorder()
		s.adminInviteActions(rec, adminPost(c.form, c.email), store)
		if len(store.created) != 0 {
			t.Errorf("%s: minted %+v", name, store.created)
		}
		if msg := mustQuery(t, rec).Get("msg"); msg == "" || strings.HasPrefix(msg, "Invite minted") {
			t.Errorf("%s: msg %q", name, msg)
		}
	}

	// An identity key posted as an option is no feature, so nothing sets it.
	store := &fakeInviteAdminStore{}
	form := mintForm("Pioneer")
	form.Set("inviteOption.Search.UserEmail", "someone@example.com")
	s.adminInviteActions(httptest.NewRecorder(), adminPost(form, "admin@example.com"), store)
	if len(store.created) != 1 || len(store.created[0].Overrides) != 0 {
		t.Errorf("identity option: %+v", store.created)
	}
}

func mustQuery(t *testing.T, rec *httptest.ResponseRecorder) url.Values {
	t.Helper()
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

func TestAdminRevokesAnInvite(t *testing.T) {
	inviteAdminTestEnv(t)
	s := newSite()
	store := &fakeInviteAdminStore{}
	form := url.Values{"inviteAction": {"revoke"}, "inviteCode": {"ABCDEFGH"}}
	if !s.adminInviteActions(httptest.NewRecorder(), adminPost(form, "admin@example.com"), store) {
		t.Fatal("revoke did not redirect")
	}
	if len(store.revoked) != 1 || store.revoked[0] != "abcdefgh" {
		t.Errorf("revoked %v", store.revoked)
	}
}

// The old tool minted from a GET's query; it is gone.
func TestAdminToolsNoLongerMintInviteLinks(t *testing.T) {
	inviteAdminTestEnv(t)
	s := newSite()
	pageVars := PageVars{}
	rec := httptest.NewRecorder()
	if s.adminTools(rec, httptest.NewRequest(http.MethodGet, "/admin?tool=invite&tier=Pioneer&duration=7", nil), s.prices(), &pageVars) {
		t.Fatalf("?tool=invite answered %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

// The tab renders on desktop and on a phone, with each invite's state,
// uses, and a link only for an open one.
func TestAdminInvitesTabRenders(t *testing.T) {
	inviteAdminTestEnv(t)
	now := time.Now()
	store := &fakeInviteAdminStore{
		rows: []userstate.Invite{
			{Code: "abcdefgh", Game: "magic", Tier: "Pioneer", MaxUses: 2, Uses: 1, AccessDays: 7, OpenUntil: now.Add(time.Hour), Note: "open one", CreatedBy: "admin@example.com", CreatedAt: now},
			{Code: "bcdefghj", Game: "magic", Tier: "Pioneer", MaxUses: 1, Uses: 0, AccessDays: 7, OpenUntil: now.Add(time.Hour), Note: "revoked one", RevokedAt: now, RevokedBy: "admin@example.com", CreatedAt: now},
		},
		reds: map[string][]userstate.Redemption{"abcdefgh": {{RedeemedAt: now, IP: "203.0.113.4", UA: "Visitor", Site: "magic-1"}}},
	}
	view := loadInvitesView(httptest.NewRequest(http.MethodGet, "/admin?page=invites", nil), store)
	if len(view.Rows) != 2 || view.Rows[0].State != "open" || view.Rows[1].State != "revoked" {
		t.Fatalf("rows %+v", view.Rows)
	}
	for _, ua := range []string{"desktop", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Mobile/15E148 Safari/604.1"} {
		req := httptest.NewRequest(http.MethodGet, "/admin?page=invites", nil)
		req.Header.Set("User-Agent", ua)
		pageVars := genPageNav(newSite(), req, "Admin", "")
		pageVars.Invites = view
		pageVars.Page = "invites"
		if pageVars.IsMobile != (ua != "desktop") {
			t.Fatalf("%s: IsMobile = %v", ua, pageVars.IsMobile)
		}
		rec := httptest.NewRecorder()
		render(rec, "admin.html", pageVars)
		body := rec.Body.String()
		for _, want := range []string{"Mint invite", "open one", "1 / 2", "203.0.113.4", "revoked one", "/invite/abcdefgh"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: no %q", ua, want)
			}
		}
		if !strings.Contains(body, `class="admin-invite-row admin-invite-closed"`) {
			t.Errorf("%s: the revoked row is not marked closed", ua)
		}
		if strings.Contains(body, "/invite/bcdefghj") {
			t.Errorf("%s: a revoked invite shows its link", ua)
		}
		if strings.Contains(body, "Create Invite Link") {
			t.Errorf("%s: the old tool is still on the page", ua)
		}
	}

	off := loadInvitesView(httptest.NewRequest(http.MethodGet, "/admin?page=invites", nil), nil)
	if off.Off == "" {
		t.Error("no store: the tab does not say so")
	}
}
