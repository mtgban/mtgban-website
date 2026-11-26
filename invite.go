package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/mtgban/mtgban-website/internal/invites"
	"github.com/mtgban/mtgban-website/ratelimit"
	"github.com/mtgban/mtgban-website/userstate"
)

// InviteVars is the invite page's own: what the invite grants, and the
// form that accepts it, or the line saying it cannot be.
type InviteVars struct {
	InviteCode       string
	InviteNonce      string
	InviteTier       string
	InviteFeatures   []string
	InviteAccessDays int
	InviteSignedIn   bool
	// InviteNotice, when set, is all the page says.
	InviteNotice string
}

const (
	inviteClosedText = "This invite can no longer be accepted."
	inviteBusyText   = "Too many requests, try again in a moment."
	inviteErrorText  = "Something went wrong reading this invite."
)

// inviteLimiter throttles the invite page by client address, GET and POST
// alike: noSigning has no limiter of its own.
var inviteLimiter = ratelimit.NewLimiter(1, 10)

// inviteStore is what the invite page reads and spends.
type inviteStore interface {
	InviteByCode(ctx context.Context, code string) (userstate.Invite, error)
	RedeemInvite(ctx context.Context, in userstate.Redeem) (userstate.Redemption, error)
}

// inviteRules is what an invite may sign against the access table in
// force: no Admin, and no key naming who a signature belongs to.
func inviteRules() invites.Rules {
	pages := slices.DeleteFunc(slices.Clone(OrderNav), func(page string) bool {
		return page == "Admin"
	})
	options := slices.DeleteFunc(slices.Clone(OptionalFields), func(key string) bool {
		return slices.Contains(identityFields, key)
	})
	return invites.Rules{Table: ACL(), Pages: pages, Options: options, Open: "Any"}
}

// Invite serves /invite/<code>: GET shows what the invite grants, and its
// POST accepts it (docs/adr/0011-invite-links.md).
func (s *site) Invite(w http.ResponseWriter, r *http.Request) {
	// A nil *Client must reach the handler as a nil interface.
	var store inviteStore
	if UserStateDB != nil {
		store = UserStateDB
	}
	s.invite(w, r, store)
}

func (s *site) invite(w http.ResponseWriter, r *http.Request, store inviteStore) {
	if store == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if crossSitePost(r) {
		http.Error(w, "cross-site form refused", http.StatusForbidden)
		return
	}
	if !inviteLimiter.Allow(inviteClientKey(r)) {
		observe(r, "ratelimit.reject", "invite")
		s.renderInvite(w, r, http.StatusTooManyRequests, InviteVars{InviteNotice: inviteBusyText})
		return
	}
	code := invites.Normalize(strings.TrimPrefix(r.URL.Path, "/invite/"))
	if !invites.ValidCode(code) {
		observe(r, "invite.closed", "")
		s.renderInvite(w, r, http.StatusNotFound, InviteVars{InviteNotice: inviteClosedText})
		return
	}
	if r.Method == http.MethodPost {
		s.acceptInvite(w, r, store, code)
		return
	}

	// Link scanners and unfurlers prefetch GETs, so a GET spends nothing.
	inv, err := store.InviteByCode(r.Context(), code)
	switch {
	case errors.Is(err, userstate.ErrInviteNotFound):
	case err != nil:
		log.Println("invite:", err)
		s.renderInvite(w, r, http.StatusInternalServerError, InviteVars{InviteNotice: inviteErrorText})
		return
	}
	if err != nil || inviteLife(inv).State(time.Now(), inviteRules().AllowedTiers()) != invites.StateOpen {
		observe(r, "invite.closed", "")
		s.renderInvite(w, r, http.StatusNotFound, InviteVars{InviteNotice: inviteClosedText})
		return
	}
	nonce, err := invites.NewNonce()
	if err != nil {
		log.Println("invite: nonce:", err)
		s.renderInvite(w, r, http.StatusInternalServerError, InviteVars{InviteNotice: inviteErrorText})
		return
	}
	observe(r, "invite.view", "")
	s.renderInvite(w, r, http.StatusOK, InviteVars{
		InviteCode:       code,
		InviteNonce:      nonce,
		InviteTier:       inv.Tier,
		InviteFeatures:   inviteFeatureLines(inv.Overrides),
		InviteAccessDays: inv.AccessDays,
		InviteSignedIn:   signedUserEmail(r) != "",
	})
}

// acceptInvite spends a use of the invite and signs the reader in with
// it, or, for a press its nonce already answered, signs them in again
// with that first acceptance's signature.
func (s *site) acceptInvite(w http.ResponseWriter, r *http.Request, store inviteStore, code string) {
	nonce := r.PostFormValue("nonce")
	if !invites.ValidNonce(nonce) {
		s.renderInvite(w, r, http.StatusBadRequest, InviteVars{InviteNotice: inviteClosedText})
		return
	}
	where := inviteWhere(r)
	red, err := store.RedeemInvite(r.Context(), userstate.Redeem{
		Code:     code,
		Nonce:    nonce,
		Tiers:    inviteRules().AllowedTiers(),
		IP:       where.IP,
		UA:       where.UA,
		Site:     where.Site,
		SignedIn: signedUserEmail(r) != "",
	})
	if errors.Is(err, userstate.ErrInviteClosed) {
		s.logRefusedInvite(r, store, code, where)
		observe(r, "invite.closed", "")
		s.renderInvite(w, r, http.StatusGone, InviteVars{InviteNotice: inviteClosedText})
		return
	}
	if err != nil {
		log.Println("invite: redeem:", err)
		s.renderInvite(w, r, http.StatusInternalServerError, InviteVars{InviteNotice: inviteErrorText})
		return
	}
	access := time.Until(red.ExpiresAt)
	if access <= 0 {
		s.renderInvite(w, r, http.StatusGone, InviteVars{InviteNotice: inviteClosedText})
		return
	}
	putSignatureInCookies(w, r, sign(red.Tier, nil, red.Overrides, access))
	if red.Repeat {
		observe(r, "invite.accept", "repeat")
	} else {
		observe(r, "invite.accept", "first")
		adminLog("Invite %s… accepted from %s on %s", codePrefix(code), where.IP, where.Site)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// logRefusedInvite tells the admins about a refused press on an invite
// that exists, which is how a forwarded single-use link shows up. A code
// that names nothing is not logged, so a stranger cannot fill the log.
func (s *site) logRefusedInvite(r *http.Request, store inviteStore, code string, where requestWhere) {
	_, err := store.InviteByCode(r.Context(), code)
	if err != nil {
		return
	}
	adminLog("Invite %s… refused from %s on %s", codePrefix(code), where.IP, where.Site)
}

// renderInvite renders the invite page with vars, at status.
func (s *site) renderInvite(w http.ResponseWriter, r *http.Request, status int, vars InviteVars) {
	pageVars := genPageNav(s, r, "Invite", verifiedSignature(r))
	// An expired cookie's notice must not replace this page's own.
	pageVars.ErrorMessage = ""
	pageVars.IsMobile = isMobileRequest(r)
	if pageVars.IsMobile {
		pageVars.Nav = filterNavForMobile(pageVars.Nav)
	}
	pageVars.Title = "Invite"
	pageVars.InviteVars = vars
	w.Header().Set("Cache-Control", "no-store")
	// The path is the invite's secret; keep it from the font and script hosts.
	w.Header().Set("Referrer-Policy", "no-referrer")
	render(&statusOnWrite{ResponseWriter: w, status: status}, "invite.html", pageVars)
}

// inviteClientKey is the address the invite limiter counts, an IPv6
// client by its /64 as the API limiter counts it.
func inviteClientKey(r *http.Request) string {
	ip, err := apiLimitAddress(r)
	if err != nil || ip == nil {
		return r.RemoteAddr
	}
	return ip.String()
}

// requestWhere is where a request came from, as an invite records it.
type requestWhere struct {
	IP   string
	UA   string
	Site string
}

// inviteWhere is the client's whole address, its user agent, and the site
// that answered: the instance name, or the host when there is none.
func inviteWhere(r *http.Request) requestWhere {
	where := requestWhere{UA: r.UserAgent(), Site: Config().InstanceName}
	ip, err := clientAddress(r)
	if err == nil && ip != nil {
		where.IP = ip.String()
	} else {
		where.IP = r.RemoteAddr
	}
	if where.Site == "" {
		where.Site = r.Host
	}
	return where
}

// inviteLife is what an invite's state is read from.
func inviteLife(inv userstate.Invite) invites.Life {
	return invites.Life{
		Tier:       inv.Tier,
		Uses:       inv.Uses,
		MaxUses:    inv.MaxUses,
		AccessDays: inv.AccessDays,
		OpenUntil:  inv.OpenUntil,
		RevokedAt:  inv.RevokedAt,
	}
}

// inviteFeatureLines names what overrides add to the tier, a line a page:
// the page, then the options it sets there.
func inviteFeatureLines(overrides map[string]map[string]string) []string {
	var lines []string
	for _, page := range OrderNav {
		options, found := overrides[page]
		if !found {
			continue
		}
		var set []string
		for key, val := range options {
			set = append(set, key+": "+val)
		}
		sort.Strings(set)
		line := page
		if len(set) > 0 {
			line += " (" + strings.Join(set, ", ") + ")"
		}
		lines = append(lines, line)
	}
	return lines
}

// codePrefix is as much of a code as a log line shows: enough to tell
// invites apart, too little to accept one with.
func codePrefix(code string) string {
	return code[:min(3, len(code))]
}

// adminLog writes a line to the Admin log, which also reaches the staff
// channel.
func adminLog(format string, args ...any) {
	logger := LogPages["Admin"]
	if logger == nil {
		log.Printf(format, args...)
		return
	}
	logger.Printf(format, args...)
}

// pruneInvites deletes the invites closed for more than 90 days.
func pruneInvites() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	n, err := UserStateDB.PruneInvites(ctx)
	if err != nil {
		log.Println("invites: prune:", err)
		backgroundJobs.Report(jobInvites, "", err.Error())
		return
	}
	backgroundJobs.Report(jobInvites, fmt.Sprintf("%d pruned", n), "")
}
