package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mtgban/mtgban-website/internal/invites"
	"github.com/mtgban/mtgban-website/userstate"
)

// InvitesAdminView is the admin's Invites tab: the mint form's choices and
// the table of invites (docs/adr/0011-invite-links.md).
type InvitesAdminView struct {
	// Off says why the tab cannot mint, when it cannot.
	Off      string
	Failed   bool
	Tiers    []string
	Features []invites.Feature
	// TierValues is each allowed tier's pages and options, for the form's
	// script to start the features on.
	TierValues     map[string]map[string]map[string]string
	OpenForChoices []inviteChoice
	MaxUses        int
	MaxAccessDays  int
	DefaultAccess  int
	MaxNote        int
	Rows           []InviteAdminRow
}

// inviteChoice is one of the Open for menu's lengths, in hours.
type inviteChoice struct {
	Label    string
	Hours    int
	Selected bool
}

// InviteAdminRow is one invite as the tab shows it.
type InviteAdminRow struct {
	userstate.Invite
	URL            string
	State          string
	Features       []string
	LastAccessEnds time.Time
	Redemptions    []userstate.Redemption
}

const (
	invitesOffText = "Invites need the userstate database, which this site has none of."
	inviteRowLimit = 200
)

// inviteAdminStore is what the tab mints, lists and revokes through.
type inviteAdminStore interface {
	CreateInvite(ctx context.Context, inv userstate.Invite) (userstate.Invite, error)
	Invites(ctx context.Context, limit int) ([]userstate.Invite, error)
	InviteRedemptions(ctx context.Context, codes []string) (map[string][]userstate.Redemption, error)
	RevokeInvite(ctx context.Context, code, by string) error
}

// inviteAdminStoreOf is the site's store, or a nil interface without one.
func inviteAdminStoreOf() inviteAdminStore {
	if UserStateDB == nil {
		return nil
	}
	return UserStateDB
}

// adminInviteActions mints or revokes the invite a POST names, and reports
// whether it answered with a redirect back to the tab.
func (s *site) adminInviteActions(w http.ResponseWriter, r *http.Request, store inviteAdminStore) bool {
	action := r.PostFormValue("inviteAction")
	if action != "mint" && action != "revoke" {
		return false
	}
	v := url.Values{"page": {"invites"}}
	minter, named := inviteMinter(r)
	switch {
	case store == nil:
		v.Set("msg", invitesOffText)
	case !named:
		v.Set("msg", "An invite needs an admin signed in with Patreon, so it can say who made it")
	case action == "mint":
		v.Set("msg", mintInvite(r, store, minter))
	default:
		code := invites.Normalize(r.PostFormValue("inviteCode"))
		err := store.RevokeInvite(r.Context(), code, minter)
		switch {
		case errors.Is(err, userstate.ErrInviteNotFound):
			v.Set("msg", "That invite was already revoked")
		case err != nil:
			log.Println("invites: revoke:", err)
			v.Set("msg", "Revoking failed: "+err.Error())
		default:
			adminLog("Invite %s… revoked by %s", codePrefix(code), minter)
			v.Set("msg", "Invite revoked")
		}
	}
	localRedirect(w, r, r.URL.Path, v)
	return true
}

// inviteMinter is who is minting: the admin's email off the verified
// signature, or "dev" on a local run that checks no signatures.
func inviteMinter(r *http.Request) (string, bool) {
	email := GetParamFromSig(verifiedSignature(r), "UserEmail")
	if email != "" {
		return email, true
	}
	if DevMode && !SigCheck {
		return "dev", true
	}
	return "", false
}

// mintInvite stores the invite the form asks for and says how it went.
// The code is not in the answer: the redirect carries it into the URL, and
// the table has a copy button for it.
func mintInvite(r *http.Request, store inviteAdminStore, minter string) string {
	rules := inviteRules()
	tier := r.PostFormValue("inviteTier")
	spec := invites.Spec{
		Tier:       tier,
		Overrides:  rules.Overrides(tier, invitePosted(r, rules, tier)),
		MaxUses:    formInt(r, "inviteUses"),
		OpenFor:    time.Duration(formInt(r, "inviteOpenFor")) * time.Hour,
		AccessDays: formInt(r, "inviteAccess"),
		Note:       strings.TrimSpace(r.PostFormValue("inviteNote")),
	}
	err := rules.Check(spec)
	if err != nil {
		return "Not minted: " + err.Error()
	}
	where := inviteWhere(r)
	inv := userstate.Invite{
		Game:        string(Config().Game),
		Tier:        spec.Tier,
		Overrides:   spec.Overrides,
		MaxUses:     spec.MaxUses,
		AccessDays:  spec.AccessDays,
		OpenUntil:   time.Now().Add(spec.OpenFor),
		Note:        spec.Note,
		CreatedBy:   minter,
		CreatedIP:   where.IP,
		CreatedUA:   where.UA,
		CreatedSite: where.Site,
	}
	// A taken code is drawn again; three in a row is something else.
	for range 3 {
		inv.Code, err = invites.NewCode()
		if err != nil {
			break
		}
		_, err = store.CreateInvite(r.Context(), inv)
		if !errors.Is(err, userstate.ErrInviteCodeTaken) {
			break
		}
	}
	if err != nil {
		log.Println("invites: mint:", err)
		return "Minting failed: " + err.Error()
	}
	adminLog("Invite %s… minted by %s: %s, %d uses", codePrefix(inv.Code), minter, inv.Tier, inv.MaxUses)
	return "Invite minted; copy its link from the table"
}

// invitePosted is the features the form posted: every page the tier opens
// or the form ticked, with the options set on it. A ticked page no invite
// may open is kept, so Check refuses it rather than dropping it.
func invitePosted(r *http.Request, rules invites.Rules, tier string) map[string]map[string]string {
	ticked := r.PostForm["invitePage"]
	base := rules.Table[tier]
	posted := map[string]map[string]string{}
	for _, feature := range rules.Features() {
		_, opened := base[feature.Page]
		if !opened && !slices.Contains(ticked, feature.Page) {
			continue
		}
		options := map[string]string{}
		for _, key := range feature.Options {
			options[key] = strings.TrimSpace(r.PostFormValue("inviteOption." + feature.Page + "." + key))
		}
		posted[feature.Page] = options
	}
	for _, page := range ticked {
		_, found := posted[page]
		if !found {
			posted[page] = map[string]string{}
		}
	}
	return posted
}

// formInt is a form field as a number, 0 when it is not one.
func formInt(r *http.Request, name string) int {
	n, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue(name)))
	if err != nil {
		return 0
	}
	return n
}

// loadInvitesView fills the tab: the form's choices, and the newest
// invites of every site with their acceptances.
func loadInvitesView(r *http.Request, store inviteAdminStore) *InvitesAdminView {
	rules := inviteRules()
	view := &InvitesAdminView{
		Tiers:          rules.AllowedTiers(),
		Features:       rules.Features(),
		TierValues:     map[string]map[string]map[string]string{},
		OpenForChoices: inviteOpenForChoices(),
		MaxUses:        invites.MaxUses,
		MaxAccessDays:  invites.MaxAccessDays,
		DefaultAccess:  invites.DefaultAccessDays,
		MaxNote:        invites.MaxNote,
	}
	for _, tier := range view.Tiers {
		view.TierValues[tier] = rules.Table[tier]
	}
	if store == nil {
		view.Off = invitesOffText
		return view
	}
	list, err := store.Invites(r.Context(), inviteRowLimit)
	if err != nil {
		log.Println("invites: list:", err)
		view.Failed = true
		return view
	}
	codes := make([]string, len(list))
	for i, inv := range list {
		codes[i] = inv.Code
	}
	redemptions, err := store.InviteRedemptions(r.Context(), codes)
	if err != nil {
		log.Println("invites: redemptions:", err)
		view.Failed = true
	}
	now := time.Now()
	for _, inv := range list {
		life := inviteLife(inv)
		view.Rows = append(view.Rows, InviteAdminRow{
			Invite:         inv,
			URL:            absoluteURL(r, "/invite/"+inv.Code),
			State:          life.State(now, view.Tiers),
			Features:       inviteFeatureLines(inv.Overrides),
			LastAccessEnds: life.LastAccessEnds(),
			Redemptions:    redemptions[inv.Code],
		})
	}
	return view
}

// inviteOpenForChoices are the lengths the Open for menu offers, the
// default selected.
func inviteOpenForChoices() []inviteChoice {
	choices := []inviteChoice{
		{Label: "One hour", Hours: 1},
		{Label: "One day", Hours: 24},
		{Label: "Three days", Hours: 3 * 24},
		{Label: "One week", Hours: 7 * 24},
		{Label: "Two weeks", Hours: 14 * 24},
		{Label: "30 days", Hours: 30 * 24},
	}
	for i := range choices {
		choices[i].Selected = time.Duration(choices[i].Hours)*time.Hour == invites.DefaultOpenFor
	}
	return choices
}
