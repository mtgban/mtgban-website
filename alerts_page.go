package main

import (
	"net/http"
	"strconv"

	"github.com/mtgban/mtgban-website/internal/alerts"
)

// AlertsPageVars is the alerts page payload.
type AlertsPageVars struct {
	SignedIn      bool
	Unverified    bool
	Allowed       bool
	Allowance     int
	Alerts        []alerts.View
	DiscordLinked bool
	InviteURL     string
	Error         string
	Form          *alerts.Options
	FormSide      alerts.Side
	// FormCardID is the card id the create or edit form is for; the JS
	// reads it off the form's data-card-id attribute.
	FormCardID string
	Editing    *alerts.View
}

// Alerts renders the list, or the create form with ?card=, or the edit
// form with ?edit=. enforceSigning has already let the reader in; what
// they may do follows the ACL values their signature carries.
func (s *site) Alerts(w http.ResponseWriter, r *http.Request) {
	sig := getSignatureFromCookies(r)
	pageVars := genPageNav(s, r, "Alerts", sig)
	pageVars.IsMobile = isMobileRequest(r)
	if pageVars.IsMobile {
		pageVars.Nav = filterNavForMobile(pageVars.Nav)
	}
	vars := &AlertsPageVars{InviteURL: Config().Discord.InviteURL}
	pageVars.AlertsPage = vars
	defer render(w, "alerts.html", pageVars)

	c, status, _ := alertsIdentity(r)
	if status != http.StatusOK {
		vars.Unverified = status == http.StatusForbidden
		return
	}
	vars.SignedIn = true
	api := s.alerts.API()
	vars.Allowance = alertAllowance(c.Values)
	vars.Allowed = vars.Allowance > 0
	store := api.Store()
	if store == nil {
		return
	}
	ctx := r.Context()
	contact, _, err := store.Contact(ctx, c.UserHash)
	if err == nil {
		vars.DiscordLinked = contact.DiscordUserID != ""
	}

	side := alerts.Side(r.FormValue("side"))
	if side == "" {
		side = alerts.SideBuylist
	}
	// A tier without an allowance gets the list, never a form.
	edit := r.FormValue("edit")
	if edit != "" && vars.Allowed {
		id, _ := strconv.ParseInt(edit, 10, 64)
		cur, found, err := store.Get(ctx, id, c.UserHash)
		if err != nil || !found {
			vars.Error = "That alert no longer exists."
			return
		}
		opts, status, msg := api.OptionsFor(ctx, c, cur.CardID, cur.Side, cur.Stores)
		if status != http.StatusOK {
			vars.Error = msg
			return
		}
		vars.Form, vars.FormSide, vars.Editing = &opts, cur.Side, &alerts.View{Alert: cur}
		vars.FormCardID = cur.CardID
		return
	}
	card := r.FormValue("card")
	if card != "" && vars.Allowed {
		opts, status, msg := api.OptionsFor(ctx, c, card, side, nil)
		if status != http.StatusOK {
			vars.Error = msg
			return
		}
		vars.Form, vars.FormSide = &opts, side
		vars.FormCardID = card
		return
	}
	views, err := api.ListFor(ctx, c)
	if err != nil {
		vars.Error = "Could not load your alerts."
		return
	}
	vars.Alerts = views
}
