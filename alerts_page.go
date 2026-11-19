package main

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/mtgban/mtgban-website/internal/alerts"
)

// AlertsPageVars is the alerts page payload.
type AlertsPageVars struct {
	SignedIn   bool
	Unverified bool
	Allowed    bool
	Allowance  int
	Alerts     []alerts.View
	InviteURL  string
	Error      string
	Form       *alerts.Options
	FormSide   alerts.Side
	// FormCardID is the card id the create or edit form is for; the JS
	// reads it off the form's data-card-id attribute.
	FormCardID string
	Editing    *alerts.View
	// Removing is the alert ?remove= named, whose Delete confirm the
	// page's JS opens on arrival.
	Removing int64
	// AllowedChannels is the ACL's delivery channels, comma-joined, read
	// off #alerts-page's data-alert-channels by the page's JS.
	AllowedChannels string
	// UnsubscribeURL is this user's one-click email unsubscribe link,
	// empty when not signed in.
	UnsubscribeURL string
	// Cards is each alert's card by its id, for the rows' hover image.
	Cards cardMetadata
	// Optimize is what the Optimize button posts, a row a card and grade.
	Optimize []alerts.OptimizeRow
	// OptimizeBuylist is the side Upload opens on, most alerts' side.
	OptimizeBuylist bool
}

// alertChannelList is alertChannels comma-joined, as the pages hand it to
// js/alerts.js in data-alert-channels.
func alertChannelList(v url.Values) string {
	chans := alertChannels(v)
	names := make([]string, len(chans))
	for i, kind := range chans {
		names[i] = string(kind)
	}
	return strings.Join(names, ",")
}

// Alerts renders the list, or the create form with ?card=, or the edit
// form with ?edit=; ?remove= lists them and asks to delete that one.
// enforceSigning has already let the reader in; what they may do follows
// the ACL values their signature carries.
func (s *site) Alerts(w http.ResponseWriter, r *http.Request) {
	sig := verifiedSignature(r)
	pageVars := genPageNav(s, r, "Alerts", sig)
	vars := &AlertsPageVars{InviteURL: Config().Discord.InviteURL}
	pageVars.AlertsPage = vars
	defer render(w, "alerts.html", pageVars)

	c, status, _ := alertsIdentity(r)
	if status != http.StatusOK {
		vars.Unverified = status == http.StatusForbidden
		return
	}
	vars.SignedIn = true
	if v := alerts.DeepLink(r.FormValue("edit"), r.FormValue("card"), r.FormValue("remove")); v != "" && isPageView(r) {
		observe(r, "alerts.deep_link", v)
	}
	api := s.alerts.API()
	vars.Allowance = alertAllowance(c.Values)
	vars.Allowed = vars.Allowance > 0
	vars.AllowedChannels = alertChannelList(c.Values)
	vars.UnsubscribeURL = alertUnsubscribeURL(externalURL(r), c.UserHash)
	store := api.Store()
	if store == nil {
		return
	}
	ctx := r.Context()

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
	remove := r.FormValue("remove")
	vars.Removing = alerts.Removing(views, remove)
	if remove != "" && vars.Removing == 0 {
		vars.Error = "That alert no longer exists."
	}
	b := s.backend()
	p := s.prices()
	vars.Cards = cardMetadata{}
	for _, view := range views {
		vars.Cards[view.CardID] = uuid2card(b, p, view.CardID, false, nil)
	}
	vars.Optimize, vars.OptimizeBuylist = alerts.OptimizeRows(liveAlerts(views, vars.Cards))
}

// liveAlerts are the views whose card the datastore still has, the ones
// Optimize sends.
func liveAlerts(views []alerts.View, cards cardMetadata) []alerts.View {
	var live []alerts.View
	for _, view := range views {
		if cards[view.CardID].UUID != "" {
			live = append(live, view)
		}
	}
	return live
}
