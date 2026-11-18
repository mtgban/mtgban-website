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
	// AllowedChannels is the ACL's delivery channels, comma-joined, read
	// off #alerts-page's data-alert-channels by the page's JS.
	AllowedChannels string
	// UnsubscribeURL is this user's one-click email unsubscribe link,
	// empty when not signed in.
	UnsubscribeURL string
	// Cards is each alert's card by its id, for the rows' hover image.
	Cards cardMetadata
	// Optimize is what the Optimize button posts, a row a card and grade.
	Optimize []alertOptimizeRow
	// OptimizeBuylist is the side Upload opens on, most alerts' side.
	OptimizeBuylist bool
}

// alertOptimizeRow is one alert as a row of Upload: its card, the
// copies it notes or 1, its grade, and the price it waits for as the
// row's loaded price.
type alertOptimizeRow struct {
	CardID    string
	Quantity  int
	Condition string
	Price     string
}

// alertOptimizeRows are the alerts whose card the datastore still has, as
// the Optimize button's rows, and whether Upload opens on buylist: the side
// of most of them, buylist on a tie. Upload merges rows of one card and
// grade, so each gets one row, from an alert on the opening side if any.
func alertOptimizeRows(views []alerts.View, cards cardMetadata) ([]alertOptimizeRow, bool) {
	var live []alerts.View
	buylist := 0
	for _, view := range views {
		if cards[view.CardID].UUID == "" {
			continue
		}
		live = append(live, view)
		if view.Side == alerts.SideBuylist {
			buylist++
		}
	}
	side := alerts.SideRetail
	if buylist*2 >= len(live) {
		side = alerts.SideBuylist
	}

	var rows []alertOptimizeRow
	at := map[[2]string]int{}
	for _, view := range live {
		row := alertOptimizeRow{
			CardID:    view.CardID,
			Quantity:  max(view.Quantity, 1),
			Condition: view.Condition,
			Price:     strconv.FormatFloat(view.Target(), 'f', 2, 64),
		}
		key := [2]string{view.CardID, view.Condition}
		i, seen := at[key]
		if !seen {
			at[key] = len(rows)
			rows = append(rows, row)
		} else if view.Side == side {
			rows[i] = row
		}
	}
	return rows, side == alerts.SideBuylist
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

// alertsDeepLink names what the alerts page was opened on, "" for the list.
func alertsDeepLink(edit, card string) string {
	switch {
	case edit != "":
		return "edit"
	case card != "":
		return "card"
	}
	return ""
}

// Alerts renders the list, or the create form with ?card=, or the edit
// form with ?edit=. enforceSigning has already let the reader in; what
// they may do follows the ACL values their signature carries.
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
	if v := alertsDeepLink(r.FormValue("edit"), r.FormValue("card")); v != "" && isPageView(r) {
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
	b := s.backend()
	p := s.prices()
	vars.Cards = cardMetadata{}
	for _, view := range views {
		vars.Cards[view.CardID] = uuid2card(b, p, view.CardID, false, nil)
	}
	vars.Optimize, vars.OptimizeBuylist = alertOptimizeRows(views, vars.Cards)
}
