package main

import (
	"html/template"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/internal/alerts"
)

// Each status the API resumes offers Resume on the page, and the rest do not.
func TestAlertsPageOffersResumeAsTheAPIAllows(t *testing.T) {
	tmpl, err := template.New("").Funcs(funcMap).ParseFiles("templates/partials/alerts-body.html")
	if err != nil {
		t.Fatal(err)
	}
	for status, want := range map[alerts.Status]bool{
		alerts.StatusPaused:        true,
		alerts.StatusUndeliverable: true,
		alerts.StatusUnresolvable:  true,
		alerts.StatusOverAllowance: false,
	} {
		vars := PageVars{AlertsPage: &AlertsPageVars{
			SignedIn: true, Allowed: true, Allowance: 5,
			Alerts: []alerts.View{{Alert: alerts.Alert{ID: 1, CardID: "card-1", Status: status}}},
		}}
		var out strings.Builder
		err := tmpl.ExecuteTemplate(&out, "alerts-body", vars)
		if err != nil {
			t.Fatalf("%s: %v", status, err)
		}
		if got := strings.Contains(out.String(), `data-action="resume"`); got != want {
			t.Errorf("%s: Resume offered %v, want %v", status, got, want)
		}
	}
}

// The search page's modal carries the delivery channels itself; on the
// alerts page #alerts-page carries them, so the modal stays bare.
func TestAlertModalCarriesTheChannelsOffTheAlertsPage(t *testing.T) {
	tmpl, err := template.New("").Funcs(funcMap).ParseFiles("templates/partials/alert-modal.html")
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		vars PageVars
		want bool
	}{
		"search": {PageVars{SearchVars: SearchVars{AlertChannelList: "discord,email"}}, true},
		"alerts": {PageVars{AlertsPage: &AlertsPageVars{AllowedChannels: "discord,email"}}, false},
	} {
		var out strings.Builder
		err := tmpl.ExecuteTemplate(&out, "alert-modal", tc.vars)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := strings.Contains(out.String(), `id="alert-modal" role="dialog" aria-modal="true" aria-labelledby="alert-modal-title" data-alert-channels="discord,email"`)
		if got != tc.want {
			t.Errorf("%s: modal carries the channels %v, want %v", name, got, tc.want)
		}
	}
}
