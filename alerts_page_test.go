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
