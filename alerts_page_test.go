package main

import (
	"html/template"
	"net/http"
	"net/http/httptest"
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

// A noted quantity reads as held on a buylist alert and wanted on a retail
// one, under the card; an unset one adds nothing.
func TestAlertsPageNotesTheQuantity(t *testing.T) {
	tmpl, err := template.New("").Funcs(funcMap).ParseFiles("templates/partials/alerts-body.html")
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		alert alerts.Alert
		want  string
	}{
		"buylist": {alerts.Alert{Side: alerts.SideBuylist, Quantity: 4}, `<span class="alert-meta">you have 4</span>`},
		"retail":  {alerts.Alert{Side: alerts.SideRetail, Quantity: 2}, `<span class="alert-meta">you want 2</span>`},
		"unset":   {alerts.Alert{Side: alerts.SideBuylist}, ""},
	} {
		tc.alert.ID, tc.alert.CardID, tc.alert.Status = 1, "card-1", alerts.StatusActive
		vars := PageVars{AlertsPage: &AlertsPageVars{
			SignedIn: true, Allowed: true, Allowance: 5, Alerts: []alerts.View{{Alert: tc.alert}},
		}}
		var out strings.Builder
		err := tmpl.ExecuteTemplate(&out, "alerts-body", vars)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		html := out.String()
		if tc.want != "" && !strings.Contains(html, tc.want) {
			t.Errorf("%s: lacks %q", name, tc.want)
		}
		if n := strings.Count(html, `class="alert-meta"`); tc.want == "" && n != 1 {
			t.Errorf("%s: %d alert-meta spans, want the set line alone", name, n)
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
		"search": {PageVars{AlertChannelList: "discord,email"}, true},
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

// Delete all sits in the heading whenever there is something to delete,
// with or without an allowance, and the Pause/Resume button carries the
// class that keeps its width, not a position.
func TestAlertsPageOffersDeleteAllWithAlerts(t *testing.T) {
	tmpl, err := template.New("").Funcs(funcMap).ParseFiles("templates/partials/alerts-body.html")
	if err != nil {
		t.Fatal(err)
	}
	one := []alerts.View{{Alert: alerts.Alert{ID: 1, CardID: "card-1", Status: alerts.StatusActive}}}
	for name, tc := range map[string]struct {
		vars       AlertsPageVars
		wantButton bool
	}{
		"allowed with alerts":  {AlertsPageVars{SignedIn: true, Allowed: true, Allowance: 5, Alerts: one}, true},
		"no allowance, alerts": {AlertsPageVars{SignedIn: true, Allowed: false, Allowance: 0, Alerts: one}, true},
		"allowed, no alerts":   {AlertsPageVars{SignedIn: true, Allowed: true, Allowance: 5}, false},
		"signed out":           {AlertsPageVars{SignedIn: false}, false},
	} {
		var out strings.Builder
		if err := tmpl.ExecuteTemplate(&out, "alerts-body", PageVars{AlertsPage: &tc.vars}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := strings.Contains(out.String(), `data-action="delete-all"`); got != tc.wantButton {
			t.Errorf("%s: Delete all offered %v, want %v", name, got, tc.wantButton)
		}
		if tc.wantButton && !strings.Contains(out.String(), `class="settings-btn alert-btn-toggle" data-action="pause"`) {
			t.Errorf("%s: Pause lacks the alert-btn-toggle class:\n%s", name, out.String())
		}
	}
}

// An empty page shows the favorites-style flow: a mock result with the
// bell, an arrow, a mock alert row; a page with alerts shows none of it.
func TestAlertsPageEmptyStateShowsTheBellFlow(t *testing.T) {
	tmpl, err := template.New("").Funcs(funcMap).ParseFiles("templates/partials/alerts-body.html")
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		vars AlertsPageVars
		want bool
	}{
		"empty":        {AlertsPageVars{SignedIn: true, Allowed: true, Allowance: 5}, true},
		"with alerts":  {AlertsPageVars{SignedIn: true, Allowed: true, Allowance: 5, Alerts: []alerts.View{{Alert: alerts.Alert{ID: 1, CardID: "card-1", Status: alerts.StatusActive}}}}, false},
		"signed out":   {AlertsPageVars{}, false},
		"no allowance": {AlertsPageVars{SignedIn: true, Allowed: false, Allowance: 0}, false},
	} {
		var out strings.Builder
		if err := tmpl.ExecuteTemplate(&out, "alerts-body", PageVars{AlertsPage: &tc.vars}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, marker := range []string{`class="landing-empty-fav alerts-empty-flow"`, `class="landing-empty-star alerts-empty-bell"`, "Press the bell to set an alert", "Edit, pause or delete it here", `class="landing-empty-arrow"`} {
			if got := strings.Contains(out.String(), marker); got != tc.want {
				t.Errorf("%s: %q present %v, want %v", name, marker, got, tc.want)
			}
		}
		if name == "no allowance" && !strings.Contains(out.String(), `<p class="alerts-empty">No alerts.</p>`) {
			t.Errorf("%s: the plain empty line is missing:\n%s", name, out.String())
		}
	}
}

// A desktop row shows its card's image on hover, and a row whose card no
// longer resolves clears it; the mobile page has no hover image to fill.
func TestAlertsPageRowsCarryTheHoverImage(t *testing.T) {
	tmpl, err := template.New("").Funcs(funcMap).ParseFiles("templates/partials/alerts-body.html")
	if err != nil {
		t.Fatal(err)
	}
	vars := AlertsPageVars{
		SignedIn: true, Allowed: true, Allowance: 5,
		Alerts: []alerts.View{
			{Alert: alerts.Alert{ID: 1, CardID: "card-1", Status: alerts.StatusActive}},
			{Alert: alerts.Alert{ID: 2, CardID: "gone", Status: alerts.StatusUnresolvable}},
		},
		Cards: cardMetadata{"card-1": {UUID: "card-1", ImageURL: "https://img.example/card-1.jpg", SetCode: "SLD"}},
	}
	for _, mobile := range []bool{false, true} {
		var out strings.Builder
		if err := tmpl.ExecuteTemplate(&out, "alerts-body", PageVars{IsMobile: mobile, AlertsPage: &vars}); err != nil {
			t.Fatalf("mobile %v: %v", mobile, err)
		}
		page := out.String()
		if got := strings.Count(page, "onmouseover="); got != map[bool]int{false: 2, true: 0}[mobile] {
			t.Errorf("mobile %v: %d rows with a hover image", mobile, got)
		}
		if mobile {
			continue
		}
		if !strings.Contains(page, `https://img.example/card-1.jpg`) || !strings.Contains(page, `hw.setAttribute('data-set','SLD')`) {
			t.Errorf("the card's row lacks its image:\n%s", page)
		}
		if !strings.Contains(page, `onmouseover="window.setCardArtSource(document.getElementById('hoverImage'),'data:image`) {
			t.Errorf("the missing card's row does not clear the image:\n%s", page)
		}
	}
}

// ?remove= names one of the reader's alerts, whose id the page hands its
// JS to open the Delete confirm on.
func TestAlertsPageRemoveLink(t *testing.T) {
	views := []alerts.View{{Alert: alerts.Alert{ID: 3, CardID: "card-1", Status: alerts.StatusActive}}}
	tmpl, err := template.New("").Funcs(funcMap).ParseFiles("templates/partials/alerts-body.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		removing int64
		want     string
	}{{3, `data-open-remove="3"`}, {0, `data-open-remove=""`}} {
		vars := AlertsPageVars{SignedIn: true, Allowed: true, Allowance: 5, Alerts: views, Removing: c.removing}
		var out strings.Builder
		if err := tmpl.ExecuteTemplate(&out, "alerts-body", PageVars{AlertsPage: &vars}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), c.want) {
			t.Errorf("removing %d: page lacks %s", c.removing, c.want)
		}
	}
}

func TestAlertsPageCountsADeepLink(t *testing.T) {
	withSigMode(t, true, false)
	t.Run("page view", func(t *testing.T) {
		rows := withFeatureCounter(t)
		r := alertsRequest(http.MethodGet, "/alerts?card=abc", devSig("a@b.com", "Legacy"))
		r.Header.Set("Sec-Fetch-Dest", "document")
		testSite.Alerts(httptest.NewRecorder(), r)
		wantRow(t, rows.rows(), "", "alerts.deep_link", "card", 1)
	})
	t.Run("not a page view", func(t *testing.T) {
		rows := withFeatureCounter(t)
		r := alertsRequest(http.MethodGet, "/alerts?edit=12", devSig("a@b.com", "Legacy"))
		r.Header.Set("Sec-Fetch-Dest", "empty")
		testSite.Alerts(httptest.NewRecorder(), r)
		wantNoRow(t, rows.rows(), "alerts.deep_link")
	})
	t.Run("signed out", func(t *testing.T) {
		rows := withFeatureCounter(t)
		testSite.Alerts(httptest.NewRecorder(), alertsRequest(http.MethodGet, "/alerts?card=abc", ""))
		wantNoRow(t, rows.rows(), "alerts.deep_link")
	})
}

// An alert whose card the datastore no longer has stays out of Optimize.
func TestLiveAlerts(t *testing.T) {
	views := []alerts.View{
		{Alert: alerts.Alert{ID: 1, CardID: "a"}},
		{Alert: alerts.Alert{ID: 2, CardID: "gone"}},
		{Alert: alerts.Alert{ID: 3, CardID: "b"}},
	}
	live := liveAlerts(views, cardMetadata{"a": {UUID: "a"}, "b": {UUID: "b"}})
	if len(live) != 2 || live[0].ID != 1 || live[1].ID != 3 {
		t.Errorf("live = %+v, want alerts 1 and 3", live)
	}
}

// The Optimize button posts each row with its grade and price, and shows
// only to a reader who can reach Upload and has a row to send.
func TestAlertsPageOffersOptimize(t *testing.T) {
	tmpl, err := template.New("").Funcs(funcMap).ParseFiles("templates/partials/alerts-body.html")
	if err != nil {
		t.Fatal(err)
	}
	one := []alerts.View{{Alert: alerts.Alert{ID: 1, CardID: "card-1", Status: alerts.StatusActive}}}
	rows := []alerts.OptimizeRow{{CardID: "card-1", Quantity: 4, Condition: "SP", Price: "12.00"}}
	for name, tc := range map[string]struct {
		canUpload bool
		rows      []alerts.OptimizeRow
		want      bool
	}{
		"can upload":      {true, rows, true},
		"cannot upload":   {false, rows, false},
		"no card to send": {true, nil, false},
	} {
		vars := AlertsPageVars{SignedIn: true, Allowed: true, Allowance: 5, Alerts: one, Optimize: tc.rows, OptimizeBuylist: true}
		var out strings.Builder
		err := tmpl.ExecuteTemplate(&out, "alerts-body", PageVars{CanUpload: tc.canUpload, AlertsPage: &vars})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		page := out.String()
		if got := strings.Contains(page, `action="/upload?from=alerts"`); got != tc.want {
			t.Errorf("%s: Optimize offered %v, want %v", name, got, tc.want)
		}
		if !tc.want {
			continue
		}
		for _, field := range []string{
			`name="mode" value="true"`, `name="hashes" value="card-1"`, `name="hashesQtys" value="4"`,
			`name="hashesCond" value="SP"`, `name="hashesPrice" value="12.00"`,
		} {
			if !strings.Contains(page, field) {
				t.Errorf("%s: the form lacks %s:\n%s", name, field, page)
			}
		}
	}
}
