package main

import (
	"os"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/internal/tmplparse"
)

func renderPrivacy(t *testing.T, mobile bool) string {
	t.Helper()
	baseName, files := renderTemplateFiles("privacy.html", mobile)
	tmpl, err := tmplparse.ParseFiles(baseName, files, funcMap)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, baseName, PageVars{Title: "Privacy", Hash: "test", UserNav: &NavElem{}}); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// The policy names what the site records: request logs and where they go,
// visits and searches against a hash, feature counts, synced state, third hosts.
func TestPrivacyPolicyDescribesWhatIsRecorded(t *testing.T) {
	for _, mobile := range []bool{false, true} {
		page := renderPrivacy(t, mobile)
		for _, want := range []string{
			"Each page you visit is also recorded with your device type and, when you are signed in, your membership tier and a hashed form of your email",
			"with the time and your account email when you are signed in, or your IP address when you are not",
			"A copy of each entry is posted to a private staff channel on Discord.",
			"and with Discord, which hosts the private staff channel our usage logs are posted to",
			"When a search you type while signed in finds results, it may also be recorded, with its text, against the same hash",
			"<strong>Feature usage.</strong> We count how often site features and settings are used. These counts carry your membership tier and device type but no account identifier.",
			"When one of our scripts fails, it reports the script's name, the line, the kind of error and the site version",
			"On one page load in ten it also reports, in broad ranges, how long the page took to load.",
			"your synced preferences, favorites, recent searches and backpack contents are also stored on our servers",
			"<code>mtgban_metrics_snap</code>, a record of the day your settings were last counted, and <code>mtgban_metrics_queue</code>, a short queue of counts that could not be sent",
			"Google Fonts, jsDelivr and unpkg",
			"Those hosts receive your IP address",
			"Do Not Track or Global Privacy Control signal, it sends us no feature-usage counts and keeps neither of the two local storage entries above",
			"Counts our servers make from the requests themselves continue",
		} {
			if !strings.Contains(page, want) {
				t.Errorf("mobile=%v: privacy policy lacks %q", mobile, want)
			}
		}
	}
}

// The retention the page states is the retention the jobs apply.
func TestPrivacyPolicyRetentionMatchesTheJobs(t *testing.T) {
	if minuteRetentionDays != 14 || errorRetentionDays != 90 || popularRetentionDays != 90 || eventsRetentionDays != 400 {
		t.Fatal("a retention changed: update templates/privacy.html and this test")
	}
	page := renderPrivacy(t, false)
	for _, want := range []string{
		"by the minute for two weeks and as daily totals after that, and delete script error reports after 90 days",
		"after about thirteen months",
		"search records are deleted after 90 days",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("privacy policy lacks %q", want)
		}
	}
}

// The two local storage keys the page names are the ones the script uses.
func TestPrivacyPolicyNamesTheScriptsStorageKeys(t *testing.T) {
	src, err := os.ReadFile("js/metrics.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"'mtgban_metrics_queue'", "'mtgban_metrics_snap'"} {
		if !strings.Contains(string(src), key) {
			t.Errorf("js/metrics.js no longer uses %s: update templates/privacy.html", key)
		}
	}
}

// The copy is typed with plain hyphens.
func TestPrivacyPolicyHasNoEmdash(t *testing.T) {
	src, err := os.ReadFile("templates/privacy.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{string(rune(0x2014)), "&mdash;", "&#8212;", "&#x2014;"} {
		if strings.Contains(string(src), bad) {
			t.Errorf("templates/privacy.html contains %q", bad)
		}
	}
}
