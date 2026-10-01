package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/internal/dsreload"
	"github.com/mtgban/mtgban-website/internal/tmplparse"
)

// TestAdminPageReportsTheReload renders the admin page in each state the
// datastore reload can be in. renderAdmin fills DatastoreReload by hand, the
// way Admin's own handler does from s.reloads.Status(), since this
// test drives the template directly rather than through the handler.
func TestAdminPageReportsTheReload(t *testing.T) {
	for _, tt := range []struct {
		desc       string
		work       func() error
		hold       bool
		queue      bool
		wantShown  []string
		wantAbsent []string
	}{
		{
			desc:       "a running reload says so and holds the action back",
			hold:       true,
			wantShown:  []string{"Datastore update in progress", "updating,", "Already running"},
			wantAbsent: []string{"?reboot=datastore\""},
		},
		{
			desc:       "a reload asked for meanwhile is said to follow it",
			hold:       true,
			queue:      true,
			wantShown:  []string{"Datastore update in progress", "Another reload is queued to follow it."},
			wantAbsent: []string{"?reboot=datastore\""},
		},
		{
			desc:       "a failed one says why",
			work:       func() error { return errTest },
			wantShown:  []string{"bucket said no"},
			wantAbsent: []string{"Datastore update in progress"},
		},
		{
			desc:       "a quiet one says neither",
			work:       func() error { return nil },
			wantAbsent: []string{"Datastore update in progress", "bucket said no"},
		},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			var reloads dsreload.Tracker
			release := make(chan struct{})
			started := make(chan struct{})
			if tt.hold {
				reloads.Start("api", "allprintings5.json.xz", func() error {
					close(started)
					<-release
					return nil
				})
				<-started
				if tt.queue {
					reloads.Start("api", "allprintings5.json.xz", func() error { return nil })
				}
			} else {
				reloads.Start("api", "allprintings5.json.xz", tt.work)
				waitForReload(t, &reloads)
			}

			page := renderAdmin(t, &reloads)

			if tt.hold {
				close(release)
				waitForReload(t, &reloads)
			}

			for _, want := range tt.wantShown {
				if !strings.Contains(page, want) {
					t.Errorf("the page does not contain %q", want)
				}
			}
			for _, absent := range tt.wantAbsent {
				if strings.Contains(page, absent) {
					t.Errorf("the page still contains %q", absent)
				}
			}
		})
	}
}

// The click that starts a reload is answered by a page that says it is
// running: the handler reads the tracker after the reboot action, not
// before. The load blocks on a server that answers only once released.
func TestAdminPageShowsTheReloadItStarted(t *testing.T) {
	withSigMode(t, true, false)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		http.NotFound(w, r)
	}))
	defer srv.Close()
	defer func(path string) { Config().DatastorePath = path }(Config().DatastorePath)
	Config().DatastorePath = srv.URL + "/allprintings5.json.xz"

	// A private site, not testSite: its reload tracker starts fresh rather
	// than carrying state another test left running.
	s := newSite()
	rec := httptest.NewRecorder()
	s.Admin(rec, httptest.NewRequest(http.MethodGet, "/admin?reboot=datastore", nil))
	close(release)
	waitForReload(t, &s.reloads)

	page := rec.Body.String()
	for _, want := range []string{"Datastore update in progress", "Already running"} {
		if !strings.Contains(page, want) {
			t.Errorf("the page that started the reload does not say %q", want)
		}
	}
	if strings.Contains(page, `href="?reboot=datastore"`) {
		t.Error("the page that started the reload still offers to start one")
	}
}

var errTest = errTestType("bucket said no")

type errTestType string

func (e errTestType) Error() string { return string(e) }

func renderAdmin(t *testing.T, reloads *dsreload.Tracker) string {
	t.Helper()
	baseName, files := renderTemplateFiles("admin.html", false)
	tmpl, err := tmplparse.ParseFiles(baseName, files, funcMap)
	if err != nil {
		t.Fatalf("parsing admin.html: %v", err)
	}
	var buf bytes.Buffer
	vars := PageVars{Title: "Admin", BetaNav: &NavElem{}, LastUpdate: time.Now(), AdminVars: AdminVars{DatastoreReload: reloads.Status()}}
	if err := tmpl.ExecuteTemplate(&buf, baseName, vars); err != nil {
		t.Fatalf("rendering admin.html: %v", err)
	}
	return buf.String()
}

func waitForReload(t *testing.T, reloads *dsreload.Tracker) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !reloads.Status().Running {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the reload never finished")
}
