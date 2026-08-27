package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/internal/dsreload"
	"github.com/mtgban/mtgban-website/internal/tmplparse"
)

// TestAdminPageReportsTheReload renders the admin page in each state the
// datastore reload can be in. The page reads the reload through a template
// function rather than a page variable, so a call spelled wrong compiles
// fine and only fails when the page is drawn - which is while a reload is
// running, the moment the page is most wanted.
func TestAdminPageReportsTheReload(t *testing.T) {
	for _, tt := range []struct {
		desc       string
		work       func() error
		hold       bool
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
			datastoreReloads = dsreload.Tracker{}
			release := make(chan struct{})
			started := make(chan struct{})
			if tt.hold {
				datastoreReloads.Start("api", "allprintings5.json.xz", func() error {
					close(started)
					<-release
					return nil
				})
				<-started
			} else {
				datastoreReloads.Start("api", "allprintings5.json.xz", tt.work)
				waitForReload(t)
			}

			page := renderAdmin(t)

			if tt.hold {
				close(release)
				waitForReload(t)
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

var errTest = errTestType("bucket said no")

type errTestType string

func (e errTestType) Error() string { return string(e) }

func renderAdmin(t *testing.T) string {
	t.Helper()
	baseName, files := renderTemplateFiles("admin.html", false)
	tmpl, err := tmplparse.ParseFiles(baseName, files, funcMap)
	if err != nil {
		t.Fatalf("parsing admin.html: %v", err)
	}
	var buf bytes.Buffer
	vars := PageVars{Title: "Admin", BetaNav: &NavElem{}, LastUpdate: time.Now()}
	if err := tmpl.ExecuteTemplate(&buf, baseName, vars); err != nil {
		t.Fatalf("rendering admin.html: %v", err)
	}
	return buf.String()
}

func waitForReload(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !datastoreReloads.Status().Running {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the reload never finished")
}
