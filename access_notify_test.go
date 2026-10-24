package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lib/pq"

	"github.com/mtgban/mtgban-website/internal/access"
	"github.com/mtgban/mtgban-website/userstate"
)

func TestSkipAccessNotification(t *testing.T) {
	notification := func(payload string) *pq.Notification {
		return &pq.Notification{Channel: grantsReloadChannel, Extra: payload}
	}
	for _, tt := range []struct {
		name         string
		n            *pq.Notification
		instanceName string
		skip         bool
	}{
		// A reconnect may have missed notifications, reload no matter what.
		{"reconnect", nil, "magic", false},
		{"own save", notification("magic"), "magic", true},
		{"peer save", notification("lorcana"), "magic", false},
		// Unnamed instances cannot be told apart, so never skip on them:
		// treating empty-equals-empty as "own" would drop peer saves.
		{"unnamed sender", notification(""), "magic", false},
		{"unnamed everywhere", notification(""), "", false},
	} {
		skip := skipAccessNotification(tt.n, tt.instanceName)
		if skip != tt.skip {
			t.Errorf("%s: skip = %v, want %v", tt.name, skip, tt.skip)
		}
	}
}

// A patreon_poke notification pokes the reader its payload names, whoever
// sent it, and is not a reload: the listener has nothing else to do with it.
func TestTakePoke(t *testing.T) {
	renewalConfig(t, renewalBlock, "client-id")
	savedName := Config().InstanceName
	t.Cleanup(func() { Config().InstanceName = savedName })
	Config().InstanceName = "magic"
	hash := userstate.HashEmail("reader@example.com")

	for _, tc := range []struct {
		name    string
		n       *pq.Notification
		taken   bool
		pokedBy string
	}{
		{"a poke", &pq.Notification{Channel: patreonPokeChannel, Extra: hash}, true, hash},
		// The payload is a hash, so the skip of a reload's own sender does not apply
		{"a poke whose payload is this instance's name", &pq.Notification{Channel: patreonPokeChannel, Extra: "magic"}, true, "magic"},
		{"a poke naming nobody", &pq.Notification{Channel: patreonPokeChannel}, true, ""},
		{"a reload carrying the same payload", &pq.Notification{Channel: grantsReloadChannel, Extra: hash}, false, ""},
		{"a reconnect", nil, false, ""},
	} {
		pokes := freshPokes(t)
		taken := takePoke(tc.n)
		if taken != tc.taken {
			t.Errorf("%s: taken %v, want %v", tc.name, taken, tc.taken)
		}
		want := 0
		if tc.pokedBy != "" {
			want = 1
		}
		if pokes.Len() != want || (want == 1 && !pokes.Poked(tc.pokedBy, time.Now(), pokeWindow())) {
			t.Errorf("%s: set %v, want %d entry for %q", tc.name, pokes.Len(), want, tc.pokedBy)
		}
	}
}

// accessFiles are the two files the site's Access reads and writes, held in
// memory so a test can change one behind its back as a peer's save would.
type accessFiles struct {
	mu    sync.Mutex
	files map[string]string
}

func (f *accessFiles) set(path, content string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[path] = content
}

func (f *accessFiles) get(path string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.files[path]
}

// fileWriter lands what it is given in the file when it is closed, as the
// bucket's writer does.
type fileWriter struct {
	files *accessFiles
	path  string
	buf   bytes.Buffer
}

func (w *fileWriter) Write(p []byte) (int, error) { return w.buf.Write(p) }

func (w *fileWriter) Close() error {
	w.files.set(w.path, w.buf.String())
	return nil
}

// loadAccessFiles serves Access from the two files for the test, loaded once
// the way the site loads at startup. The files are named "acl" and "grants";
// a file given as empty does not exist.
func loadAccessFiles(t *testing.T, table, grants string) *accessFiles {
	t.Helper()
	files := &accessFiles{files: map[string]string{"acl": table, "grants": grants}}
	installAccessFiles(t, files)
	err := Access.Load(context.Background(), access.Sources{TablePath: "acl", GrantsPath: "grants"})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// installAccessFiles serves files through Access for the test, loading
// nothing, and puts back the Access it found.
func installAccessFiles(t *testing.T, files *accessFiles) {
	t.Helper()
	saved := Access
	t.Cleanup(func() { Access = saved })
	Access = access.New(access.Hooks{
		Open: func(_ context.Context, path string) (io.ReadCloser, error) {
			content := files.get(path)
			if content == "" {
				return nil, os.ErrNotExist
			}
			return io.NopCloser(strings.NewReader(content)), nil
		},
		OpenWrite: func(_ context.Context, path string) (io.WriteCloser, error) {
			return &fileWriter{files: files, path: path}, nil
		},
	})
}

// grantFor is the grant file's entry for email.
func grantFor(email, tier string) string {
	return fmt.Sprintf(`{"email":%q,"name":"Name","category":"friend","tier":%q}`, email, tier)
}

// The access table is stamped when a reload brings a different one and not
// otherwise: the listener re-reads every value on a reconnect, and a stamp
// there would renew every active reader after every blip of the connection.
func TestReloadACLStampsOnlyAChangedTable(t *testing.T) {
	pokes := freshPokes(t)
	files := loadAccessFiles(t, `{"Legacy":{"Search":{}}}`, `[]`)

	// The file as it was: the reconnect case
	err := reloadACL(context.Background())
	if err != nil || !pokes.ACLChanged().IsZero() {
		t.Fatalf("reload of an unchanged table: err %v, stamp %v; want no stamp", err, pokes.ACLChanged())
	}

	// The same table written another way
	files.set("acl", `{ "Legacy": { "Search": {} } }`)
	err = reloadACL(context.Background())
	if err != nil || !pokes.ACLChanged().IsZero() {
		t.Fatalf("reload of a table spaced differently: err %v, stamp %v; want no stamp", err, pokes.ACLChanged())
	}

	files.set("acl", `{"Legacy":{"Search":{},"Upload":{}}}`)
	before := time.Now().Truncate(time.Second)
	err = reloadACL(context.Background())
	stamp := pokes.ACLChanged()
	if err != nil || stamp.Before(before) || time.Since(stamp) > time.Minute {
		t.Fatalf("reload of a changed table: err %v, stamp %v; want it stamped now", err, stamp)
	}

	// Read again, it is the table it is
	err = reloadACL(context.Background())
	if err != nil || !pokes.ACLChanged().Equal(stamp) {
		t.Errorf("a second reload: err %v, stamp %v then %v; want the stamp left as it was", err, stamp, pokes.ACLChanged())
	}
}

// A reload that fails keeps the table it could not replace, and stamps
// nothing.
func TestReloadACLThatFailsStampsNothing(t *testing.T) {
	pokes := freshPokes(t)
	files := loadAccessFiles(t, `{"Legacy":{"Search":{}}}`, `[]`)
	files.set("acl", "")

	err := reloadACL(context.Background())
	if err == nil || !pokes.ACLChanged().IsZero() || len(ACL()) != 1 {
		t.Errorf("err %v, stamp %v, table %v; want an error, no stamp, the old table kept", err, pokes.ACLChanged(), ACL())
	}
}

// The site's startup load stamps and pokes nothing: a deploy restarts nine
// sites, and none of them may renew every reader. The admin's config reload
// after it is an edit like a save: a changed table stamps, a changed grant
// pokes its reader, and the same files again leave the stamp as it was.
func TestLoadStampsOnlyAChangeAfterTheFirst(t *testing.T) {
	renewalConfig(t, renewalBlock, "client-id")
	pokes := freshPokes(t)
	sources := access.Sources{TablePath: "acl", GrantsPath: "grants"}
	files := &accessFiles{files: map[string]string{"acl": `{"Legacy":{"Search":{}}}`, "grants": `[` + grantFor("a@example.com", "Legacy") + `]`}}
	installAccessFiles(t, files)

	err := loadAccess(context.Background(), sources)
	if err != nil {
		t.Fatal(err)
	}
	if !pokes.ACLChanged().IsZero() || pokes.Len() != 0 {
		t.Fatalf("the first load stamped %v and poked %v", pokes.ACLChanged(), pokes.Len())
	}

	files.set("acl", `{"Legacy":{"Search":{},"Upload":{}},"Vintage":{"Search":{}}}`)
	files.set("grants", `[`+grantFor("a@example.com", "Vintage")+`]`)
	before := time.Now().Truncate(time.Second)
	err = loadAccess(context.Background(), sources)
	if err != nil {
		t.Fatal(err)
	}
	if len(ACL()) != 2 || PatreonGrants()[0].Tier != "Vintage" {
		t.Fatalf("the load did not bring the changed files: %v %v", ACL(), PatreonGrants())
	}
	stamp := pokes.ACLChanged()
	poked := pokes.Poked(userstate.HashEmail("a@example.com"), time.Now(), pokeWindow())
	if stamp.Before(before) || !poked || pokes.Len() != 1 {
		t.Errorf("a reload of changed files stamped %v and poked %v, want a stamp now and the grantee alone", stamp, pokes.Len())
	}

	err = loadAccess(context.Background(), sources)
	if err != nil || !pokes.ACLChanged().Equal(stamp) {
		t.Errorf("a reload of the same files: err %v, stamp %v then %v; want the stamp left as it was", err, stamp, pokes.ACLChanged())
	}
}

// An admin's save is stamped on the site that saved it, which skips its own
// NOTIFY, and only when the table it saved is not the one it replaced.
func TestSaveACLStampsOnlyAChangedTable(t *testing.T) {
	pokes := freshPokes(t)
	files := loadAccessFiles(t, `{"Legacy":{"Search":{}}}`, `[]`)

	err := saveACL(context.Background(), access.Table{"Legacy": {"Search": {}}})
	if err != nil || !pokes.ACLChanged().IsZero() {
		t.Fatalf("save of the same table: err %v, stamp %v; want no stamp", err, pokes.ACLChanged())
	}

	before := time.Now().Truncate(time.Second)
	err = saveACL(context.Background(), access.Table{"Legacy": {"Search": {}, "Upload": {}}})
	stamp := pokes.ACLChanged()
	if err != nil || stamp.Before(before) || time.Since(stamp) > time.Minute {
		t.Fatalf("save of a changed table: err %v, stamp %v; want it stamped now", err, stamp)
	}
	if !strings.Contains(files.get("acl"), "Upload") {
		t.Errorf("the file holds %q, want the saved table", files.get("acl"))
	}

	err = saveACL(context.Background(), ACL())
	if err != nil || !pokes.ACLChanged().Equal(stamp) {
		t.Errorf("a second save of it: err %v, stamp %v then %v; want the stamp left as it was", err, stamp, pokes.ACLChanged())
	}
}

// A save that fails changes nothing and stamps nothing.
func TestSaveACLThatFailsStampsNothing(t *testing.T) {
	pokes := freshPokes(t)
	loadAccessFiles(t, `{"Legacy":{"Search":{}}}`, `[]`)
	Access = access.New(access.Hooks{})

	err := saveACL(context.Background(), access.Table{"Legacy": {"Search": {}, "Upload": {}}})
	if err == nil || !pokes.ACLChanged().IsZero() {
		t.Errorf("err %v, stamp %v; want an error and no stamp", err, pokes.ACLChanged())
	}
}

// A grant list reloaded pokes the grantees whose tier or overrides changed, and
// the readers it adds or removes, and nobody else.
func TestReloadGrantsPokesOnlyTheGranteesWhoseGrantChanged(t *testing.T) {
	renewalConfig(t, renewalBlock, "client-id")
	pokes := freshPokes(t)
	files := loadAccessFiles(t, `{"Legacy":{"Search":{}}}`, `[`+
		grantFor("a@example.com", "Legacy")+`,`+grantFor("b@example.com", "Legacy")+`,`+grantFor("c@example.com", "Legacy")+`]`)
	a, b, c := userstate.HashEmail("a@example.com"), userstate.HashEmail("b@example.com"), userstate.HashEmail("c@example.com")

	// Nothing changed: the reconnect case
	err := reloadGrants(context.Background())
	if err != nil || pokes.Len() != 0 {
		t.Fatalf("reload of an unchanged list: err %v, poked %v; want nobody", err, pokes.Len())
	}

	// One tier changed, and a label
	files.set("grants", `[`+grantFor("a@example.com", "Legacy")+`,`+grantFor("b@example.com", "Vintage")+`,`+
		`{"email":"c@example.com","name":"Renamed","category":"mod","tier":"Legacy"}]`)
	err = reloadGrants(context.Background())
	if err != nil || pokes.Len() != 1 || !pokes.Poked(b, time.Now(), pokeWindow()) || pokes.Poked(a, time.Now(), pokeWindow()) || pokes.Poked(c, time.Now(), pokeWindow()) {
		t.Fatalf("reload with b's tier changed: err %v, poked %v; want only b", err, pokes.Len())
	}
	if !pokes.ACLChanged().IsZero() {
		t.Error("a grant edit stamped the access table")
	}

	// One grant removed, one added
	files.set("grants", `[`+grantFor("b@example.com", "Vintage")+`,`+grantFor("c@example.com", "Legacy")+`,`+grantFor("d@example.com", "Legacy")+`]`)
	err = reloadGrants(context.Background())
	if err != nil || !pokes.Poked(a, time.Now(), pokeWindow()) || !pokes.Poked(userstate.HashEmail("d@example.com"), time.Now(), pokeWindow()) || pokes.Len() != 3 {
		t.Errorf("reload with a removed and d added: err %v, poked %v; want a, b and d", err, pokes.Len())
	}
}

// A grant list that cannot be read pokes nobody and keeps the list it has.
func TestReloadGrantsThatFailsPokesNobody(t *testing.T) {
	renewalConfig(t, renewalBlock, "client-id")
	pokes := freshPokes(t)
	files := loadAccessFiles(t, `{"Legacy":{"Search":{}}}`, `[`+grantFor("a@example.com", "Legacy")+`]`)
	files.set("grants", "")

	err := reloadGrants(context.Background())
	if err == nil || pokes.Len() != 0 || len(PatreonGrants()) != 1 {
		t.Errorf("err %v, poked %v, list %v; want an error, nobody and the list kept", err, pokes.Len(), PatreonGrants())
	}
}

// An admin's grant edits poke the grantee on the site that saved them, which
// skips its own NOTIFY.
func TestSaveGrantsPokesTheGrantee(t *testing.T) {
	renewalConfig(t, renewalBlock, "client-id")
	pokes := freshPokes(t)
	files := loadAccessFiles(t, `{"Legacy":{"Search":{}}}`, `[`+grantFor("a@example.com", "Legacy")+`]`)
	a, b := userstate.HashEmail("a@example.com"), userstate.HashEmail("B@Example.com")

	err := saveGrants(context.Background(), PatreonGrants())
	if err != nil || pokes.Len() != 0 {
		t.Fatalf("save of the same list: err %v, poked %v; want nobody", err, pokes.Len())
	}

	err = saveGrants(context.Background(), append(PatreonGrants()[:1:1], PatreonGrant{Email: "B@Example.com", Tier: "Vintage"}))
	if err != nil || pokes.Len() != 1 || !pokes.Poked(b, time.Now(), pokeWindow()) {
		t.Fatalf("save with b granted: err %v, poked %v; want only b", err, pokes.Len())
	}
	if !strings.Contains(files.get("grants"), "Vintage") {
		t.Errorf("the file holds %q, want the saved list", files.get("grants"))
	}

	err = saveGrants(context.Background(), PatreonGrants()[1:])
	if err != nil || !pokes.Poked(a, time.Now(), pokeWindow()) || pokes.Len() != 2 {
		t.Errorf("save with a revoked: err %v, poked %v; want a and b", err, pokes.Len())
	}
}
