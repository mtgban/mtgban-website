package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/userstate"
)

type fakeShareReader struct {
	share userstate.UploadShare
	found bool
	err   error
	asked []string
}

func (f *fakeShareReader) UploadShareByKey(_ context.Context, key, _ string) (userstate.UploadShare, bool, error) {
	f.asked = append(f.asked, key)
	return f.share, f.found, f.err
}

const goodShareKey = "AbCdEfGhIjKlMnOpQrStUv"

func TestLoadUploadShareRefusesBadKeys(t *testing.T) {
	rd := &fakeShareReader{found: true, share: userstate.UploadShare{Key: goodShareKey}}
	for _, key := range []string{"", "abc", "AbCdEfGhIjKlMnOpQrStU'", goodShareKey + "x"} {
		if _, found := loadUploadShare(context.Background(), rd, key); found {
			t.Errorf("%q found", key)
		}
	}
	if len(rd.asked) != 0 {
		t.Fatalf("store asked about %v", rd.asked)
	}
}

func TestLoadUploadShare(t *testing.T) {
	ctx := context.Background()
	if _, found := loadUploadShare(ctx, nil, goodShareKey); found {
		t.Fatal("found without a reader")
	}
	if _, found := loadUploadShare(ctx, &fakeShareReader{err: errors.New("down")}, goodShareKey); found {
		t.Fatal("found on a read error")
	}
	if _, found := loadUploadShare(ctx, &fakeShareReader{}, goodShareKey); found {
		t.Fatal("found an unknown key")
	}
	want := userstate.UploadShare{Key: goodShareKey, Rows: "uuid-1\t1\t\t\t\t\t", Buylist: true}
	got, found := loadUploadShare(ctx, &fakeShareReader{share: want, found: true}, goodShareKey)
	if !found || got != want {
		t.Fatalf("got %+v found %v", got, found)
	}
}

func TestWithSharedRowsKeepsEveryFieldButNotes(t *testing.T) {
	in := withSharedRows(uploadInput{textArea: "ignored"}, "uuid-1\t2\tNM\t1.50\tnote\tbox-1\t1\nuuid-2\t1\t\t\t\t\t", 100)
	if !slices.Equal(in.hashes, []string{"uuid-1", "uuid-2"}) {
		t.Fatalf("hashes %v", in.hashes)
	}
	if !slices.Equal(in.hashesQtys, []string{"2", "1"}) || !slices.Equal(in.hashesCond, []string{"NM", ""}) ||
		!slices.Equal(in.hashesPrice, []string{"1.50", ""}) || !slices.Equal(in.hashesNotes, []string{"", ""}) ||
		!slices.Equal(in.hashesFrom, []string{"box-1", ""}) || !slices.Equal(in.hashesFromQtys, []string{"1", ""}) {
		t.Fatalf("fields %+v", in)
	}
	if in.textArea != "ignored" {
		t.Fatal("other input fields changed")
	}
}

func TestWithSharedRowsCutsAtTheCap(t *testing.T) {
	rows := "u1\t1\tNM\t1\tn1\tf1\t1\nu2\t2\tNM\t2\tn2\tf2\t2\nu3\t3\t\t\t\t\t\nu4\t4\t\t\t\t\t\nu5\t5\t\t\t\t\t"
	in := withSharedRows(uploadInput{}, rows, 2)
	for name, f := range map[string][]string{"hashes": in.hashes, "qtys": in.hashesQtys, "cond": in.hashesCond,
		"price": in.hashesPrice, "notes": in.hashesNotes, "from": in.hashesFrom, "fromQtys": in.hashesFromQtys} {
		if len(f) != 2 {
			t.Errorf("%s has %d entries, want 2", name, len(f))
		}
	}
	if !slices.Equal(in.hashes, []string{"u1", "u2"}) || !slices.Equal(in.hashesQtys, []string{"1", "2"}) {
		t.Fatalf("kept %v %v, want the first two rows", in.hashes, in.hashesQtys)
	}
	if in.rowsCap != 2 {
		t.Errorf("rowsCap is %d, want the cap the rows were cut at", in.rowsCap)
	}
	for _, cap := range []int{0, -1} {
		got := withSharedRows(uploadInput{}, rows, cap)
		if len(got.hashes) != 5 || len(got.hashesFromQtys) != 5 || got.rowsCap != 0 {
			t.Errorf("cap %d cut the rows to %d (rowsCap %d)", cap, len(got.hashes), got.rowsCap)
		}
	}
	if !in.shared {
		t.Fatal("shared flag not set")
	}
}

func TestSharedModeFollowsTheGrant(t *testing.T) {
	cases := []struct{ shareBuylist, canBuylist, want bool }{
		{true, true, true}, {true, false, false}, {false, true, false}, {false, false, false},
	}
	for _, c := range cases {
		if got := sharedMode(c.shareBuylist, c.canBuylist); got != c.want {
			t.Errorf("sharedMode(%v, %v) = %v", c.shareBuylist, c.canBuylist, got)
		}
	}
}

func TestUploadShareSourceNilWithoutClient(t *testing.T) {
	saved := UserStateDB
	t.Cleanup(func() { UserStateDB = saved })
	UserStateDB = nil
	if rd := uploadShareSource(); rd != nil {
		t.Fatalf("reader %#v, want a nil interface", rd)
	}
}

type shareTestReader struct {
	share userstate.UploadShare
	found bool
}

func (f shareTestReader) UploadShareByKey(context.Context, string, string) (userstate.UploadShare, bool, error) {
	return f.share, f.found, nil
}

// shareRows packs n rows the way the page does.
func shareRows(n int) string {
	lines := make([]string, n)
	for i := range lines {
		lines[i] = fmt.Sprintf("uuid-%d\t1\t\t\t\t\t", i)
	}
	return strings.Join(lines, "\n")
}

// openShare serves GET /upload?share= as a signed-in Pioneer reader, who
// has Upload but no buylist grant, and returns the response.
func openShare(t *testing.T, rd uploadShareReader) *httptest.ResponseRecorder {
	t.Helper()
	withSigMode(t, true, true)
	savedSrc := uploadShareSource
	t.Cleanup(func() { uploadShareSource = savedSrc })
	uploadShareSource = func() uploadShareReader { return rd }
	savedLogs := LogPages
	t.Cleanup(func() { LogPages = savedLogs })
	LogPages = map[string]*log.Logger{"Upload": log.New(io.Discard, "", 0)}

	r := httptest.NewRequest(http.MethodGet, "/upload?share="+goodShareKey, nil)
	user := &PatreonUserData{FullName: "A", Email: nextShareEmail(), EmailVerified: true}
	r.AddCookie(&http.Cookie{Name: "MTGBAN", Value: sign("Pioneer", user, map[string]map[string]string{"Upload": {}}, time.Hour)})
	rec := httptest.NewRecorder()
	newSite().Upload(rec, r)
	return rec
}

// The body is counted for data-hash= rather than exposing the page vars.
func TestUploadOpensAShare(t *testing.T) {
	share := userstate.UploadShare{Key: goodShareKey, Rows: shareRows(3), Buylist: true}
	rec := openShare(t, shareTestReader{share: share, found: true})
	body := rec.Body.String()
	for _, want := range []string{"Results from a shared list", "Retail mode", "upload-share-link"} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q", want)
		}
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "gdocURL" {
			t.Errorf("share set the %s cookie", c.Name)
		}
	}
}

func TestUploadCapsAShareAtTheReadersRows(t *testing.T) {
	share := userstate.UploadShare{Key: goodShareKey, Rows: shareRows(MaxUploadEntries + 5)}
	body := openShare(t, shareTestReader{share: share, found: true}).Body.String()
	if want := fmt.Sprintf("Input truncated to the first %d entries", MaxUploadEntries); !strings.Contains(body, want) {
		t.Errorf("body lacks %q", want)
	}
	if n := strings.Count(body, "data-hash="); n != MaxUploadEntries {
		t.Errorf("%d rows rendered, want %d", n, MaxUploadEntries)
	}
}

func TestUploadSaysADeadShareIsGone(t *testing.T) {
	body := openShare(t, shareTestReader{}).Body.String()
	if !strings.Contains(body, uploadShareMissingMsg) {
		t.Error("body lacks the dead-link message")
	}
	if strings.Contains(body, "problem uploading") {
		t.Error("dead link blamed on an upload")
	}
	if strings.Contains(body, "data-hash=") {
		t.Error("rows rendered for a dead link")
	}
}

// A share's notes stay with the owner. On the reader's page a URL note is
// what sourceLink turns into the price cell's href, and the note is written
// verbatim into the reader's CSV, so an owner could hand every reader a
// link, or a spreadsheet formula, under the site's own wording.
func TestSharedRowsCarryNoNotes(t *testing.T) {
	rows := "uuid-1\t1\tNM\t12.00\thttps://attacker.example/login?next=1\t\t\n" +
		"uuid-2\t2\tSP\t3.00\t=HYPERLINK(\"https://attacker.example\",\"open\")\t\t"
	in := withSharedRows(uploadInput{}, rows, 0)
	entries, err := loadHashes(in.hashes, in.hashesQtys, in.hashesCond, in.hashesPrice,
		in.hashesNotes, in.hashesFrom, in.hashesFromQtys)
	if err != nil || len(entries) != 2 {
		t.Fatalf("loadHashes: %d entries, %v", len(entries), err)
	}
	for i, entry := range entries {
		if entry.Notes != "" {
			t.Errorf("row %d carries the owner's note %q", i, entry.Notes)
		}
		cell := loadedPrice(t, entry)
		if strings.Contains(cell, "<a") || strings.Contains(cell, "attacker.example") {
			t.Errorf("row %d links the reader somewhere:\n%s", i, cell)
		}
	}
	// The rest of the row still arrives.
	if entries[0].OriginalPrice != 12 || entries[0].Quantity != 1 || entries[0].OriginalCondition != "NM" ||
		entries[1].OriginalPrice != 3 || entries[1].Quantity != 2 || entries[1].OriginalCondition != "SP" {
		t.Fatalf("other fields lost: %+v", entries)
	}
	if !strings.Contains(loadedPrice(t, entries[0]), "$ 12.00") {
		t.Fatal("the price itself is missing")
	}
}

// The condition column is the other free text a reader's CSV copies as it
// is, so a shared row keeps one of the five grades or nothing.
func TestSharedRowsKeepOnlyKnownConditions(t *testing.T) {
	rows := "uuid-1\t1\t=HYPERLINK(\"https://attacker.example\",\"open\")\t\t\t\t\n" +
		"uuid-2\t1\tNM\t\t\t\t\nuuid-3\t1\tPO\t\t\t\t\nuuid-4\t1\tnm\t\t\t\t\nuuid-5\t1\t\t\t\t\t"
	in := withSharedRows(uploadInput{}, rows, 0)
	entries, err := loadHashes(in.hashes, in.hashesQtys, in.hashesCond, in.hashesPrice,
		in.hashesNotes, in.hashesFrom, in.hashesFromQtys)
	if err != nil || len(entries) != 5 {
		t.Fatalf("loadHashes: %d entries, %v", len(entries), err)
	}
	want := []string{"", "NM", "PO", "", ""}
	for i, entry := range entries {
		if string(entry.OriginalCondition) != want[i] {
			t.Errorf("row %d condition %q, want %q", i, entry.OriginalCondition, want[i])
		}
	}
}
