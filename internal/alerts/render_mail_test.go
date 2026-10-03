package alerts

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

// compareGolden reads path and compares it to got, normalizing CRLF to LF
// on both sides so Windows checkouts stay green; -update rewrites it.
func compareGolden(t *testing.T, path, got string) {
	t.Helper()
	norm := func(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") }
	got = norm(got)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v", path, err)
	}
	wantStr := norm(string(want))
	if got == wantStr {
		return
	}
	gotLines := strings.Split(got, "\n")
	wantLines := strings.Split(wantStr, "\n")
	n := max(len(gotLines), len(wantLines))
	for i := range n {
		var g, w string
		if i < len(gotLines) {
			g = gotLines[i]
		}
		if i < len(wantLines) {
			w = wantLines[i]
		}
		if g != w {
			t.Fatalf("%s: differs at line %d\n- want: %q\n+ got:  %q", path, i+1, w, g)
		}
	}
	t.Fatalf("%s: differs (length mismatch, %d vs %d lines)", path, len(gotLines), len(wantLines))
}

// feldonAlert is digestFixture's first firing: a buylist alert on Feldon
// of the Third Path, reference 0.80, armed above an absolute 1.05.
func feldonAlert(id int64) Alert {
	return Alert{
		ID: id, UserHash: "u1", Game: "magic", CardID: "c19-141-nonfoil",
		Side: SideBuylist, Condition: "NM",
		Card:           Card{Name: "Feldon of the Third Path", Set: "C19", Number: "141", Finish: "nonfoil"},
		ReferencePrice: 0.80,
		Above:          Threshold{Kind: KindAbs, Value: 1.05},
		Status:         StatusActive, Delivery: DeliveryEmail,
		Origin: "https://mtgban.com",
	}
}

// moxOpalAlert is digestFixture's second firing: a retail alert.
func moxOpalAlert(id int64) Alert {
	return Alert{
		ID: id, UserHash: "u1", Game: "magic", CardID: "mh3-232-foil",
		Side: SideRetail, Condition: "NM",
		Card:           Card{Name: "Mox Opal", Set: "MH3", Number: "232", Finish: "foil"},
		ReferencePrice: 150.00,
		Above:          Threshold{Kind: KindAbs, Value: 180.00},
		Status:         StatusActive, Delivery: DeliveryEmail,
		Origin: "https://mtgban.com",
	}
}

// wastelandAlert is digestFixture's third firing: a buylist alert.
func wastelandAlert(id int64) Alert {
	return Alert{
		ID: id, UserHash: "u1", Game: "magic", CardID: "exo-93-nonfoil",
		Side: SideBuylist, Condition: "NM",
		Card:           Card{Name: "Wasteland", Set: "EXO", Number: "93", Finish: "nonfoil"},
		ReferencePrice: 20.00,
		Above:          Threshold{Kind: KindAbs, Value: 25.00},
		Status:         StatusActive, Delivery: DeliveryEmail,
		Origin: "https://mtgban.com",
	}
}

// digestFixture builds n firings, each a different card (Feldon, then Mox
// Opal, then Wasteland), plus two other active alerts and an unsubscribe
// link.
func digestFixture(n int) Digest {
	d := Digest{
		UserHash: "u1",
		Contact:  Contact{UserHash: "u1", Tier: "Legacy"},
		Others: []Alert{
			{Card: Card{Name: "Sol Ring", Set: "C21", Number: "263", Finish: "nonfoil"}, Condition: "NM", Side: SideRetail},
			{Card: Card{Name: "Demonic Tutor", Set: "3ED", Number: "56", Finish: "nonfoil"}, Condition: "NM", Side: SideBuylist},
		},
		UnsubscribeURL: "https://mtgban.com/alerts/unsubscribe?token=abc123",
	}
	firings := []struct {
		alert func(int64) Alert
		hit   Quote
	}{
		{feldonAlert, Quote{Store: "CK", Price: 1.05}},
		{moxOpalAlert, Quote{Store: "SCG", Price: 185.50}},
		{wastelandAlert, Quote{Store: "CK", Price: 26.75}},
	}
	for i := range n {
		f := firings[i%len(firings)]
		a := f.alert(int64(i + 1))
		dec := Decision{FireAbove: true, AboveHits: []Quote{f.hit}}
		d.Firings = append(d.Firings, Firing{Alert: a, Decision: dec, Origin: a.Origin, Contact: d.Contact})
	}
	return d
}

func TestRenderMailGolden(t *testing.T) {
	tpl, err := LoadMailTemplates("../../templates/mail")
	if err != nil {
		t.Fatal(err)
	}
	label := func(s string) string { return map[string]string{"CK": "Card Kingdom", "SCG": "Star City Games"}[s] }
	image := func(id string) string { return "https://img.example/" + id + ".jpg" }
	for _, c := range []struct {
		name    string
		d       Digest
		subject string
	}{
		{"one", digestFixture(1), "Price alert: Feldon of the Third Path"},
		{"three", digestFixture(3), "3 price alerts fired"},
	} {
		subject, text, html, err := RenderMail(tpl, c.d, label, image)
		if err != nil || subject != c.subject {
			t.Fatalf("%s: %q %v", c.name, subject, err)
		}
		compareGolden(t, "testdata/digest_"+c.name+".txt", text)
		compareGolden(t, "testdata/digest_"+c.name+".html", html)
		for _, banned := range []string{"Time to sell", "buy now", "sell now", "\u2014"} {
			if strings.Contains(strings.ToLower(html), strings.ToLower(banned)) {
				t.Errorf("%s: html carries %q", c.name, banned)
			}
		}
		if !strings.Contains(html, "/alerts") || !strings.Contains(text, "/alerts") {
			t.Errorf("%s: no link to the alerts page", c.name)
		}
		if strings.Contains(html, "<link") || strings.Contains(html, "<style") {
			t.Errorf("%s: html must use inline styles only", c.name)
		}
	}
}
