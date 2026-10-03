package alerts

import (
	"context"
	"strings"
	"testing"
	"time"
)

func parkNoticeFixture(n int) ParkNotice {
	var parked []Moved
	for i := range n {
		parked = append(parked, Moved{
			ID: int64(i + 1), Status: StatusOverAllowance, Side: SideBuylist, Condition: "NM", Origin: "https://lorcana.mtgban.com",
			Card: Card{Name: "Bolt", Set: "LEA", Number: "161", Finish: "nonfoil"},
		})
	}
	return ParkNotice{Parked: parked, Reason: "First reason.\n\nSecond reason."}
}

// The notice says why, lists what, caps the list, and links the site the
// alerts were saved on and the unsubscribe page, in text and HTML alike.
func TestRenderParkMail(t *testing.T) {
	tpl, err := LoadMailTemplates("../../templates/mail")
	if err != nil {
		t.Fatal(err)
	}
	subject, text, html, err := RenderParkMail(tpl, parkNoticeFixture(12), "https://lorcana.mtgban.com/alerts/unsubscribe?token=x")
	if err != nil {
		t.Fatal(err)
	}
	if subject != "Your price alerts are paused" {
		t.Errorf("subject = %q", subject)
	}
	for _, body := range []string{text, html} {
		for _, want := range []string{"First reason.", "Second reason.", "Bolt LEA #161, nonfoil, NM buylist", "and 2 more", "https://lorcana.mtgban.com/alerts", "unsubscribe?token=x"} {
			if !strings.Contains(body, want) {
				t.Errorf("notice body lacks %q:\n%s", want, body)
			}
		}
	}
	if strings.Count(text, "Bolt LEA") != noticeMaxLines {
		t.Errorf("text lists %d alerts, want %d", strings.Count(text, "Bolt LEA"), noticeMaxLines)
	}
}

// A park notice is not a digest: it goes out at the daily ceiling, with the
// unsubscribe headers, to the channel's address.
func TestMailDelivererNotifyParkIgnoresTheCeiling(t *testing.T) {
	fm := &fakeMailer{id: "msg-1"}
	m := testDeliverer(t, fm, 20)
	ch := Channel{UserHash: "u1", Address: "user@example.com"}

	err := m.NotifyPark(context.Background(), ch, parkNoticeFixture(1))
	if err != nil {
		t.Fatal(err)
	}
	if len(fm.sent) != 1 || fm.sent[0].To != ch.Address || fm.sent[0].Subject != "Your price alerts are paused" {
		t.Fatalf("sent = %+v", fm.sent)
	}
	if fm.sent[0].Headers["List-Unsubscribe"] != "<https://mtgban.com/alerts/unsubscribe?u=u1>" || fm.sent[0].Headers["List-Unsubscribe-Post"] == "" {
		t.Fatalf("headers = %v", fm.sent[0].Headers)
	}
}

// Without a mailer or the notice templates there is nothing to send with.
func TestMailDelivererNotifyParkNotConfigured(t *testing.T) {
	m := &MailDeliverer{Now: time.Now}
	err := m.NotifyPark(context.Background(), Channel{Address: "user@example.com"}, parkNoticeFixture(1))
	if err != errMailNotConfigured {
		t.Fatalf("err = %v", err)
	}
}

// No unsubscribe link, no unsubscribe headers: a mail must not advertise
// a one-click that leads nowhere.
func TestMailDelivererNotifyParkWithoutALinkSendsNoHeader(t *testing.T) {
	fm := &fakeMailer{id: "msg-1"}
	m := testDeliverer(t, fm, 0)
	m.Unsubscribe = func(string) string { return "" }
	if err := m.NotifyPark(context.Background(), Channel{Address: "user@example.com"}, parkNoticeFixture(1)); err != nil {
		t.Fatal(err)
	}
	if len(fm.sent[0].Headers) != 0 {
		t.Fatalf("headers = %v", fm.sent[0].Headers)
	}
}
