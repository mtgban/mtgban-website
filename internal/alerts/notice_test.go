package alerts

import (
	"context"
	"errors"
	"slices"
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

// A park notice goes out with the unsubscribe headers, to the channel's
// address, reserved before the send so the daily ceiling counts it; a
// failed send drops its reservation.
func TestMailDelivererNotifyParkCountsTowardTheCeiling(t *testing.T) {
	fm := &fakeMailer{id: "msg-1"}
	m := testDeliverer(t, fm, 19)
	reserved := map[int64]string{}
	var next int64
	// sentAtReserve is how many mails had gone at each reservation.
	var sentAtReserve []int
	m.Reserve = func(_ context.Context, userHash string, _ time.Time, ceiling int) (int64, bool, error) {
		sentAtReserve = append(sentAtReserve, len(fm.sent))
		next++
		reserved[next] = userHash
		return next, ceiling == 20, nil
	}
	m.Release = func(_ context.Context, id int64) error {
		delete(reserved, id)
		return nil
	}
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
	if len(reserved) != 1 || reserved[1] != "u1" {
		t.Fatalf("reserved = %v", reserved)
	}

	fm.err = errors.New("mail down")
	err = m.NotifyPark(context.Background(), ch, parkNoticeFixture(1))
	if err == nil || len(reserved) != 1 {
		t.Fatalf("failed send: %v, reserved %v", err, reserved)
	}
	if !slices.Equal(sentAtReserve, []int{0, 1}) {
		t.Fatalf("reserved with %v mails gone, want each before its send", sentAtReserve)
	}

	// At the ceiling the notice is held back like a digest.
	fm.err = nil
	m = testDeliverer(t, fm, 20)
	err = m.NotifyPark(context.Background(), ch, parkNoticeFixture(1))
	if !errors.Is(err, ErrDailyLimit) || len(fm.sent) != 2 {
		t.Fatalf("at the ceiling: %v, sent %d", err, len(fm.sent))
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
