package alerts

import (
	"context"
	"errors"
	htmltemplate "html/template"
	"testing"
	texttemplate "text/template"
	"time"

	"github.com/mtgban/mtgban-website/mailer"
)

// fakeMailer records every Send call and answers id, err on each.
type fakeMailer struct {
	sent []mailer.Message
	id   string
	err  error
}

func (f *fakeMailer) Send(_ context.Context, m mailer.Message) (string, error) {
	f.sent = append(f.sent, m)
	return f.id, f.err
}

// fakeLedger is a mail ledger already holding sent mails, reserving and
// releasing as the store does.
type fakeLedger struct {
	sent     int
	reserves int
}

func (l *fakeLedger) reserve(_ context.Context, _ string, _ time.Time, ceiling int) (int64, bool, error) {
	if ceiling > 0 && l.sent >= ceiling {
		return 0, false, nil
	}
	l.sent++
	l.reserves++
	return int64(l.reserves), true, nil
}

func (l *fakeLedger) release(context.Context, int64) error {
	l.sent--
	return nil
}

// testDeliverer builds a MailDeliverer over fm with sentCount mails already
// in its ledger and the repo's real mail templates.
func testDeliverer(t *testing.T, fm *fakeMailer, sentCount int) *MailDeliverer {
	t.Helper()
	tpl, err := LoadMailTemplates("../../templates/mail")
	if err != nil {
		t.Fatal(err)
	}
	ledger := &fakeLedger{sent: sentCount}
	return &MailDeliverer{
		Mailer:      fm,
		Templates:   tpl,
		Image:       func(string) string { return "" },
		Unsubscribe: func(userHash string) string { return "https://mtgban.com/alerts/unsubscribe?u=" + userHash },
		Reserve:     ledger.reserve,
		Release:     ledger.release,
		Ceiling:     20,
	}
}

func TestMailDelivererKind(t *testing.T) {
	m := &MailDeliverer{}
	if m.Kind() != ChannelEmail {
		t.Fatalf("Kind() = %v, want %v", m.Kind(), ChannelEmail)
	}
}

func TestMailDelivererSendsOneMailForTheWholeDigest(t *testing.T) {
	fm := &fakeMailer{id: "msg-1"}
	m := testDeliverer(t, fm, 0)
	d := digestFixture(2)
	ch := Channel{Address: "user@example.com"}

	results := m.Deliver(context.Background(), d, ch, func(s string) string { return s })

	if len(fm.sent) != 1 {
		t.Fatalf("Send called %d times, want 1", len(fm.sent))
	}
	msg := fm.sent[0]
	if msg.To != ch.Address {
		t.Fatalf("To = %q, want %q", msg.To, ch.Address)
	}
	wantUnsub := "<https://mtgban.com/alerts/unsubscribe?u=u1>"
	if msg.Headers["List-Unsubscribe"] != wantUnsub {
		t.Fatalf("List-Unsubscribe = %q, want %q", msg.Headers["List-Unsubscribe"], wantUnsub)
	}
	if msg.Headers["List-Unsubscribe-Post"] != "List-Unsubscribe=One-Click" {
		t.Fatalf("List-Unsubscribe-Post = %q", msg.Headers["List-Unsubscribe-Post"])
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	for _, r := range results {
		if r.Err != nil || r.MessageID != "msg-1" {
			t.Fatalf("result = %+v, want MessageID msg-1 and no error", r)
		}
	}
}

// Only a send the provider refused gives its reservation back; a timeout
// or a 5xx may have gone out, and stays counted toward the ceiling.
func TestMailDelivererReleasesOnlyARefusedSend(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		left int
	}{
		{"refused", &mailer.SendError{Status: 422, Permanent: true, Msg: "to: invalid"}, 0},
		{"rate limited", &mailer.SendError{Status: 429, Msg: "slow down"}, 1},
		{"server error", &mailer.SendError{Status: 500, Msg: "internal"}, 1},
		{"timeout", errors.New("mailer: resend: context deadline exceeded"), 1},
	} {
		fm := &fakeMailer{err: tc.err}
		m := testDeliverer(t, fm, 0)
		ledger := &fakeLedger{}
		m.Reserve, m.Release = ledger.reserve, ledger.release
		m.Deliver(context.Background(), digestFixture(1), Channel{Address: "user@example.com"}, func(s string) string { return s })
		if ledger.sent != tc.left {
			t.Errorf("%s: %d mails counted, want %d", tc.name, ledger.sent, tc.left)
		}
	}
}

func TestMailDelivererPermanentSendErrorPropagatesToEveryFiring(t *testing.T) {
	sendErr := &mailer.SendError{Status: 550, Permanent: true, Msg: "no such user"}
	fm := &fakeMailer{err: sendErr}
	m := testDeliverer(t, fm, 0)
	d := digestFixture(2)

	results := m.Deliver(context.Background(), d, Channel{Address: "user@example.com"}, func(s string) string { return s })

	if len(fm.sent) != 1 {
		t.Fatalf("Send called %d times, want 1", len(fm.sent))
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	for _, r := range results {
		if r.Err == nil || !mailer.PermanentSendError(r.Err) {
			t.Fatalf("result Err = %v, want a permanent send error", r.Err)
		}
	}
}

func TestMailDelivererAtCeilingSendsNothing(t *testing.T) {
	fm := &fakeMailer{id: "should-not-send"}
	m := testDeliverer(t, fm, 20)
	d := digestFixture(2)

	results := m.Deliver(context.Background(), d, Channel{Address: "user@example.com"}, func(s string) string { return s })

	if len(fm.sent) != 0 {
		t.Fatalf("Send called %d times, want 0", len(fm.sent))
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	for _, r := range results {
		if !errors.Is(r.Err, ErrDailyLimit) {
			t.Fatalf("result Err = %v, want ErrDailyLimit", r.Err)
		}
	}
}

func TestMailDelivererOneBelowCeilingStillSends(t *testing.T) {
	fm := &fakeMailer{id: "msg-2"}
	m := testDeliverer(t, fm, 19)
	d := digestFixture(1)

	results := m.Deliver(context.Background(), d, Channel{Address: "user@example.com"}, func(s string) string { return s })

	if len(fm.sent) != 1 {
		t.Fatalf("Send called %d times, want 1", len(fm.sent))
	}
	if len(results) != 1 || results[0].Err != nil || results[0].MessageID != "msg-2" {
		t.Fatalf("results = %+v, want one success with msg-2", results)
	}
}

// TestMailDelivererZeroValueFailsClosed covers a MailDeliverer{} built by
// omission (no constructor exists): it must not panic, and must hold every
// firing back with errMailNotConfigured instead of sending.
func TestMailDelivererZeroValueFailsClosed(t *testing.T) {
	m := &MailDeliverer{}
	d := digestFixture(2)

	results := m.Deliver(context.Background(), d, Channel{Address: "user@example.com"}, func(s string) string { return s })

	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	for _, r := range results {
		if !errors.Is(r.Err, errMailNotConfigured) {
			t.Fatalf("result Err = %v, want errMailNotConfigured", r.Err)
		}
	}
}

// TestMailDelivererNilUnsubscribeOmitsHeaders covers a deliverer with no
// Unsubscribe func: it still sends, with UnsubscribeURL left "" and both
// List-Unsubscribe headers left out rather than sent empty.
func TestMailDelivererNilUnsubscribeOmitsHeaders(t *testing.T) {
	fm := &fakeMailer{id: "msg-3"}
	m := testDeliverer(t, fm, 0)
	m.Unsubscribe = nil
	d := digestFixture(1)

	results := m.Deliver(context.Background(), d, Channel{Address: "user@example.com"}, func(s string) string { return s })

	if len(fm.sent) != 1 {
		t.Fatalf("Send called %d times, want 1", len(fm.sent))
	}
	msg := fm.sent[0]
	if _, ok := msg.Headers["List-Unsubscribe"]; ok {
		t.Fatalf("List-Unsubscribe present: %+v", msg.Headers)
	}
	if _, ok := msg.Headers["List-Unsubscribe-Post"]; ok {
		t.Fatalf("List-Unsubscribe-Post present: %+v", msg.Headers)
	}
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("results = %+v, want one success", results)
	}
}

// TestMailDelivererRenderErrorFailsClosed covers RenderMail failing: every
// firing gets the error back and nothing is sent, the same as a Reserve or
// ceiling failure.
func TestMailDelivererRenderErrorFailsClosed(t *testing.T) {
	fm := &fakeMailer{id: "should-not-send"}
	badText := texttemplate.Must(texttemplate.New("digest.txt").Parse("{{.NoSuchField}}"))
	okHTML := htmltemplate.Must(htmltemplate.New("digest.html").Parse("<p>ok</p>"))
	m := &MailDeliverer{
		Mailer:      fm,
		Templates:   MailTemplates{HTML: okHTML, Text: badText},
		Unsubscribe: func(string) string { return "https://mtgban.com/unsub" },
		Reserve:     (&fakeLedger{}).reserve,
		Ceiling:     20,
	}
	d := digestFixture(1)

	results := m.Deliver(context.Background(), d, Channel{Address: "user@example.com"}, func(s string) string { return s })

	if len(fm.sent) != 0 {
		t.Fatalf("Send called %d times, want 0", len(fm.sent))
	}
	if len(results) != 1 || results[0].Err == nil {
		t.Fatalf("results = %+v, want a render error", results)
	}
}

func TestMailDelivererDoneContextSendsNothing(t *testing.T) {
	fm := &fakeMailer{id: "msg-1"}
	m := testDeliverer(t, fm, 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results := m.Deliver(ctx, digestFixture(2), Channel{Address: "user@example.com"}, func(s string) string { return s })

	if len(fm.sent) != 0 {
		t.Fatalf("Send called %d times, want 0", len(fm.sent))
	}
	if len(results) != 2 || !errors.Is(results[0].Err, errNotAttempted) || !errors.Is(results[1].Err, context.Canceled) {
		t.Fatalf("results = %+v", results)
	}
}

func TestMailDelivererReserveCutByTheDeadlineIsNotAttempted(t *testing.T) {
	fm := &fakeMailer{id: "msg-1"}
	m := testDeliverer(t, fm, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Reserve = func(ctx context.Context, _ string, _ time.Time, _ int) (int64, bool, error) {
		cancel()
		return 0, false, ctx.Err()
	}

	results := m.Deliver(ctx, digestFixture(1), Channel{Address: "user@example.com"}, func(s string) string { return s })

	if len(fm.sent) != 0 {
		t.Fatalf("Send called %d times, want 0", len(fm.sent))
	}
	if len(results) != 1 || !errors.Is(results[0].Err, errNotAttempted) || !errors.Is(results[0].Err, context.Canceled) {
		t.Fatalf("results = %+v", results)
	}
}
