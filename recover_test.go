package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/mtgban/go-mtgban/mtgban"

	"github.com/mtgban/mtgban-website/timeseries"
)

// serverWebhook points ServerNotify at a webhook of the test's own and
// returns what is posted to it, without the "[DEV] " marker. Each message
// is posted from a goroutine of its own, so they arrive in no set order.
// It clears the panic quiet window too, so the test's first panic posts
// its report whatever panicked before it.
func serverWebhook(t *testing.T) <-chan string {
	t.Helper()
	panicReportMu.Lock()
	lastPanicReport, quietPanics = time.Time{}, 0
	panicReportMu.Unlock()

	posts := make(chan string, 64)
	hook := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		var p struct{ Content string }
		err := json.NewDecoder(r.Body).Decode(&p)
		if err != nil {
			t.Error(err)
			return
		}
		select {
		case posts <- strings.TrimPrefix(p.Content, "[DEV] "):
		default:
		}
	}))
	t.Cleanup(hook.Close)

	prev := Config.Discord.ServerWebhookURL
	Config.Discord.ServerWebhookURL = hook.URL
	t.Cleanup(func() { Config.Discord.ServerWebhookURL = prev })
	return posts
}

// panicReport waits for the three messages a recovered panic posts, among
// whatever else reaches the webhook: the panic's message without its
// @here, the stack, and the source line.
func panicReport(t *testing.T, posts <-chan string) (message, stack, source string) {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for message == "" || stack == "" || source == "" {
		select {
		case post := <-posts:
			switch {
			case strings.HasPrefix(post, "@here "):
				message = strings.TrimPrefix(post, "@here ")
			case strings.HasPrefix(post, "goroutine "):
				stack = post
			case strings.HasPrefix(post, "source "):
				source = post
			}
		case <-timeout:
			t.Fatalf("incomplete panic report: message %q, stack %q, source %q", message, stack, source)
		}
	}
	return message, stack, source
}

// A panic value that is not an error is reported as it reads.
func TestRecoverPanicReportsTheValue(t *testing.T) {
	posts := serverWebhook(t)

	panicky := noSigning(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("a string, not an error")
	}))
	panicky.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/search", nil))

	message, _, _ := panicReport(t, posts)
	if message != "a string, not an error" {
		t.Errorf("message = %q, want the panic's value", message)
	}
}

// receiverError is an error whose Error reads its receiver, so a nil one
// panics when asked for its text.
type receiverError struct{ text string }

func (e *receiverError) Error() string { return e.text }

// A panic value whose Error method panics in turn is still reported, as
// fmt prints a nil receiver, and the request still gets its 500.
func TestRecoverPanicReportsAValueWhoseErrorPanics(t *testing.T) {
	posts := serverWebhook(t)

	var nilErr *receiverError
	panicky := noSigning(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(nilErr)
	}))
	rec := httptest.NewRecorder()
	panicky.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/search", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	message, _, _ := panicReport(t, posts)
	if message != "<nil>" {
		t.Errorf("message = %q, want fmt's <nil>", message)
	}
}

// The stack posted is the panicking goroutine's own trace, as printed. A
// goroutine this shallow prints less than the 1024-byte cut, so nothing
// may follow its trace: no other goroutine's, and no NUL padding.
func TestRecoverPanicReportsItsOwnStack(t *testing.T) {
	posts := serverWebhook(t)

	go func() {
		defer recoverPanic(httptest.NewRequest(http.MethodGet, "/search", nil), httptest.NewRecorder())
		panic("a shallow goroutine")
	}()

	_, stack, _ := panicReport(t, posts)
	if strings.Contains(stack, "\ngoroutine ") {
		t.Errorf("stack = %q, want this goroutine's trace alone", stack)
	}
	if strings.ContainsRune(stack, 0) {
		t.Errorf("stack = %q, want no NUL padding", stack)
	}
	// Last, so a failure above still stands: long checkout paths can push
	// even this trace past the cut, and then nothing follows it to check.
	if len(stack) >= 1024 {
		t.Skipf("the trace is %d bytes here, too long to show what follows it", len(stack))
	}
}

// A handler's panic is answered with a 500 and reported with the request
// it came from.
func TestRecoverPanicReportsTheRequest(t *testing.T) {
	posts := serverWebhook(t)

	panicky := noSigning(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(errors.New("the handler broke"))
	}))
	rec := httptest.NewRecorder()
	panicky.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/search?q=bolt", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	message, _, source := panicReport(t, posts)
	if message != "the handler broke" {
		t.Errorf("message = %q, want the panic's", message)
	}
	if source != "source request: /search?q=bolt" {
		t.Errorf("source = %q, want the request", source)
	}
}

// Once a report posts, the panics of the next panicQuietWindow are only
// logged, value, stack and source alike, and the first report past the
// window says how many there were.
func TestReportPanicPostsOncePerQuietWindow(t *testing.T) {
	posts := serverWebhook(t)

	reportPanic("the first panic", "source job: first")
	message, _, _ := panicReport(t, posts)
	if message != "the first panic" {
		t.Errorf("message = %q, want the first panic's", message)
	}

	prevLog := log.Writer()
	var logged bytes.Buffer
	log.SetOutput(&logged)
	reportPanic("the second panic", "source job: second")
	log.SetOutput(prevLog)
	for _, want := range []string{"the second panic", "goroutine ", "source job: second"} {
		if !strings.Contains(logged.String(), want) {
			t.Errorf("logged %q, want %q in it", logged.String(), want)
		}
	}

	panicReportMu.Lock()
	lastPanicReport = lastPanicReport.Add(-panicQuietWindow)
	panicReportMu.Unlock()
	reportPanic("the third panic", "source job: third")

	message, _, source := panicReport(t, posts)
	if message != "the third panic (unposted panics since the last report: 1)" {
		t.Errorf("message = %q, want the third panic's, counting the second", message)
	}
	if source != "source job: third" {
		t.Errorf("source = %q, want the third panic's", source)
	}
}

// cron.v2 runs each job on a goroutine of its own, where an unrecovered
// panic ends the process. Run through recovered, the job's panic is
// reported instead, naming the job.
func TestRecoveredReportsTheJob(t *testing.T) {
	posts := serverWebhook(t)

	go recovered("cron test", func() { panic(errors.New("the job broke")) })()

	message, _, source := panicReport(t, posts)
	if message != "the job broke" {
		t.Errorf("message = %q, want the panic's", message)
	}
	if source != "source job: cron test" {
		t.Errorf("source = %q, want the job", source)
	}
}

// discordgo runs each event handler on a goroutine of its own, so a panic
// in one is reported and costs only that event.
func TestDiscordHandlersRecover(t *testing.T) {
	session, err := discordgo.New("Bot test")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("guildCreate", func(t *testing.T) {
		posts := serverWebhook(t)

		// A GuildCreate that carries no guild.
		go guildCreate(session, &discordgo.GuildCreate{})

		_, _, source := panicReport(t, posts)
		if source != "source job: discord guildCreate" {
			t.Errorf("source = %q, want the handler", source)
		}
	})

	t.Run("messageCreate", func(t *testing.T) {
		posts := serverWebhook(t)

		// The handler ignores messages until scrapers are loaded: one nil
		// each gets past that check, then a message with no author panics.
		prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
		t.Cleanup(func() {
			sellersPtr.Store(prevSellers)
			vendorsPtr.Store(prevVendors)
		})
		sellers := []mtgban.Seller{nil}
		vendors := []mtgban.Vendor{nil}
		sellersPtr.Store(&sellers)
		vendorsPtr.Store(&vendors)

		go testSite.messageCreate(session, &discordgo.MessageCreate{Message: &discordgo.Message{Content: "!Lightning Bolt"}})

		_, _, source := panicReport(t, posts)
		if source != "source job: discord messageCreate" {
			t.Errorf("source = %q, want the handler", source)
		}
	})
}

// panicBucket is a dumps bucket whose every read panics.
type panicBucket struct{}

func (panicBucket) NewReader(context.Context, string) (io.ReadCloser, error) {
	panic(errors.New("the bucket read broke"))
}

// Saving key overrides reloads each affected scraper on a goroutine of its
// own, where a load that panics would otherwise end the process.
func TestOverrideReloadRecovers(t *testing.T) {
	posts := serverWebhook(t)

	prevBucket, prevIdx := DataBucket, scraperIndexPtr.Load()
	t.Cleanup(func() {
		DataBucket = prevBucket
		scraperIndexPtr.Store(prevIdx)
	})
	DataBucket = panicBucket{}
	scraperIndexPtr.Store(newScraperIndex())
	updateScraperIndexStore("cardkingdom", map[string][]string{"retail": {"CK"}})

	reloadOverriddenScrapers(map[string]struct{}{"CK": {}})

	_, _, source := panicReport(t, posts)
	if source != "source job: override reload cardkingdom/retail/CK" {
		t.Errorf("source = %q, want the reload", source)
	}
}

// The admin page hands a snapshot to a goroutine of its own. A panic there
// is reported, and the stash is left free to run again.
func TestAdminSnapshotRecovers(t *testing.T) {
	posts := serverWebhook(t)

	prevDB, prevSellers := PricesArchiveDB, sellersPtr.Load()
	t.Cleanup(func() {
		PricesArchiveDB = prevDB
		sellersPtr.Store(prevSellers)
	})
	// Any archive gets the stash past its first check, and a nil seller
	// panics it on the first read.
	PricesArchiveDB = &timeseries.Client{}
	sellers := []mtgban.Seller{nil}
	sellersPtr.Store(&sellers)

	testSite.Admin(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/admin?reboot=snapshot", nil))

	_, _, source := panicReport(t, posts)
	if source != "source job: admin stashInTimeseries" {
		t.Errorf("source = %q, want the snapshot", source)
	}
	if IsStashingInProgress() {
		t.Error("the stash still counts as running after its panic")
	}
}

// The access listener runs every reload on its goroutine, where a panic
// would end the process and the listening with it.
func TestAccessReloadRecovers(t *testing.T) {
	posts := serverWebhook(t)

	go runAccessReload(aclReloadChannel, "test", func(context.Context) error {
		panic(errors.New("the table broke"))
	})

	_, _, source := panicReport(t, posts)
	if source != "source job: access reload acl_reload" {
		t.Errorf("source = %q, want the reload", source)
	}
}
