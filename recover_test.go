package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// serverWebhook points ServerNotify at a webhook of the test's own and
// returns what is posted to it, without the "[DEV] " marker. Each message
// is posted from a goroutine of its own, so they arrive in no set order.
func serverWebhook(t *testing.T) <-chan string {
	t.Helper()
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
