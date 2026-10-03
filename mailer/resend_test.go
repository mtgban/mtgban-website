package mailer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newResendServer(t *testing.T, status int, body string, calls *[]map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/emails" || r.Header.Get("Authorization") != "Bearer re_test" {
			t.Errorf("bad request %s %s auth %q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		var got map[string]any
		_ = json.NewDecoder(r.Body).Decode(&got)
		*calls = append(*calls, got)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func TestResendSendsTheMessageAndReturnsTheID(t *testing.T) {
	var calls []map[string]any
	srv := newResendServer(t, 200, `{"id":"49a3999c-0ce1-4ea6-ab68-afcd6dc2e794"}`, &calls)
	defer srv.Close()
	r := &Resend{Key: "re_test", From: "MTGBAN <no-reply@mtgban.com>", Endpoint: srv.URL + "/emails", Client: srv.Client()}
	id, err := r.Send(context.Background(), Message{To: "ann@example.com", Subject: "Hi", Text: "t", HTML: "<p>h</p>",
		Headers: map[string]string{"List-Unsubscribe": "<https://x/u>"}})
	if err != nil || id != "49a3999c-0ce1-4ea6-ab68-afcd6dc2e794" {
		t.Fatalf("id %q err %v", id, err)
	}
	got := calls[0]
	if got["from"] != "MTGBAN <no-reply@mtgban.com>" || got["subject"] != "Hi" || got["text"] != "t" || got["html"] != "<p>h</p>" {
		t.Errorf("payload %v", got)
	}
	to, ok := got["to"].([]any)
	if !ok || len(to) != 1 || to[0] != "ann@example.com" {
		t.Errorf("to %v", got["to"])
	}
	h, ok := got["headers"].(map[string]any)
	if !ok || h["List-Unsubscribe"] != "<https://x/u>" {
		t.Errorf("headers %v", got["headers"])
	}
}

func TestResendRetriesOnceOn429ThenGivesUp(t *testing.T) {
	var calls []map[string]any
	srv := newResendServer(t, 429, `{"message":"rate limited"}`, &calls)
	defer srv.Close()
	r := &Resend{Key: "re_test", From: "a@b.c", Endpoint: srv.URL + "/emails", Client: srv.Client(), retryWait: time.Millisecond}
	_, err := r.Send(context.Background(), Message{To: "d@e.f", Subject: "s", Text: "t"})
	if err == nil || PermanentSendError(err) || len(calls) != 2 {
		t.Fatalf("err %v permanent %v calls %d", err, PermanentSendError(err), len(calls))
	}
}

func TestResendTreatsARecipientRefusalAsPermanent(t *testing.T) {
	var calls []map[string]any
	srv := newResendServer(t, 422, `{"message":"Invalid `+"`to`"+` field. The email address needs to follow the format."}`, &calls)
	defer srv.Close()
	r := &Resend{Key: "re_test", From: "a@b.c", Endpoint: srv.URL + "/emails", Client: srv.Client()}
	_, err := r.Send(context.Background(), Message{To: "reject@example.com", Subject: "s", Text: "t"})
	if !PermanentSendError(err) || len(calls) != 1 || !strings.Contains(err.Error(), "Invalid `to` field") {
		t.Fatalf("err %v calls %d", err, len(calls))
	}
}

func TestResendKeepsConfigErrorsTransient(t *testing.T) {
	cases := []struct {
		status    int
		body      string
		permanent bool
	}{
		{401, `{"message":"Missing API key in the authorization header"}`, false},
		{403, `{"message":"The mtgban.com domain is not verified."}`, false},
		{422, `{"message":"Invalid ` + "`from`" + ` field. The email address needs to follow the format."}`, false},
		{400, `{"message":"bad request"}`, true},
	}
	for _, c := range cases {
		var calls []map[string]any
		srv := newResendServer(t, c.status, c.body, &calls)
		r := &Resend{Key: "re_test", From: "a@b.c", Endpoint: srv.URL + "/emails", Client: srv.Client(), retryWait: time.Millisecond}
		_, err := r.Send(context.Background(), Message{To: "d@e.f", Subject: "s", Text: "t"})
		srv.Close()
		if err == nil || PermanentSendError(err) != c.permanent || len(calls) != 1 {
			t.Errorf("%d: err %v permanent %v calls %d", c.status, err, PermanentSendError(err), len(calls))
		}
	}
}

func TestResendFromEnv(t *testing.T) {
	t.Setenv("RESEND_API_KEY", "")
	if r, err := ResendFromEnv("a@b.c"); r != nil || err != nil {
		t.Fatalf("no key must give nil, nil: %v %v", r, err)
	}
	t.Setenv("RESEND_API_KEY", "re_x")
	if _, err := ResendFromEnv("not an address"); err == nil {
		t.Fatal("bad from accepted")
	}
	r, err := ResendFromEnv("MTGBAN <no-reply@mtgban.com>")
	if err != nil || r.Key != "re_x" || r.Endpoint != "https://api.resend.com/emails" {
		t.Fatalf("%+v %v", r, err)
	}
}
