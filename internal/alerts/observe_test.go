package alerts

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/bwmarrin/discordgo"
	"golang.org/x/time/rate"

	"github.com/mtgban/mtgban-website/observability"
	"github.com/mtgban/mtgban-website/ratelimit"
)

type seen struct{ scope, name, value string }

// recorder is a hook of either shape, keeping what it was told.
type recorder struct{ got []seen }

func (rec *recorder) job(scope, name, value string) {
	rec.got = append(rec.got, seen{scope, name, value})
}

func (rec *recorder) request(_ *http.Request, scope, name, value string) { rec.job(scope, name, value) }

// count is how many times s was seen.
func (rec *recorder) count(s seen) int {
	n := 0
	for _, g := range rec.got {
		if g == s {
			n++
		}
	}
	return n
}

// named is how many times name was seen, whatever its scope and value.
func (rec *recorder) named(name string) int {
	n := 0
	for _, g := range rec.got {
		if g.name == name {
			n++
		}
	}
	return n
}

func TestHelpers(t *testing.T) {
	a := Alert{Above: Threshold{Kind: KindPct, Value: 10}, Below: Threshold{Kind: KindAbs, Value: 2}}
	if got := thresholdValues(a); !slices.Equal(got, []string{"above_pct", "below_abs"}) {
		t.Errorf("thresholdValues = %v", got)
	}
	b := Alert{Above: Threshold{Kind: KindAbs, Value: 1}, Below: Threshold{Kind: KindPct, Value: 5}}
	if got := thresholdValues(b); !slices.Equal(got, []string{"above_abs", "below_pct"}) {
		t.Errorf("thresholdValues = %v", got)
	}
	if got := thresholdValues(Alert{}); len(got) != 0 {
		t.Errorf("thresholdValues of none = %v", got)
	}
	if sideValue(SideRetail) != "retail" || sideValue(SideBuylist) != "buylist" || sideValue("x") != "" {
		t.Error("sideValue maps the two sides and nothing else")
	}
	for n, want := range map[int]string{0: "0", 1: "1-2", 2: "1-2", 3: "3-9", 10: "10+"} {
		if got := storesBucket(n); got != want {
			t.Errorf("storesBucket(%d) = %q, want %q", n, got, want)
		}
	}
	for _, c := range []struct {
		e    MailEvent
		want string
	}{
		{MailEvent{Type: "email.bounced", BounceType: "Permanent"}, "hard_bounce"},
		{MailEvent{Type: "email.bounced", BounceType: "Transient"}, "soft_bounce"},
		{MailEvent{Type: "email.bounced"}, "soft_bounce"},
		{MailEvent{Type: "email.complained"}, "complaint"},
		{MailEvent{Type: "email.delivered"}, "other"},
	} {
		if got := mailEventClass(c.e); got != c.want {
			t.Errorf("mailEventClass(%+v) = %q, want %q", c.e, got, c.want)
		}
	}
	if deliveryOutcome(nil) != "ok" || deliveryOutcome(ErrDailyLimit) != "deferred" ||
		deliveryOutcome(errNotAttempted) != "deferred" || deliveryOutcome(notAttempted(canceledContext())) != "deferred" ||
		deliveryOutcome(errors.New("x")) != "fail" || deliveryOutcome(refusedDM()) != "refused" {
		t.Error("deliveryOutcome")
	}
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// observedAPI is testAlertsAPI with a Discord contact for a@b.com and rec as its hook.
func observedAPI(rec *recorder) (*API, *fakeAlertStore) {
	store := newFakeAlertStore()
	hash := testHash("a@b.com")
	store.contacts[hash] = Contact{UserHash: hash, DiscordUserID: "1", Tier: "Legacy"}
	api := testAlertsAPI(store)
	api.deps.Observe = rec.request
	return api, store
}

const observedCreate = `{"card_id":"card-1","side":"buylist","condition":"NM","stores":["CK"],"above":{"kind":"abs","value":20}}`

func TestCreateIsObserved(t *testing.T) {
	rec := &recorder{}
	api, _ := observedAPI(rec)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/", observedCreate, testCaller("a@b.com", "Legacy")))
	if w.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}
	for _, want := range []seen{
		{"other", "alerts.create", "buylist"}, {"", "alerts.create_delivery", "discord"},
		{"", "alerts.create_condition", "NM"}, {"", "alerts.create_threshold", "above_abs"},
		{"", "alerts.create_stores", "1-2"},
	} {
		if rec.count(want) != 1 {
			t.Errorf("%v seen %d times, want 1: %v", want, rec.count(want), rec.got)
		}
	}
	if len(rec.got) != 5 {
		t.Errorf("observed %v, want the five create facts alone", rec.got)
	}
}

func TestCreateIsObservedOnItsPage(t *testing.T) {
	rec := &recorder{}
	api, _ := observedAPI(rec)
	identity := api.deps.Identity
	api.deps.Identity = func(r *http.Request) (Caller, int, string) {
		c, status, msg := identity(r)
		c.Page = "search"
		return c, status, msg
	}
	body := `{"card_id":"card-1","side":"retail","condition":"NM","above":{"kind":"pct","value":10},"below":{"kind":"abs","value":5}}`
	w := httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/", body, testCaller("a@b.com", "Legacy")))
	if w.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}
	for _, want := range []seen{
		{"search", "alerts.create", "retail"}, {"", "alerts.create_threshold", "above_pct"},
		{"", "alerts.create_threshold", "below_abs"}, {"", "alerts.create_stores", "0"},
	} {
		if rec.count(want) != 1 {
			t.Errorf("%v seen %d times, want 1: %v", want, rec.count(want), rec.got)
		}
	}
}

func TestARefusedCreateIsNotObserved(t *testing.T) {
	rec := &recorder{}
	api, _ := observedAPI(rec)
	body := `{"card_id":"nope","side":"buylist","condition":"NM","above":{"kind":"abs","value":20}}`
	w := httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/", body, testCaller("a@b.com", "Legacy")))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}
	// A duplicate is refused too.
	for range 2 {
		w = httptest.NewRecorder()
		api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/", observedCreate, testCaller("a@b.com", "Legacy")))
	}
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate = %d %s", w.Code, w.Body)
	}
	if n := rec.named("alerts.create"); n != 1 {
		t.Fatalf("alerts.create seen %d times, want the one created: %v", n, rec.got)
	}
}

func TestRowActionsAreObserved(t *testing.T) {
	rec := &recorder{}
	api, _ := observedAPI(rec)
	sig := testCaller("a@b.com", "Legacy")
	for _, step := range []struct {
		method, path, body string
		want               int
	}{
		{"POST", "/api/alerts/", observedCreate, http.StatusCreated},
		{"PATCH", "/api/alerts/1", `{"status":"paused"}`, http.StatusOK},
		{"PATCH", "/api/alerts/1", `{"status":"active"}`, http.StatusOK},
		{"PATCH", "/api/alerts/1", `{"condition":"SP"}`, http.StatusOK},
		{"PATCH", "/api/alerts/1", `{"condition":"XX"}`, http.StatusUnprocessableEntity},
		{"DELETE", "/api/alerts/1", "", http.StatusNoContent},
		{"DELETE", "/api/alerts/1", "", http.StatusNotFound},
		{"DELETE", "/api/alerts/", "", http.StatusOK},
	} {
		w := httptest.NewRecorder()
		api.ServeHTTP(w, alertsRequest(step.method, step.path, step.body, sig))
		if w.Code != step.want {
			t.Fatalf("%s %s %s = %d %s", step.method, step.path, step.body, w.Code, w.Body)
		}
	}
	for _, name := range []string{"alerts.pause", "alerts.resume", "alerts.edit", "alerts.delete", "alerts.delete_all"} {
		if rec.count(seen{"", name, ""}) != 1 {
			t.Errorf("%s seen %d times, want 1: %v", name, rec.count(seen{"", name, ""}), rec.got)
		}
	}
}

func TestTheLimiterRefusalIsObserved(t *testing.T) {
	rec := &recorder{}
	api, _ := observedAPI(rec)
	api.deps.Limiter = ratelimit.NewLimiter(rate.Every(time.Hour), 1)
	codes := []int{}
	for range 2 {
		w := httptest.NewRecorder()
		api.ServeHTTP(w, alertsRequest("GET", "/api/alerts/", "", testCaller("a@b.com", "Legacy")))
		codes = append(codes, w.Code)
	}
	if !slices.Equal(codes, []int{http.StatusOK, http.StatusTooManyRequests}) {
		t.Fatalf("codes = %v", codes)
	}
	if rec.count(seen{"", "ratelimit.reject", "alerts"}) != 1 || len(rec.got) != 1 {
		t.Fatalf("observed %v", rec.got)
	}
}

func TestChannelActionsAreObserved(t *testing.T) {
	rec := &recorder{}
	store := newFakeAlertStore()
	sent := []sentConfirm{}
	api := testChannelAPI(store, &sent, nil)
	api.deps.Observe = rec.request
	// Four mails here, over the per-user three an hour.
	api.deps.ConfirmLimiter = ratelimit.NewLimiter(rate.Inf, 1)
	sig := testCaller("a@b.com", "Legacy")
	hash := testHash("a@b.com")
	now := time.Now()
	store.channels[channelKey{hash, ChannelEmail, SourcePatreon}] = Channel{UserHash: hash, Kind: ChannelEmail, Address: "pat@example.com", Source: SourcePatreon, VerifiedAt: &now, DisabledAt: &now, DisabledReason: ReasonUnsubscribed}
	// rewind takes the last mail to address as sent age ago, past the hourly gap.
	rewind := func(address string, age time.Duration) {
		store.confirmSends[confirmKey{hash, address}] = confirmSend{at: time.Now().Add(-age)}
	}
	steps := []struct {
		method, path, body string
		before             func()
		code               int
		want               string
	}{
		{"POST", "/api/alerts/channels/email", `{"address":"one@example.com"}`, nil, http.StatusAccepted, "add"},
		{"POST", "/api/alerts/channels/email", `{"address":"two@example.com"}`, nil, http.StatusAccepted, "change"},
		{"POST", "/api/alerts/channels/email/resend", `{}`, func() { rewind("one@example.com", 3*time.Hour); rewind("two@example.com", 2*time.Hour) }, http.StatusAccepted, "resend"},
		{"POST", "/api/alerts/channels/email", `{"address":"Two@Example.com"}`, func() { rewind("two@example.com", 2*time.Hour) }, http.StatusAccepted, "resend"},
		{"POST", "/api/alerts/channels/enable", `{"kind":"email"}`, nil, http.StatusNoContent, "enable"},
		{"DELETE", "/api/alerts/channels/email", "", nil, http.StatusNoContent, "remove"},
	}
	for i, step := range steps {
		if step.before != nil {
			step.before()
		}
		w := httptest.NewRecorder()
		api.ServeHTTP(w, channelRequest(step.method, step.path, step.body, sig))
		if w.Code != step.code {
			t.Fatalf("step %d %s %s = %d %s", i, step.method, step.path, w.Code, w.Body)
		}
		if len(rec.got) != i+1 || rec.got[i] != (seen{"", "alerts.channel", step.want}) {
			t.Fatalf("step %d observed %v, want alerts.channel:%s last", i, rec.got, step.want)
		}
	}
	// A refused resend, inside the hour, observes nothing.
	w := httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email", `{"address":"three@example.com"}`, sig))
	w = httptest.NewRecorder()
	api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email/resend", `{}`, sig))
	if w.Code != http.StatusTooManyRequests || rec.count(seen{"", "alerts.channel", "resend"}) != 2 {
		t.Fatalf("resend inside the hour = %d, observed %v", w.Code, rec.got)
	}
}

func TestTheConfirmLimiterRefusalIsObserved(t *testing.T) {
	rec := &recorder{}
	store := newFakeAlertStore()
	sent := []sentConfirm{}
	api := testChannelAPI(store, &sent, nil)
	api.deps.Observe = rec.request
	api.deps.ConfirmLimiter = ratelimit.NewLimiter(rate.Every(time.Hour), 1)
	sig := testCaller("a@b.com", "Legacy")
	codes := []int{}
	for _, addr := range []string{"one@example.com", "two@example.com"} {
		w := httptest.NewRecorder()
		api.ServeHTTP(w, channelRequest("POST", "/api/alerts/channels/email", `{"address":"`+addr+`"}`, sig))
		codes = append(codes, w.Code)
	}
	if !slices.Equal(codes, []int{http.StatusAccepted, http.StatusTooManyRequests}) {
		t.Fatalf("codes = %v", codes)
	}
	want := []seen{{"", "alerts.channel", "add"}, {"", "ratelimit.reject", "alerts_confirm"}}
	if !slices.Equal(rec.got, want) {
		t.Fatalf("observed %v, want %v", rec.got, want)
	}
}

func TestANilHookIsSafe(t *testing.T) {
	store := newFakeAlertStore()
	hash := testHash("a@b.com")
	store.contacts[hash] = Contact{UserHash: hash, DiscordUserID: "1", Tier: "Legacy"}
	api := testAlertsAPI(store)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, alertsRequest("POST", "/api/alerts/", observedCreate, testCaller("a@b.com", "Legacy")))
	if w.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}

	es := newFakeEvalStore(activeAlert())
	dd := &fakeDeliverer{}
	runEvaluation(context.Background(), evalDeps(es, dd, 13), buylistOnly)
	if len(dd.sent) != 1 {
		t.Fatalf("sent = %v", dd.sent)
	}

	secret := []byte("s")
	wh := &Webhook{Secret: secret, Store: newFakeWebhookStore()}
	body := []byte(`{"type":"email.complained","data":{"to":["a@b.com"]}}`)
	rw := httptest.NewRecorder()
	wh.ServeHTTP(rw, signedRequest(secret, "msg_1", time.Now(), body))
	if rw.Code != http.StatusOK {
		t.Fatalf("webhook = %d", rw.Code)
	}
}

func TestFiringIsObserved(t *testing.T) {
	rec := &recorder{}
	store := newFakeEvalStore(activeAlert())
	deps := evalDeps(store, &fakeDeliverer{}, 13)
	deps.Observe = rec.job
	runEvaluation(context.Background(), deps, buylistOnly)
	if rec.count(seen{"", "alerts.fired", "buylist"}) != 1 || rec.count(seen{"discord", "alerts.delivered", "ok"}) != 1 || len(rec.got) != 2 {
		t.Fatalf("observed %v", rec.got)
	}
}

func TestAFailedDeliveryIsObserved(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{errors.New("dial tcp"), "fail"},
		{ErrDailyLimit, "deferred"},
		{refusedDM(), "refused"},
	} {
		rec := &recorder{}
		store := newFakeEvalStore(activeAlert())
		deps := evalDeps(store, &fakeDeliverer{err: c.err}, 13)
		deps.Observe = rec.job
		runEvaluation(context.Background(), deps, buylistOnly)
		if rec.count(seen{"discord", "alerts.delivered", c.want}) != 1 || rec.named("alerts.delivered") != 1 {
			t.Errorf("%v: observed %v", c.err, rec.got)
		}
		fired := 1
		if c.want == "deferred" {
			fired = 0
		}
		if rec.named("alerts.fired") != fired {
			t.Errorf("%v: %d alerts.fired, want %d", c.err, rec.named("alerts.fired"), fired)
		}
	}
}

// A firing deferred on two runs and delivered on the third is fired once and deferred twice.
func TestADeferredFiringIsFiredOnce(t *testing.T) {
	rec := &recorder{}
	store := newFakeEvalStore(activeAlert())
	dd := &fakeDeliverer{err: ErrDailyLimit}
	deps := evalDeps(store, dd, 13)
	deps.Observe = rec.job
	for run := range 3 {
		if run == 2 {
			dd.err = nil
		}
		runEvaluation(context.Background(), deps, buylistOnly)
	}
	if len(store.claims) != 3 {
		t.Fatalf("claims = %v, want one a run", store.claims)
	}
	if rec.count(seen{"", "alerts.fired", "buylist"}) != 1 || rec.count(seen{"discord", "alerts.delivered", "deferred"}) != 2 ||
		rec.count(seen{"discord", "alerts.delivered", "ok"}) != 1 || len(rec.got) != 4 {
		t.Fatalf("observed %v", rec.got)
	}
}

func TestAQuietRunObservesNothing(t *testing.T) {
	rec := &recorder{}
	store := newFakeEvalStore(activeAlert())
	deps := evalDeps(store, &fakeDeliverer{}, 11)
	deps.Observe = rec.job
	runEvaluation(context.Background(), deps, buylistOnly)
	if len(rec.got) != 0 {
		t.Fatalf("observed %v", rec.got)
	}
}

func TestMailEventIsObserved(t *testing.T) {
	rec := &recorder{}
	secret := []byte("s")
	wh := &Webhook{Secret: secret, Store: newFakeWebhookStore(), Observe: rec.job}
	body := []byte(`{"type":"email.complained","data":{"to":["a@b.com"]}}`)
	rw := httptest.NewRecorder()
	wh.ServeHTTP(rw, signedRequest(secret, "msg_1", time.Now(), body))
	if rw.Code != http.StatusOK {
		t.Fatalf("webhook = %d", rw.Code)
	}
	rw = httptest.NewRecorder()
	wh.ServeHTTP(rw, signedRequest([]byte("wrong"), "msg_2", time.Now(), body))
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("bad signature = %d", rw.Code)
	}
	// A type the webhook ignores is still one event.
	rw = httptest.NewRecorder()
	wh.ServeHTTP(rw, signedRequest(secret, "msg_3", time.Now(), []byte(`{"type":"email.delivered","data":{"to":["a@b.com"]}}`)))
	if rw.Code != http.StatusOK {
		t.Fatalf("ignored type = %d", rw.Code)
	}
	if want := []seen{{"", "alerts.mail_event", "complaint"}, {"", "alerts.mail_event", "other"}}; !slices.Equal(rec.got, want) {
		t.Fatalf("observed %v, want %v", rec.got, want)
	}
}

func TestAMailEventTheStoreFailsIsNotObserved(t *testing.T) {
	rec := &recorder{}
	secret := []byte("s")
	store := newFakeWebhookStore()
	store.channelsErr = errors.New("db down")
	wh := &Webhook{Secret: secret, Store: store, Observe: rec.job, Log: func(string, ...any) {}}
	rw := httptest.NewRecorder()
	wh.ServeHTTP(rw, signedRequest(secret, "msg_1", time.Now(), []byte(`{"type":"email.complained","data":{"to":["a@b.com"]}}`)))
	if rw.Code != http.StatusInternalServerError || len(rec.got) != 0 {
		t.Fatalf("webhook = %d, observed %v", rw.Code, rec.got)
	}
}

// refusedDM is a Discord refusal that parks an alert.
func refusedDM() error {
	return &discordgo.RESTError{
		Response: &http.Response{StatusCode: http.StatusForbidden},
		Message:  &discordgo.APIErrorMessage{Code: discordgo.ErrCodeCannotSendMessagesToThisUser},
	}
}

// Every condition an alert may compare is a value alerts.create_condition accepts.
func TestConditionsMatchTheRegistry(t *testing.T) {
	n, ok := observability.Lookup("alerts.create_condition")
	if !ok {
		t.Fatal("alerts.create_condition is not registered")
	}
	for _, c := range Conditions {
		if _, _, ok := n.Check("", c, observability.Validators{}); !ok {
			t.Errorf("the registry refuses condition %q", c)
		}
	}
}
