package cardconduit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
)

// toServer sends every request to srv in place of the host it names.
type toServer struct {
	next http.RoundTripper
	srv  *url.URL
}

func (rt toServer) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme = rt.srv.Scheme
	req.URL.Host = rt.srv.Host
	req.Host = ""
	return rt.next.RoundTrip(req)
}

// useServer points the client at srv, with the given timeout, for one test.
func useServer(t *testing.T, srv *httptest.Server, timeout time.Duration) {
	t.Helper()
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	saved := client
	client = mtgban.NewHTTPClient(
		mtgban.WithHTTPTimeout(timeout),
		mtgban.WithHTTPRetries(0),
		mtgban.WithHTTPTransport(func(next http.RoundTripper) http.RoundTripper {
			return toServer{next: next, srv: target}
		}),
	)
	t.Cleanup(func() { client = saved })
}

func TestSendEstimateReturnsLink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"success":true,"data":{"estimate":{"url":"https://cardconduit.com/e/1"}}}`))
	}))
	defer srv.Close()
	useServer(t, srv, 30*time.Second)

	link, err := SendEstimate(context.Background(), "token", []Item{{Quantity: 1}})
	if err != nil || link != "https://cardconduit.com/e/1" {
		t.Fatalf("got %q, %v, want the estimate's link", link, err)
	}
}

// An answer that stalls mid-body is cut off by the client's timeout.
func TestSendEstimateStalledBodyTimesOut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"success":`))
		err := http.NewResponseController(w).Flush()
		if err != nil {
			t.Error(err)
		}
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer srv.Close()
	useServer(t, srv, 200*time.Millisecond)

	start := time.Now()
	_, err := SendEstimate(context.Background(), "token", []Item{{Quantity: 1}})
	if err == nil {
		t.Fatal("a stalled body decoded without error")
	}
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Fatalf("stalled body took %v to fail, want about the 200ms timeout", elapsed)
	}
}

// A successful answer past the cap is refused, not read to its end.
func TestSendEstimateOversizeBodyErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"success":true,"message":"` + strings.Repeat("a", maxBody) +
			`","data":{"estimate":{"url":"https://cardconduit.com/e/1"}}}`))
	}))
	defer srv.Close()
	useServer(t, srv, 30*time.Second)

	_, err := SendEstimate(context.Background(), "token", []Item{{Quantity: 1}})
	if err == nil {
		t.Fatal("a body past maxBody decoded without error")
	}
}
