package tcgcsv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// testClient points a client at a test server with throttling and backoff
// disabled so unit tests stay fast.
func testClient(baseURL string) *Client {
	c := NewClient(Config{UserAgent: "test-agent/9.9"})
	c.baseURL = baseURL
	c.throttle = 0
	c.retryWait = 0
	return c
}

func TestGroupsAndUserAgent(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		if r.URL.Path != "/tcgplayer/71/groups" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Write([]byte(`{"totalItems":1,"success":true,"errors":[],"results":[
			{"groupId":17690,"name":"D23 Promos","abbreviation":"D23","isSupplemental":true,"categoryId":71}]}`))
	}))
	defer srv.Close()

	groups, err := testClient(srv.URL).Groups(context.Background(), 71)
	if err != nil {
		t.Fatalf("Groups: %v", err)
	}
	if len(groups) != 1 || groups[0].GroupID != 17690 || groups[0].Name != "D23 Promos" {
		t.Fatalf("unexpected groups: %+v", groups)
	}
	if gotUA != "test-agent/9.9" {
		t.Errorf("User-Agent = %q, want test-agent/9.9", gotUA)
	}
}

func TestPricesNullHandling(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"success":true,"errors":[],"results":[
			{"productId":454229,"lowPrice":1250.0,"midPrice":1250.0,"highPrice":1250.0,"marketPrice":null,"directLowPrice":null,"subTypeName":"Holofoil"},
			{"productId":454231,"lowPrice":1000.0,"midPrice":1000.0,"highPrice":1000.0,"marketPrice":925.99,"directLowPrice":null,"subTypeName":"Holofoil"}]}`))
	}))
	defer srv.Close()

	prices, err := testClient(srv.URL).Prices(context.Background(), 71, 17690)
	if err != nil {
		t.Fatalf("Prices: %v", err)
	}
	if len(prices) != 2 {
		t.Fatalf("got %d prices, want 2", len(prices))
	}
	// Null market/direct must decode to nil, not 0.
	if prices[0].MarketPrice != nil {
		t.Errorf("expected nil MarketPrice, got %v", *prices[0].MarketPrice)
	}
	if prices[0].DirectLowPrice != nil {
		t.Errorf("expected nil DirectLowPrice, got %v", *prices[0].DirectLowPrice)
	}
	if prices[0].LowPrice == nil || *prices[0].LowPrice != 1250.0 {
		t.Errorf("LowPrice = %v, want 1250.0", prices[0].LowPrice)
	}
	if prices[1].MarketPrice == nil || *prices[1].MarketPrice != 925.99 {
		t.Errorf("MarketPrice = %v, want 925.99", prices[1].MarketPrice)
	}
}

func TestProductExtended(t *testing.T) {
	p := Product{ExtendedData: []ExtendedData{
		{Name: "Rarity", Value: "Promo"},
		{Name: "Number", Value: "4"},
	}}
	if got := p.Extended("Number"); got != "4" {
		t.Errorf("Extended(Number) = %q, want 4", got)
	}
	if got := p.Extended("Missing"); got != "" {
		t.Errorf("Extended(Missing) = %q, want empty", got)
	}
}

func TestLastUpdatedParsing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/last-updated.txt" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Write([]byte("2026-06-30T20:05:27+0000\n"))
	}))
	defer srv.Close()

	got, err := testClient(srv.URL).LastUpdated(context.Background())
	if err != nil {
		t.Fatalf("LastUpdated: %v", err)
	}
	want := time.Date(2026, 6, 30, 20, 5, 27, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("LastUpdated = %v, want %v", got, want)
	}
}

func TestRetryThenSuccess(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte(`{"success":true,"errors":[],"results":[]}`))
	}))
	defer srv.Close()

	if _, err := testClient(srv.URL).Categories(context.Background()); err != nil {
		t.Fatalf("Categories after retries: %v", err)
	}
	if n := calls.Load(); n != 3 {
		t.Errorf("server was hit %d times, want 3 (2 failures + 1 success)", n)
	}
}

func TestRetryExhausted(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer srv.Close()

	if _, err := testClient(srv.URL).Groups(context.Background(), 71); err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if n := calls.Load(); n != 4 {
		t.Errorf("server was hit %d times, want 4 (maxRetries+1)", n)
	}
}

func TestUnsuccessfulEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"success":false,"errors":["bad category"],"results":[]}`))
	}))
	defer srv.Close()

	if _, err := testClient(srv.URL).Groups(context.Background(), 99999); err == nil {
		t.Fatal("expected error for unsuccessful envelope")
	}
}
