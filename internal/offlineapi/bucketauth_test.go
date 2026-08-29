package offlineapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func authService(auth func(context.Context, time.Duration) (string, string, time.Time, error)) *Service {
	return NewService(Deps{
		Allow:                  func(r *http.Request) (string, bool) { return "someone@example.com", true },
		ImagesPathConfigured:   func() bool { return true },
		ManifestPathConfigured: func() bool { return false },
		ImagesDownloadAuth:     auth,
	})
}

func TestServeBucketAuthIssuesAToken(t *testing.T) {
	exp := time.Date(2026, 8, 12, 9, 0, 0, 0, time.UTC)
	var gotValid time.Duration
	s := authService(func(_ context.Context, valid time.Duration) (string, string, time.Time, error) {
		gotValid = valid
		return "https://f004.backblazeb2.com/file/mtgban-images/magic", "tok-abc", exp, nil
	})

	w := httptest.NewRecorder()
	s.Handle(w, httptest.NewRequest("GET", "/api/offline/bucket-auth", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", w.Code)
	}
	var doc struct{ Base, Token, Expires string }
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Base != "https://f004.backblazeb2.com/file/mtgban-images/magic" || doc.Token != "tok-abc" {
		t.Errorf("base/token mismatch: %+v", doc)
	}
	if doc.Expires != "2026-08-12T09:00:00Z" {
		t.Errorf("expires = %q, want the issuer's own expiry", doc.Expires)
	}
	if gotValid != bucketAuthValidity {
		t.Errorf("asked for %v, want %v", gotValid, bucketAuthValidity)
	}
	// The token is a credential: a shared cache holding it would hand one
	// user's authorization to the next.
	if got := w.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Errorf("cache control = %q, want private, no-store", got)
	}
}

func TestServeBucketAuthReportsIssuerFailure(t *testing.T) {
	s := authService(func(context.Context, time.Duration) (string, string, time.Time, error) {
		return "", "", time.Time{}, errors.New("b2 unreachable")
	})
	w := httptest.NewRecorder()
	s.Handle(w, httptest.NewRequest("GET", "/api/offline/bucket-auth", nil))
	if w.Code != http.StatusBadGateway {
		t.Errorf("code = %d, want 502 so a client retries rather than caching a failure", w.Code)
	}
}

func TestServeBucketAuthAbsentWhenTheStoreCannotSign(t *testing.T) {
	s := authService(nil)
	w := httptest.NewRecorder()
	s.Handle(w, httptest.NewRequest("GET", "/api/offline/bucket-auth", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("code = %d, want 404 when no issuer is wired", w.Code)
	}
}

// Image bytes are read from the bucket, never from here. This is the guard on
// that: the route existing again would quietly put the origin back in the path
// for every image, which is the whole cost the bundle sync exists to avoid.
func TestImagesAreNotServedByThisServer(t *testing.T) {
	s := authService(nil)
	for _, path := range []string{
		"/api/offline/images/ab154b52-1234-5678-9abc-def012345678.webp",
		"/api/offline/images/p-MH3-541185.jpg",
		"/api/offline/imagebundles/NEO.zip",
	} {
		w := httptest.NewRecorder()
		s.Handle(w, httptest.NewRequest("GET", path, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: code = %d, want 404", path, w.Code)
		}
	}
}
