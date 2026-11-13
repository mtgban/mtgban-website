package offlineapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mtgban/go-mtgban/matcher"
)

func TestHandleDeniesWithoutACL(t *testing.T) {
	s, _ := newTestService(t)
	s.deps.Allow = func(r *http.Request) (string, bool) { return "", false }

	for _, path := range []string{
		"/api/offline/manifest.json",
		"/api/offline/catalog.json",
		"/api/offline/prices/NEO.bin",
		"/api/offline/images/uuid.jpg",
	} {
		w := httptest.NewRecorder()
		s.Handle(w, httptest.NewRequest("GET", path, nil))
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 403", path, w.Code)
		}
	}
}

func TestHandleUnknownEndpointIs404(t *testing.T) {
	s, _ := newTestService(t)
	s.deps.Allow = func(r *http.Request) (string, bool) { return "a@b.c", true }
	w := httptest.NewRecorder()
	s.Handle(w, httptest.NewRequest("GET", "/api/offline/nope", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestHandleRoutesManifest(t *testing.T) {
	s, _ := newTestService(t)
	s.deps.Allow = func(r *http.Request) (string, bool) { return "a@b.c", true }
	w := httptest.NewRecorder()
	s.Handle(w, httptest.NewRequest("GET", "/api/offline/manifest.json", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestHandleObservesTheEndpoint(t *testing.T) {
	s, _ := newTestService(t)
	allow := true
	s.deps.Allow = func(r *http.Request) (string, bool) { return "a@b.c", allow }
	s.deps.CanonicalSetCode = func(*matcher.Backend, string) (string, error) { return "", errors.New("unknown set") }
	var got []string
	s.deps.Observe = func(r *http.Request, scope, name, value string) {
		got = append(got, scope+"|"+name+"|"+value)
	}
	for path, want := range map[string]string{
		"/api/offline/manifest.json": "manifest",
		"/api/offline/catalog.json":  "catalog",
		"/api/offline/prices/LEA":    "prices",
		"/api/offline/bucket-auth":   "bucket_auth",
		"/api/offline/nope":          "",
	} {
		got = nil
		s.Handle(httptest.NewRecorder(), httptest.NewRequest("GET", path, nil))
		if want == "" {
			if len(got) != 0 {
				t.Errorf("%s observed %v, want nothing", path, got)
			}
			continue
		}
		if len(got) != 1 || got[0] != "|offlineapi.fetch|"+want {
			t.Errorf("%s observed %v, want one %s", path, got, want)
		}
	}

	allow = false
	got = nil
	s.Handle(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/offline/manifest.json", nil))
	if len(got) != 0 {
		t.Errorf("a refused request observed %v", got)
	}

	// NewService fills a nil hook with a no-op.
	quiet, _ := newTestService(t)
	quiet.deps.Allow = func(r *http.Request) (string, bool) { return "a@b.c", true }
	quiet.Handle(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/offline/manifest.json", nil))
}
