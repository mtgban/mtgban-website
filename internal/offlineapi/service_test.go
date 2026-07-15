package offlineapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleDeniesWithoutACL(t *testing.T) {
	s, _ := newTestService(t)
	s.deps.Allow = func(r *http.Request) (string, bool) { return "", false }

	for _, path := range []string{
		"/api/offline/manifest.json",
		"/api/offline/catalog.json",
		"/api/offline/prices/NEO.bin",
		"/api/offline/images/uuid.webp",
		"/api/offline/imagebundles/NEO.zip",
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
