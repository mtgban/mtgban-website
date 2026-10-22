package main

import (
	"net/http"
	"testing"
	"time"
)

// The listener bounds how long a client may take to send its headers, how
// long a keep-alive connection may sit idle, and how large the headers may
// be, and leaves the body unbounded for slow uploads and long downloads.
func TestNewHTTPServerTimeouts(t *testing.T) {
	srv := newHTTPServer(":8080", http.NotFoundHandler())

	if srv.Addr != ":8080" {
		t.Errorf("Addr = %q, want :8080", srv.Addr)
	}
	if srv.ReadHeaderTimeout <= 0 || srv.ReadHeaderTimeout > 30*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want (0, 30s]", srv.ReadHeaderTimeout)
	}
	if srv.IdleTimeout <= 0 {
		t.Errorf("IdleTimeout = %v, want > 0: zero falls back to ReadTimeout, and no timeout", srv.IdleTimeout)
	}
	if srv.MaxHeaderBytes <= 0 || srv.MaxHeaderBytes >= http.DefaultMaxHeaderBytes {
		t.Errorf("MaxHeaderBytes = %d, want below the 1 MB default", srv.MaxHeaderBytes)
	}
	if srv.ReadTimeout != 0 || srv.WriteTimeout != 0 {
		t.Errorf("ReadTimeout = %v, WriteTimeout = %v, want 0: they would cut off uploads and exports",
			srv.ReadTimeout, srv.WriteTimeout)
	}
}
