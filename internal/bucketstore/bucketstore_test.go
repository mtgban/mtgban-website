package bucketstore

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mtgban/simplecloud"
)

type testDoc struct {
	Events []string `json:"events"`
}

func fileStore(t *testing.T, name string, missingOK bool) *Store[testDoc] {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	return &Store[testDoc]{
		Bucket: func(ctx context.Context) (simplecloud.ReadWriter, string, error) {
			return &simplecloud.FileBucket{}, path, nil
		},
		MissingOK: missingOK,
	}
}

func TestStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := fileStore(t, "doc.json", false)

	if got := s.Get(); got.Events != nil {
		t.Errorf("unloaded Get = %v, want zero value", got)
	}

	want := testDoc{Events: []string{"a", "b"}}
	if err := s.Save(ctx, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if got := s.Get(); len(got.Events) != 2 || got.Events[0] != "a" {
		t.Errorf("Get after Save = %v, want %v", got, want)
	}

	// A fresh store over the same path must read back what was saved
	fresh := &Store[testDoc]{Bucket: s.Bucket}
	if err := fresh.Load(ctx); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := fresh.Get(); len(got.Events) != 2 || got.Events[1] != "b" {
		t.Errorf("Get after Load = %v, want %v", got, want)
	}
}

func TestStoreMissingDocument(t *testing.T) {
	ctx := context.Background()

	strict := fileStore(t, "absent.json", false)
	if err := strict.Load(ctx); err == nil {
		t.Error("Load of a missing document should fail without MissingOK")
	}

	lax := fileStore(t, "absent.json", true)
	if err := lax.Load(ctx); err != nil {
		t.Errorf("Load with MissingOK: %v", err)
	}
	if got := lax.Get(); got.Events != nil {
		t.Errorf("missing document should publish the zero value, got %v", got)
	}
}

func TestStoreJSON(t *testing.T) {
	s := fileStore(t, "doc.json", false)

	// The zero snapshot still serializes to a valid document
	out, err := s.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if !strings.Contains(out, "\"events\"") {
		t.Errorf("zero JSON = %q, want an events field", out)
	}

	if err := s.Save(context.Background(), testDoc{Events: []string{"x<y"}}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	out, err = s.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	// Pretty-printed without HTML escaping
	if !strings.Contains(out, "x<y") {
		t.Errorf("JSON should not HTML-escape, got %q", out)
	}
	if !strings.Contains(out, "\n  ") {
		t.Errorf("JSON should be indented, got %q", out)
	}
}
