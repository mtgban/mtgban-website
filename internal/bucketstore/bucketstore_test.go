package bucketstore

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/mtgban/simplecloud"
)

type testDoc struct {
	Events []string `json:"events"`
}

func fileStore(t *testing.T, name string) *Store[testDoc] {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	return &Store[testDoc]{
		Bucket: func(ctx context.Context) (simplecloud.ReadWriter, string, error) {
			return &simplecloud.FileBucket{}, path, nil
		},
	}
}

func TestStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := fileStore(t, "doc.json")

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

	s := fileStore(t, "absent.json")
	if err := s.Load(ctx); err != nil {
		t.Errorf("Load of a missing document: %v", err)
	}
	if got := s.Get(); got.Events != nil {
		t.Errorf("missing document should publish the zero value, got %v", got)
	}
}

// lazyBucket opens every object and fails on the first read, as B2 does.
type lazyBucket struct {
	simplecloud.FileBucket
	err error
}

func (b *lazyBucket) NewReader(context.Context, string) (io.ReadCloser, error) {
	return io.NopCloser(iotest.ErrReader(b.err)), nil
}

// errB2NotFound stands in for blazer's not-found, whose type is unexported.
var errB2NotFound = errors.New("b2_download_file_by_name: 404: no such file")

// lazyStore reads path from a lazyBucket failing with err, and has
// isB2NotExist report errB2NotFound alone.
func lazyStore(t *testing.T, path string, err error) *Store[testDoc] {
	saved := isB2NotExist
	isB2NotExist = func(e error) bool { return e == errB2NotFound }
	t.Cleanup(func() { isB2NotExist = saved })
	return &Store[testDoc]{
		Bucket: func(ctx context.Context) (simplecloud.ReadWriter, string, error) {
			return &lazyBucket{err: err}, path, nil
		},
	}
}

func TestStoreLoadMissingOnFirstRead(t *testing.T) {
	s := lazyStore(t, "b2://mtgban-config/lorcana/checkpoints.json", errB2NotFound)
	err := s.Load(context.Background())
	if err != nil || !s.Loaded() {
		t.Errorf("Load of a document B2 reports missing = %v, Loaded %v; want nil, true", err, s.Loaded())
	}
}

func TestStoreLoadNamesDocumentOnReadFailure(t *testing.T) {
	const path = "b2://mtgban-config/lorcana/checkpoints.json"
	refused := errors.New("b2_download_file_by_name: 503: service unavailable")
	s := lazyStore(t, path, refused)

	err := s.Load(context.Background())
	if !errors.Is(err, refused) {
		t.Fatalf("Load = %v, want it to wrap %v", err, refused)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("Load = %q, want it to name %s", err, path)
	}
	if s.Loaded() {
		t.Error("a document that failed to read should leave the store not loaded")
	}
}

func TestStoreLazyReloadFailureKeepsDocument(t *testing.T) {
	ctx := context.Background()
	s := fileStore(t, "doc.json")
	err := s.Save(ctx, testDoc{Events: []string{"a"}})
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	s.Bucket = lazyStore(t, "doc.json", errB2NotFound).Bucket
	err = s.Load(ctx)
	if err == nil {
		t.Error("reload of a document B2 reports missing should fail")
	}
	if got := s.Get(); len(got.Events) != 1 || !s.Loaded() {
		t.Errorf("after a failed reload Get = %v, Loaded %v; want the saved document, true", got, s.Loaded())
	}
}

func TestStoreReloadKeepsDocument(t *testing.T) {
	ctx := context.Background()
	s := fileStore(t, "doc.json")
	if err := s.Save(ctx, testDoc{Events: []string{"a"}}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	_, path, _ := s.Bucket(ctx)

	// A reader on the same path never saw the document fail: it loads it,
	// then a reload that cannot open it fails and keeps what was read
	fresh := &Store[testDoc]{Bucket: s.Bucket}
	if err := fresh.Load(ctx); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := fresh.Load(ctx); err == nil {
		t.Error("reload of a document that cannot be opened should fail")
	}
	if got := fresh.Get(); len(got.Events) != 1 || got.Events[0] != "a" {
		t.Errorf("Get after a failed reload = %v, want the loaded document", got)
	}

	// A store that never read one stays quiet on every reload
	absent := fileStore(t, "absent.json")
	for range 2 {
		if err := absent.Load(ctx); err != nil {
			t.Errorf("Load of a document never read: %v", err)
		}
	}
}

func TestStoreJSON(t *testing.T) {
	s := fileStore(t, "doc.json")

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
