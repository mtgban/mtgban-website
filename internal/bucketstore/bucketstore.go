// Package bucketstore keeps an in-memory snapshot of a JSON document that
// lives in a cloud bucket, with atomic swap-on-load/save semantics. It backs
// the admin-editable documents (key overrides, chart checkpoints) that are
// read on every request but written rarely.
package bucketstore

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"sync/atomic"

	"github.com/mtgban/simplecloud"
)

// Store is a bucket-persisted JSON document of type T. Get is safe for
// concurrent readers; Load and Save atomically publish a new snapshot.
// The zero snapshot (before any Load) is the zero value of T.
type Store[T any] struct {
	// Bucket returns the bucket client and document path for one operation.
	// It is called per operation so path or credential changes in the host
	// config are picked up without rebuilding the store.
	Bucket func(ctx context.Context) (simplecloud.ReadWriter, string, error)

	// MissingOK makes Load treat an unopenable document as the zero T
	// instead of an error, for documents that are optional until first
	// saved.
	MissingOK bool

	ptr atomic.Pointer[T]
}

// Get returns the current snapshot, or the zero T when nothing was loaded.
func (s *Store[T]) Get() T {
	p := s.ptr.Load()
	if p == nil {
		var zero T
		return zero
	}
	return *p
}

// Set publishes value as the current snapshot without persisting it, for
// tests and in-process defaults; Save is the persistent form.
func (s *Store[T]) Set(value T) {
	s.ptr.Store(&value)
}

// Load reads the document from the bucket and publishes it. With MissingOK
// set, a document that cannot be opened publishes the zero T instead of
// failing, mirroring how an absent optional file means "no data yet".
func (s *Store[T]) Load(ctx context.Context) error {
	bucket, path, err := s.Bucket(ctx)
	if err != nil {
		return err
	}
	reader, err := simplecloud.InitReader(ctx, bucket, path)
	if err != nil {
		if s.MissingOK {
			log.Printf("bucketstore: %s unavailable, starting empty: %v", path, err)
			var zero T
			s.ptr.Store(&zero)
			return nil
		}
		return err
	}
	defer reader.Close()

	var value T
	if err := json.NewDecoder(reader).Decode(&value); err != nil {
		return err
	}
	s.ptr.Store(&value)
	return nil
}

// Save writes value to the bucket and, on success, publishes it as the new
// snapshot. The document is serialized to a buffer first so encoding errors
// cannot leave a half-written object behind.
func (s *Store[T]) Save(ctx context.Context, value T) error {
	bucket, path, err := s.Bucket(ctx)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	if err := encode(&buf, &value); err != nil {
		return err
	}

	writer, err := simplecloud.InitWriter(ctx, bucket, path)
	if err != nil {
		return err
	}
	if _, err := io.Copy(writer, &buf); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}

	s.ptr.Store(&value)
	return nil
}

// JSON returns the current snapshot serialized the same way Save writes it,
// for display in the admin editor. The zero snapshot serializes normally, so
// an empty store still yields a valid document.
func (s *Store[T]) JSON() (string, error) {
	value := s.Get()
	var buf bytes.Buffer
	if err := encode(&buf, &value); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// encode pretty-prints without HTML escaping so manual diffs stay readable.
func encode(w io.Writer, value any) error {
	e := json.NewEncoder(w)
	e.SetEscapeHTML(false)
	e.SetIndent("", "  ")
	return e.Encode(value)
}
