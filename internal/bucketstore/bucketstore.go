// Package bucketstore keeps an in-memory snapshot of a JSON document that
// lives in a cloud bucket, with atomic swap-on-load/save semantics. It backs
// the admin-editable documents (key overrides, chart checkpoints) that are
// read on every request but written rarely.
package bucketstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"sync/atomic"

	"github.com/Backblaze/blazer/b2"
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

	ptr atomic.Pointer[T]
	// loaded is set while the snapshot reflects the bucket: a document was
	// read or saved, or the bucket confirmed there is none.
	loaded atomic.Bool
	// held is set once a document was read or saved, after which a missing
	// or unreadable one is a failure rather than "none yet".
	held atomic.Bool
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

// Loaded reports whether the snapshot reflects the bucket: a document was
// read or saved, or the bucket confirmed there is none.
func (s *Store[T]) Loaded() bool {
	return s.loaded.Load()
}

// Load reads the document from the bucket and publishes it. Until one was
// read or saved, a document that cannot be opened publishes the zero T, and
// one the bucket reports missing marks the store loaded. Once one was read
// or saved, any failure returns the error and the snapshot stays.
func (s *Store[T]) Load(ctx context.Context) error {
	bucket, path, err := s.Bucket(ctx)
	if err != nil {
		return err
	}
	reader, err := simplecloud.InitReader(ctx, bucket, path)
	if err != nil {
		if s.held.Load() {
			return err
		}
		s.startEmpty(path, err)
		return nil
	}
	defer reader.Close()

	// B2 opens lazily, so a missing object first fails here, in an error that
	// does not name it.
	var value T
	err = json.NewDecoder(reader).Decode(&value)
	if err != nil && !s.held.Load() && missing(err) {
		s.startEmpty(path, err)
		return nil
	}
	if err != nil {
		if !s.held.Load() {
			s.loaded.Store(false)
		}
		return fmt.Errorf("bucketstore: %s: %w", path, err)
	}
	s.ptr.Store(&value)
	s.loaded.Store(true)
	s.held.Store(true)
	return nil
}

// startEmpty publishes the zero T, loaded only when err says the bucket has
// no document.
func (s *Store[T]) startEmpty(path string, err error) {
	log.Printf("bucketstore: %s unavailable, starting empty: %v", path, err)
	var zero T
	s.ptr.Store(&zero)
	s.loaded.Store(missing(err))
}

// isB2NotExist reports a B2 not-found, a variable so tests can swap it.
var isB2NotExist = b2.IsNotExist

// missing reports whether err says the document does not exist.
func missing(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || isB2NotExist(err)
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
	s.loaded.Store(true)
	s.held.Store(true)
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
