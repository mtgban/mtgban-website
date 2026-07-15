package imgmirror

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/mtgban/simplecloud"
)

// errBucket fails every read with a fixed non-not-found error.
type errBucket struct{ err error }

func (b errBucket) NewReader(ctx context.Context, path string) (io.ReadCloser, error) {
	return nil, b.err
}

func TestLoadStateMissingFileStartsEmpty(t *testing.T) {
	base := filepath.ToSlash(t.TempDir())
	state, err := LoadState(context.Background(), &simplecloud.FileBucket{}, base)
	if err != nil {
		t.Fatal(err)
	}
	if len(state) != 0 {
		t.Errorf("state = %v, want empty", state)
	}
}

func TestLoadStateTransientErrorFails(t *testing.T) {
	if _, err := LoadState(context.Background(), errBucket{errors.New("auth failed")}, "base"); err == nil {
		t.Fatal("transient error must not silently start empty")
	}
}

func TestLoadStateCorruptFileFails(t *testing.T) {
	base := filepath.ToSlash(t.TempDir())
	os.WriteFile(filepath.Join(base, "mirror-state.json"), []byte("{not json"), 0644)
	if _, err := LoadState(context.Background(), &simplecloud.FileBucket{}, base); err == nil {
		t.Fatal("expected error on corrupt state")
	}
}
