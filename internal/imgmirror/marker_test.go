package imgmirror

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/mtgban/simplecloud"
)

func TestMarkerRoundTrip(t *testing.T) {
	base := filepath.ToSlash(t.TempDir())
	bucket := &simplecloud.FileBucket{}
	if _, found, err := ReadMarker(context.Background(), bucket, base); err != nil || found {
		t.Fatalf("pre-write: found=%v err=%v", found, err)
	}
	if err := WriteMarker(context.Background(), bucket, base, 42); err != nil {
		t.Fatal(err)
	}
	m, found, err := ReadMarker(context.Background(), bucket, base)
	if err != nil || !found {
		t.Fatalf("post-write: found=%v err=%v", found, err)
	}
	if m.Images != 42 || m.CompletedAt == "" {
		t.Errorf("marker = %+v", m)
	}
}

func TestReadMarkerTransientErrorFails(t *testing.T) {
	if _, _, err := ReadMarker(context.Background(), errBucket{errors.New("auth failed")}, "base"); err == nil {
		t.Fatal("transient error must not read as absent")
	}
}
