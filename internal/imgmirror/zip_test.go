package imgmirror

import (
	"archive/zip"
	"bytes"
	"io"
	"testing"
)

func TestBuildBundleRoundtrip(t *testing.T) {
	entries := []BundleEntry{
		{Name: "uuid-b.webp", Data: []byte("bbb")},
		{Name: "uuid-a.webp", Data: []byte("aaa")},
	}
	data, err := BuildBundle(entries)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if len(zr.File) != 2 {
		t.Fatalf("entry count = %d, want 2", len(zr.File))
	}
	// Entries come out sorted regardless of input order.
	if zr.File[0].Name != "uuid-a.webp" || zr.File[1].Name != "uuid-b.webp" {
		t.Fatalf("entry order: %s, %s", zr.File[0].Name, zr.File[1].Name)
	}
	if zr.File[0].Method != zip.Store {
		t.Error("entries should be stored, not deflated")
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(rc)
	rc.Close()
	if string(body) != "aaa" {
		t.Errorf("entry body = %q", body)
	}
}

func TestBuildBundleDeterministic(t *testing.T) {
	a, err := BuildBundle([]BundleEntry{{Name: "x.webp", Data: []byte("1")}, {Name: "y.webp", Data: []byte("2")}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildBundle([]BundleEntry{{Name: "y.webp", Data: []byte("2")}, {Name: "x.webp", Data: []byte("1")}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("same entries in different order produced different zips")
	}
}

func TestBuildBundleEmpty(t *testing.T) {
	data, err := BuildBundle(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err != nil {
		t.Errorf("empty bundle is not a valid zip: %v", err)
	}
}
