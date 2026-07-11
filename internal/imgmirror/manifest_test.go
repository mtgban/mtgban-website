package imgmirror

import "testing"

func TestBundleHashDeterministicAndOrderFree(t *testing.T) {
	a := BundleHash(map[string]string{"uuid-a": "d1", "uuid-b": "d2"})
	b := BundleHash(map[string]string{"uuid-b": "d2", "uuid-a": "d1"})
	if a == "" || a != b {
		t.Errorf("hash not deterministic: %q vs %q", a, b)
	}
}

func TestBundleHashSensitive(t *testing.T) {
	base := map[string]string{"uuid-a": "d1", "uuid-b": "d2"}
	ref := BundleHash(base)
	for name, m := range map[string]map[string]string{
		"digest changed": {"uuid-a": "d1x", "uuid-b": "d2"},
		"uuid changed":   {"uuid-ax": "d1", "uuid-b": "d2"},
		"member removed": {"uuid-a": "d1"},
		"member added":   {"uuid-a": "d1", "uuid-b": "d2", "uuid-c": "d3"},
	} {
		if BundleHash(m) == ref {
			t.Errorf("%s: hash did not change", name)
		}
	}
}

func TestBundleHashFieldBoundary(t *testing.T) {
	if BundleHash(map[string]string{"ab": "c"}) == BundleHash(map[string]string{"a": "bc"}) {
		t.Error("uuid/digest boundary collision")
	}
}

func TestJoinPath(t *testing.T) {
	tests := []struct{ base, want string }{
		{"offline-mirror", "offline-mirror/images/x.webp"},
		{"b2://bucket/offline", "b2://bucket/offline/images/x.webp"},
		{"C:/Users/elmo/scratch", "C:/Users/elmo/scratch/images/x.webp"},
	}
	for _, tt := range tests {
		if got := JoinPath(tt.base, "images", "x.webp"); got != tt.want {
			t.Errorf("JoinPath(%q) = %q, want %q", tt.base, got, tt.want)
		}
	}
}

func TestEntryName(t *testing.T) {
	if got := (StateEntry{}).EntryName("u1"); got != "u1.webp" {
		t.Errorf("default entry name = %q", got)
	}
	if got := (StateEntry{Ext: "jpg"}).EntryName("u1"); got != "u1.jpg" {
		t.Errorf("jpg entry name = %q", got)
	}
}
