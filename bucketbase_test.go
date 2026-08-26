package main

import "testing"

// images_path is written by hand, so it arrives with or without a trailing
// slash. B2 object names are literal strings, not a directory tree, so the two
// spellings have to resolve to the same prefix and the same base url.
func TestBucketBaseIgnoresHowThePathWasWritten(t *testing.T) {
	const (
		uri    = "https://f004.backblazeb2.com"
		bucket = "mtgban-images"
		want   = "https://f004.backblazeb2.com/file/mtgban-images/magic"
	)
	for _, path := range []string{"/magic", "/magic/", "magic", "magic/", "//magic//"} {
		prefix := bucketObjectPrefix(path)
		if prefix != "magic" {
			t.Errorf("bucketObjectPrefix(%q) = %q, want magic", path, prefix)
		}
		if got := bucketDownloadBase(uri, bucket, prefix); got != want {
			t.Errorf("bucketDownloadBase for %q = %q, want %q", path, got, want)
		}
	}
}

// A base that ends in a slash makes every object url carry an empty path
// segment, and B2 answers 404 for an object that is really there. The 404 has
// no CORS headers, so a browser reports it as a cross-origin failure and the
// real cause never surfaces.
func TestBucketDownloadBaseNeverEndsInASlash(t *testing.T) {
	for _, tc := range []struct{ uri, bucket, prefix string }{
		{"https://f004.backblazeb2.com/", "mtgban-images", "magic"},
		{"https://f004.backblazeb2.com", "mtgban-images", ""},
		{"https://f004.backblazeb2.com/", "mtgban-images", ""},
	} {
		got := bucketDownloadBase(tc.uri, tc.bucket, tc.prefix)
		if got[len(got)-1] == '/' {
			t.Errorf("bucketDownloadBase(%q, %q, %q) = %q, ends in a slash", tc.uri, tc.bucket, tc.prefix, got)
		}
	}
}

// The whole point: what the client actually requests.
func TestBundleURLFromATrailingSlashConfig(t *testing.T) {
	base := bucketDownloadBase("https://f004.backblazeb2.com", "mtgban-images", bucketObjectPrefix("/magic/"))
	got := base + "/bundles/NEO-abc123.zip"
	want := "https://f004.backblazeb2.com/file/mtgban-images/magic/bundles/NEO-abc123.zip"
	if got != want {
		t.Errorf("bundle url = %q, want %q", got, want)
	}
}
