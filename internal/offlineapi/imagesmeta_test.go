package offlineapi

import (
	"encoding/json"
	"testing"
)

func TestJoinBucketPath(t *testing.T) {
	tests := []struct{ base, want string }{
		{"offline-mirror", "offline-mirror/images/x.jpg"},
		{"b2://bucket/offline", "b2://bucket/offline/images/x.jpg"},
		{"C:/Users/elmo/scratch", "C:/Users/elmo/scratch/images/x.jpg"},
	}
	for _, tt := range tests {
		if got := JoinBucketPath(tt.base, "images", "x.jpg"); got != tt.want {
			t.Errorf("JoinBucketPath(%q) = %q, want %q", tt.base, got, tt.want)
		}
	}
}

func TestImageInfoJSONRoundTrip(t *testing.T) {
	info := ImageInfo{Hash: "abc123", Count: 302, Bytes: 24800000}
	data, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"h":"abc123","n":302,"b":24800000}` {
		t.Errorf("marshal = %s", data)
	}
	var got ImageInfo
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got != info {
		t.Errorf("round trip = %+v, want %+v", got, info)
	}
}
