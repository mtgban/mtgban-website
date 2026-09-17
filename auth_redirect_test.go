package main

import "testing"

func TestAuthRedirect(t *testing.T) {
	tests := []struct {
		name  string
		state string
		want  string
	}{
		{
			name:  "removes error from relative path",
			state: "/?errmsg=TierNotFound;baninc",
			want:  "/",
		},
		{
			name:  "preserves other query parameters",
			state: "/search?q=sol&errmsg=UserNotFound;baninc",
			want:  "/search?q=sol",
		},
		{
			name:  "preserves fragments",
			state: "/search?q=sol&errmsg=UserNotFound#results;baninc",
			want:  "/search?q=sol#results",
		},
		{
			name:  "empty state goes home",
			state: ";baninc",
			want:  "/",
		},
		{
			name:  "rejects absolute URL",
			state: "https://evil.example/?errmsg=TierNotFound;baninc",
			want:  "/",
		},
		{
			name:  "rejects protocol relative URL",
			state: "//evil.example/?errmsg=TierNotFound;baninc",
			want:  "/",
		},
		{
			name:  "rejects backslash host separator",
			state: `/\\evil.example/?errmsg=TierNotFound;baninc`,
			want:  "/",
		},
		{
			name:  "logout goes home",
			state: "https://mtgban.com/?errmsg=logout;baninc",
			want:  "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := authRedirect(tt.state); got != tt.want {
				t.Fatalf("authRedirect(%q) = %q, want %q", tt.state, got, tt.want)
			}
		})
	}
}
