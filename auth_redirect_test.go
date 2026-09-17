package main

import "testing"

func TestAuthRedirect(t *testing.T) {
	tests := []struct {
		name  string
		state string
		want  string
	}{
		{
			name:  "removes error from absolute URL",
			state: "https://mtgban.com/?errmsg=TierNotFound;baninc",
			want:  "https://mtgban.com/",
		},
		{
			name:  "preserves other query parameters",
			state: "https://mtgban.com/search?q=sol&errmsg=UserNotFound;baninc",
			want:  "https://mtgban.com/search?q=sol",
		},
		{
			name:  "empty state goes home",
			state: ";baninc",
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
