package imgmirror

import (
	"testing"
	"time"
)

func TestReserveSpacesRequests(t *testing.T) {
	l := &Limiter{Interval: 100 * time.Millisecond}
	now := time.Unix(1000, 0)

	if d := l.Reserve("scryfall", now); d != 0 {
		t.Errorf("first reserve wait = %v, want 0", d)
	}
	if d := l.Reserve("scryfall", now); d != 100*time.Millisecond {
		t.Errorf("second reserve wait = %v, want 100ms", d)
	}
	if d := l.Reserve("scryfall", now); d != 200*time.Millisecond {
		t.Errorf("third reserve wait = %v, want 200ms", d)
	}
}

func TestReserveDomainsIndependent(t *testing.T) {
	l := &Limiter{Interval: 100 * time.Millisecond}
	now := time.Unix(1000, 0)
	l.Reserve("scryfall", now)
	if d := l.Reserve("tcgplayer", now); d != 0 {
		t.Errorf("other domain wait = %v, want 0", d)
	}
}

func TestReserveResetsAfterIdle(t *testing.T) {
	l := &Limiter{Interval: 100 * time.Millisecond}
	l.Reserve("scryfall", time.Unix(1000, 0))
	if d := l.Reserve("scryfall", time.Unix(2000, 0)); d != 0 {
		t.Errorf("wait after idle = %v, want 0", d)
	}
}

func TestBackoff(t *testing.T) {
	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{0, time.Second}, {1, 2 * time.Second}, {2, 4 * time.Second},
		{4, 16 * time.Second}, {5, 30 * time.Second}, {20, 30 * time.Second},
		{63, 30 * time.Second},
	}
	for _, tt := range tests {
		if got := Backoff(tt.attempt); got != tt.want {
			t.Errorf("Backoff(%d) = %v, want %v", tt.attempt, got, tt.want)
		}
	}
}
