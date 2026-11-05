package salesvelocity

import (
	"strings"
	"testing"
	"time"
)

// TestJudgePull alarms on the real signed-out day and not the real
// signed-in ones, and on a pull that stopped, not on a normal wait for the next.
func TestJudgePull(t *testing.T) {
	date := func(month time.Month, day, hour int) time.Time {
		return time.Date(2026, month, day, hour, 0, 0, 0, time.UTC)
	}
	for _, tc := range []struct {
		desc           string
		newest         time.Time
		rows, overFive int64
		now            time.Time
		want           string
	}{
		{"signed out, measured", date(10, 13, 0), 86093, 0, date(10, 14, 7), "TCGplayer logins look expired"},
		{"signed in, measured", date(11, 4, 0), 94075, 9142, date(11, 5, 7), ""},
		{"first signed-in day, measured", date(10, 14, 0), 93942, 9239, date(10, 15, 7), ""},
		{"under the share", date(11, 4, 0), 94075, 900, date(11, 5, 7), "TCGplayer logins look expired"},
		{"a day with no rows is not signed out", date(11, 4, 0), 0, 0, date(11, 5, 7), ""},
		{"just before the next pull", date(11, 4, 0), 94075, 9142, date(11, 6, 6), ""},
		{"a whole pull missed", date(11, 3, 0), 94075, 9142, date(11, 6, 1), "no new sale day since 2026-11-03"},
		{"stopped wins over signed out", date(11, 3, 0), 86093, 0, date(11, 6, 1), "no new sale day"},
	} {
		day := tc.newest.AddDate(0, 0, -1)
		result, problem := judgePull(tc.newest, day, tc.rows, tc.overFive, tc.now)
		if !strings.Contains(result, tc.newest.Format(time.DateOnly)) {
			t.Errorf("%s: result %q does not name the newest day", tc.desc, result)
		}
		if tc.want == "" && problem != "" {
			t.Errorf("%s: got problem %q, want none", tc.desc, problem)
		}
		if tc.want != "" && !strings.Contains(problem, tc.want) {
			t.Errorf("%s: got problem %q, want %q", tc.desc, problem, tc.want)
		}
	}
}
