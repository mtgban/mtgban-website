package alerts

import (
	"errors"

	"github.com/mtgban/mtgban-website/observability"
)

// sideValue is a side as the registry spells it, "" for neither.
func sideValue(s Side) string {
	switch s {
	case SideRetail:
		return "retail"
	case SideBuylist:
		return "buylist"
	}
	return ""
}

// thresholdValues names the thresholds an alert set.
func thresholdValues(a Alert) []string {
	var out []string
	for _, t := range []struct {
		th       Threshold
		abs, pct string
	}{
		{a.Above, "above_abs", "above_pct"},
		{a.Below, "below_abs", "below_pct"},
	} {
		switch t.th.Kind {
		case KindAbs:
			out = append(out, t.abs)
		case KindPct:
			out = append(out, t.pct)
		}
	}
	return out
}

// storesBucket buckets the stores an alert is scoped to, 0 being every store.
func storesBucket(n int) string {
	return observability.Bucket([]int64{1, 3, 10}, int64(n))
}

// mailEventClass is the kind of mail provider event e is.
func mailEventClass(e MailEvent) string {
	switch {
	case e.Type == "email.bounced" && e.BounceType == "Permanent":
		return "hard_bounce"
	case e.Type == "email.bounced":
		return "soft_bounce"
	case e.Type == "email.complained":
		return "complaint"
	}
	return "other"
}

// deliveryOutcome is how a delivery ended; deferred and fail are retried, refused parks the alert.
func deliveryOutcome(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, ErrDailyLimit), errors.Is(err, errNotAttempted):
		return "deferred"
	case isPermanent(err):
		return "refused"
	}
	return "fail"
}
