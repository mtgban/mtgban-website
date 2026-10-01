package alerts

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
)

const (
	minGap         = 6 * time.Hour
	eventRetention = 90 * 24 * time.Hour
	pruneEvery     = time.Hour
	// contactMaxAge is how long a login keeps the evaluator trusting a
	// contact's tier: a billing cycle.
	contactMaxAge = 31 * 24 * time.Hour
)

// EvalStore is what one evaluation run reads and writes; *Store is one.
type EvalStore interface {
	UsersWithAlerts(ctx context.Context, game string) ([]Contact, error)
	ListActive(ctx context.Context, game string, sides []Side) ([]ActiveAlert, error)
	MarkOverAllowance(ctx context.Context, userHash, game string, allowance int) ([]Moved, error)
	ClaimFire(ctx context.Context, id int64, seenUpdatedAt time.Time, wasAbove, wasBelow, nextAbove, nextBelow bool) (bool, error)
	SetState(ctx context.Context, id int64, st State) (bool, error)
	AddEvent(ctx context.Context, e Event) error
	PruneEvents(ctx context.Context, before time.Time) (int64, error)
}

// EvalDeps is everything one evaluation run reads or writes.
type EvalDeps struct {
	Store      EvalStore
	Sender     Sender
	Ready      func() bool
	Values     func(userHash, tier string) url.Values
	Allowance  func(v url.Values) int
	Prices     func(cardID string, side Side, v url.Values) []StorePrice
	Resolve    func(cardID string) (Card, bool, bool)
	Game       string
	StoreLabel func(shorthand string) string
	Now        func() time.Time
	Pace       time.Duration
	Debounce   time.Duration
	RunTimeout time.Duration
	Log        func(format string, args ...any)
	// Report, when set, records what a run did and what went wrong, ""
	// when nothing did.
	Report func(summary, problem string)

	// PerRun, when set, binds the deps to the live data once per run, so a
	// run reads one datastore and one grant index throughout.
	PerRun func(d EvalDeps) EvalDeps
	// PruneDue says whether this run prunes old events; nil prunes every run.
	PruneDue func(now time.Time) bool
}

// logf logs through Log, or the standard logger when it is unset.
func (d EvalDeps) logf(format string, args ...any) {
	if d.Log != nil {
		d.Log(format, args...)
		return
	}
	log.Printf(format, args...)
}

// report records a run's outcome through Report, when it is set.
func (d EvalDeps) report(summary, problem string) {
	if d.Report != nil {
		d.Report(summary, problem)
	}
}

// evalSummary is what one evaluation run did, for the jobs dashboard.
type evalSummary struct {
	users, active, sent, skipped int
	// notices is the parked-alerts DMs the run delivered.
	notices int
	// err is the first error the run logged, nil when there was none.
	err error
}

// fail logs err under step and keeps it when it is the run's first.
func (s *evalSummary) fail(deps EvalDeps, step string, err error) {
	deps.logf("alerts: %s: %v", step, err)
	if s.err == nil {
		s.err = fmt.Errorf("%s: %w", step, err)
	}
}

func (s evalSummary) String() string {
	out := fmt.Sprintf("%d users, %d active, %d sent, %d skipped", s.users, s.active, s.sent, s.skipped)
	if s.notices > 0 {
		out += fmt.Sprintf(", %d park notices", s.notices)
	}
	return out
}

// problem is the first error's text, "" when there was none.
func (s evalSummary) problem() string {
	if s.err == nil {
		return ""
	}
	return s.err.Error()
}

// setState writes a state, logging rather than propagating the error
// so callers stay readable one line per branch.
func setState(ctx context.Context, deps EvalDeps, sum *evalSummary, id int64, st State) {
	_, err := deps.Store.SetState(ctx, id, st)
	if err != nil {
		sum.fail(deps, "state", err)
	}
}

// runEvaluation is one pass over the game's active alerts on the sides
// that changed: allowance, quotes, claim, send, state and events, then
// the prune. A contact older than contactMaxAge is parked and skipped, and
// a user whose alerts this run parks is told so once.
func runEvaluation(ctx context.Context, deps EvalDeps, sides []Side) evalSummary {
	var sum evalSummary
	label := deps.StoreLabel
	if label == nil {
		label = func(shorthand string) string { return shorthand }
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	now := deps.Now()
	users, err := deps.Store.UsersWithAlerts(ctx, deps.Game)
	if err != nil {
		sum.fail(deps, "users", err)
		return sum
	}
	sum.users = len(users)
	attempts := 0
	// send paces every DM a run sends, notices and firings alike.
	send := func(discordUserID string, embed *discordgo.MessageEmbed) error {
		if attempts > 0 && deps.Pace > 0 {
			time.Sleep(deps.Pace)
		}
		attempts++
		return deps.Sender.Send(discordUserID, embed)
	}
	for _, c := range users {
		lapsed := now.Sub(c.UpdatedAt) > contactMaxAge
		allowance := deps.Allowance(deps.Values(c.UserHash, c.Tier))
		if lapsed {
			allowance = 0
		}
		moved, err := deps.Store.MarkOverAllowance(ctx, c.UserHash, deps.Game, allowance)
		if err != nil {
			sum.fail(deps, "allowance", err)
			continue
		}
		var parked []Moved
		for _, m := range moved {
			if m.Status == StatusOverAllowance {
				parked = append(parked, m)
			}
		}
		if len(parked) == 0 || c.DiscordUserID == "" {
			continue
		}
		err = send(c.DiscordUserID, parkedEmbed(parked, parkReason(lapsed, allowance)))
		if err != nil {
			sum.fail(deps, "park notice", err)
			continue
		}
		sum.notices++
	}
	active, err := deps.Store.ListActive(ctx, deps.Game, sides)
	if err != nil {
		sum.fail(deps, "list active", err)
		return sum
	}
	sum.active = len(active)

	for _, a := range active {
		if now.Sub(a.Contact.UpdatedAt) > contactMaxAge {
			deps.logf("alerts: %d skipped, contact login is older than %s", a.ID, contactMaxAge)
			sum.skipped++
			continue
		}
		_, _, found := deps.Resolve(a.CardID)
		if !found {
			setState(ctx, deps, &sum, a.ID, State{Status: StatusUnresolvable, AboveArmed: a.AboveArmed, BelowArmed: a.BelowArmed, LastError: "card no longer in the datastore"})
			sum.skipped++
			continue
		}
		var quotes []Quote
		for _, p := range deps.Prices(a.CardID, a.Side, deps.Values(a.Contact.UserHash, a.Contact.Tier)) {
			if len(a.Stores) > 0 && !slices.ContainsFunc(a.Stores, func(s string) bool { return strings.EqualFold(s, p.Shorthand) }) {
				continue
			}
			price, ok := p.Prices[a.Condition]
			if ok {
				quotes = append(quotes, Quote{Store: p.Shorthand, Price: price})
			}
		}
		d := Evaluate(a.Alert, quotes, now, minGap)
		if !d.FireAbove && !d.FireBelow {
			if d.AboveArmed != a.AboveArmed || d.BelowArmed != a.BelowArmed {
				setState(ctx, deps, &sum, a.ID, State{Status: StatusActive, AboveArmed: d.AboveArmed, BelowArmed: d.BelowArmed})
			}
			continue
		}
		if a.Contact.DiscordUserID == "" {
			setState(ctx, deps, &sum, a.ID, State{Status: StatusUndeliverable, AboveArmed: a.AboveArmed, BelowArmed: a.BelowArmed, LastError: "no Discord account linked on Patreon"})
			sum.skipped++
			continue
		}
		claimed, err := deps.Store.ClaimFire(ctx, a.ID, a.UpdatedAt, a.AboveArmed, a.BelowArmed, d.AboveArmed, d.BelowArmed)
		if err != nil {
			sum.fail(deps, "claim", err)
			sum.skipped++
			continue
		}
		if !claimed {
			deps.logf("alerts: %d changed since listed, skipped", a.ID)
			sum.skipped++
			continue
		}
		sendErr := send(a.Contact.DiscordUserID, dmEmbed(a.Alert, d, a.Origin, label))
		recordEvents(ctx, deps, &sum, a.ID, d, now, sendErr)
		switch {
		case sendErr == nil:
			sum.sent++
			// Delivered: stamp the fire time that starts the send gap.
			setState(ctx, deps, &sum, a.ID, State{Status: StatusActive, AboveArmed: d.AboveArmed, BelowArmed: d.BelowArmed, LastFiredAt: &now})
		case isDMPermanent(sendErr):
			setState(ctx, deps, &sum, a.ID, State{Status: StatusUndeliverable, AboveArmed: d.AboveArmed, BelowArmed: d.BelowArmed, LastError: undeliverableReason(sendErr)})
		default:
			sum.fail(deps, fmt.Sprintf("send %d", a.ID), sendErr)
			setState(ctx, deps, &sum, a.ID, State{Status: StatusActive, AboveArmed: a.AboveArmed, BelowArmed: a.BelowArmed, LastError: "delivery failed, will retry"})
		}
	}
	if deps.PruneDue == nil || deps.PruneDue(now) {
		_, err := deps.Store.PruneEvents(ctx, now.Add(-eventRetention))
		if err != nil {
			sum.fail(deps, "prune", err)
		}
	}
	return sum
}

// parkReason says why a user's alerts were parked and what brings them back.
func parkReason(lapsed bool, allowance int) string {
	switch {
	case lapsed:
		return "No Patreon sign-in for over a month.\nSign in on the site and they come back at the next price update."
	case allowance == 0:
		return "Your tier no longer includes price alerts."
	}
	if allowance == 1 {
		return "Your tier allows 1 alert.\nDelete some and these come back at the next price update."
	}
	return fmt.Sprintf("Your tier allows %d alerts.\nDelete some and these come back at the next price update.", allowance)
}

// recordEvents logs one event per store that crossed, with the outcome.
func recordEvents(ctx context.Context, deps EvalDeps, sum *evalSummary, id int64, d Decision, now time.Time, sendErr error) {
	msg := ""
	if sendErr != nil {
		// fmt recovers if Error() itself panics; a bare .Error() call would not.
		msg = fmt.Sprint(sendErr)
	}
	add := func(threshold string, hits []Quote) {
		for _, q := range hits {
			err := deps.Store.AddEvent(ctx, Event{AlertID: id, FiredAt: now, Threshold: threshold, Store: q.Store, Price: q.Price, Delivered: sendErr == nil, Error: msg})
			if err != nil {
				sum.fail(deps, "event", err)
			}
		}
	}
	if d.FireAbove {
		add("above", d.AboveHits)
	}
	if d.FireBelow {
		add("below", d.BelowHits)
	}
}
