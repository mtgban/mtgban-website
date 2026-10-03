package alerts

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/mtgban/mtgban-website/mailer"
)

const (
	minGap         = 6 * time.Hour
	eventRetention = 90 * 24 * time.Hour
	pruneEvery     = time.Hour
	// contactMaxAge is how long a login keeps the evaluator trusting a
	// contact's tier: a billing cycle.
	contactMaxAge = 31 * 24 * time.Hour
	// unverifiedChannelMaxAge is how long an unverified user-entered
	// address is kept before it is pruned.
	unverifiedChannelMaxAge = 7 * 24 * time.Hour
	// maxOthers caps the other alerts a digest lists.
	maxOthers = 10
	// channelNoticeReason is the notice line for alerts parked by their channel.
	channelNoticeReason = "Your tier no longer includes the delivery channel these alerts use."
)

// ErrDailyLimit is a deliverer holding a firing back for the user's daily cap.
var ErrDailyLimit = errors.New("alerts: daily email limit reached")

// Deliverer sends a user's firings on one channel and reports per firing.
type Deliverer interface {
	Kind() ChannelKind
	Deliver(ctx context.Context, d Digest, ch Channel, label func(string) string) []Delivery
}

// Delivery is one firing's outcome; MessageID is the provider's, if any.
type Delivery struct {
	AlertID   int64
	Err       error
	MessageID string
}

// EvalStore is what one evaluation run reads and writes; *Store is one.
type EvalStore interface {
	UsersWithAlerts(ctx context.Context, game string) ([]Contact, error)
	ListActive(ctx context.Context, game string, sides []Side) ([]ActiveAlert, error)
	MarkOverAllowance(ctx context.Context, userHash, game string, allowance int) ([]Moved, error)
	MarkChannelDisallowed(ctx context.Context, userHash, game string, allowed []ChannelKind) ([]Moved, error)
	ClaimFire(ctx context.Context, id int64, seenUpdatedAt time.Time, wasAbove, wasBelow, nextAbove, nextBelow bool) (bool, error)
	SetState(ctx context.Context, id int64, seenUpdatedAt time.Time, st State) (bool, error)
	AddEvent(ctx context.Context, e Event) error
	PruneEvents(ctx context.Context, before time.Time) (int64, error)
	PruneUnverifiedChannels(ctx context.Context, before time.Time) (int64, error)
	ChannelsDisabledSince(ctx context.Context, since, until time.Time) (int, error)
}

// EvalDeps is everything one evaluation run reads or writes.
type EvalDeps struct {
	Store      EvalStore
	Deliverers []Deliverer
	ChannelFor func(ctx context.Context, userHash string, kind ChannelKind) (Channel, bool, error)
	// Channels is the delivery channels a user's values allow.
	Channels   func(v url.Values) []ChannelKind
	Ready      func() bool
	Values     func(userHash, tier string) url.Values
	Allowance  func(v url.Values) int
	Prices     func(cardID string, side Side, v url.Values) []StorePrice
	Resolve    func(cardID string) (Card, bool, bool)
	Game       string
	StoreLabel func(shorthand string) string
	Now        func() time.Time
	// Since, when set, is the previous run's start; a zero time counts nothing.
	Since      func() time.Time
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
	// notices is the parked-alerts notices the run delivered, DM or mail.
	notices int
	// mails is the distinct messages sent this run, by provider id.
	mails int
	// deferred is firings held back by a deliverer's daily cap.
	deferred int
	// disabled is channels a bounce or complaint disabled since the last run.
	disabled int
	// start is the time the run began, the next run's Since.
	start time.Time
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
	if s.mails > 0 {
		out += fmt.Sprintf(", %d mails", s.mails)
	}
	if s.deferred > 0 {
		out += fmt.Sprintf(", %d deferred", s.deferred)
	}
	if s.disabled > 0 {
		out += fmt.Sprintf(", %d channels disabled", s.disabled)
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
func setState(ctx context.Context, deps EvalDeps, sum *evalSummary, a ActiveAlert, st State) {
	_, err := deps.Store.SetState(ctx, a.ID, a.UpdatedAt, st)
	if err != nil {
		sum.fail(deps, "state", err)
	}
}

// runEvaluation is one pass over the game's active alerts on the sides
// that changed: allowance, quotes, claim, delivery per user and channel,
// state and events, then the prune. A contact older than contactMaxAge is
// parked and skipped, and a user whose alerts this run parks is told so once.
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
	sum.start = now
	users, err := deps.Store.UsersWithAlerts(ctx, deps.Game)
	if err != nil {
		sum.fail(deps, "users", err)
		return sum
	}
	sum.users = len(users)
	for _, c := range users {
		lapsed := now.Sub(c.UpdatedAt) > contactMaxAge
		values := deps.Values(c.UserHash, c.Tier)
		allowance := deps.Allowance(values)
		if lapsed {
			allowance = 0
		}
		// The channel step first: the allowance ranks only what it leaves.
		// With no allowance at all the allowance step parks, with its notice.
		var disallowed []Moved
		if allowance > 0 {
			disallowed, err = deps.Store.MarkChannelDisallowed(ctx, c.UserHash, deps.Game, deps.Channels(values))
			if err != nil {
				sum.fail(deps, "channels", err)
				continue
			}
		}
		moved, err := deps.Store.MarkOverAllowance(ctx, c.UserHash, deps.Game, allowance)
		if err != nil {
			sum.fail(deps, "allowance", err)
			continue
		}
		byAllowance, byChannel := netParked(disallowed, moved)
		if len(byAllowance) == 0 && len(byChannel) == 0 {
			continue
		}
		var reasons []string
		if len(byAllowance) > 0 {
			reasons = append(reasons, parkReason(lapsed, allowance))
		}
		if len(byChannel) > 0 {
			reasons = append(reasons, channelNoticeReason)
		}
		sendNotice(ctx, deps, &sum, c.UserHash, ParkNotice{Parked: append(byAllowance, byChannel...), Reason: strings.Join(reasons, "\n\n")})
	}
	active, err := deps.Store.ListActive(ctx, deps.Game, sides)
	if err != nil {
		sum.fail(deps, "list active", err)
		return sum
	}
	sum.active = len(active)

	type key struct {
		user string
		kind ChannelKind
	}
	type lookup struct {
		ch Channel
		ok bool
	}
	found := map[key]lookup{}
	digests := map[key]*Digest{}
	var order []key
	// stopped is the alerts this run took out of active before delivery.
	stopped := map[int64]bool{}
	for _, a := range active {
		if now.Sub(a.Contact.UpdatedAt) > contactMaxAge {
			deps.logf("alerts: %d skipped, contact login is older than %s", a.ID, contactMaxAge)
			sum.skipped++
			continue
		}
		_, _, ok := deps.Resolve(a.CardID)
		if !ok {
			setState(ctx, deps, &sum, a, State{Status: StatusUnresolvable, AboveArmed: a.AboveArmed, BelowArmed: a.BelowArmed, LastError: "card no longer in the datastore"})
			stopped[a.ID] = true
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
				setState(ctx, deps, &sum, a, State{Status: StatusActive, AboveArmed: d.AboveArmed, BelowArmed: d.BelowArmed})
			}
			continue
		}
		kind := ChannelDiscord
		if a.Delivery == DeliveryEmail {
			kind = ChannelEmail
		}
		if delivererFor(deps.Deliverers, kind) == nil {
			sum.fail(deps, fmt.Sprintf("deliver %d", a.ID), fmt.Errorf("no %s deliverer", kind))
			sum.skipped++
			continue
		}
		k := key{a.Contact.UserHash, kind}
		ch, seen := found[k]
		if !seen {
			c, ok, err := deps.ChannelFor(ctx, a.Contact.UserHash, kind)
			if err != nil {
				sum.fail(deps, "channel", err)
				sum.skipped++
				continue
			}
			ch = lookup{c, ok}
			found[k] = ch
		}
		if !ch.ok {
			setState(ctx, deps, &sum, a, State{Status: StatusUndeliverable, AboveArmed: a.AboveArmed, BelowArmed: a.BelowArmed, LastError: missingChannelReason(kind)})
			stopped[a.ID] = true
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
		dg, seen := digests[k]
		if !seen {
			dg = &Digest{UserHash: a.Contact.UserHash, Contact: a.Contact}
			digests[k] = dg
			order = append(order, k)
		}
		dg.Firings = append(dg.Firings, Firing{Alert: a.Alert, Decision: d, Origin: a.Origin, Contact: a.Contact})
	}
	byUser := map[string][]ActiveAlert{}
	// rows is each listed alert by id, so a state written after delivery
	// carries the row the run read and leaves one edited since alone.
	rows := map[int64]ActiveAlert{}
	for _, a := range active {
		byUser[a.Contact.UserHash] = append(byUser[a.Contact.UserHash], a)
		rows[a.ID] = a
	}
	// mailIDs is the distinct provider message ids seen this run, across
	// users and channels, so a digest of several firings counts as one mail.
	mailIDs := map[string]bool{}
	for _, k := range order {
		dg := digests[k]
		dg.Others = othersFor(byUser[k.user], dg, stopped)
		results := delivererFor(deps.Deliverers, k.kind).Deliver(ctx, *dg, found[k].ch, label)
		for _, f := range dg.Firings {
			id := f.Alert.ID
			res := resultFor(results, id)
			recordEvents(ctx, deps, &sum, id, f.Decision, now, res.Err, res.MessageID)
			switch {
			case res.Err == nil:
				sum.sent++
				if res.MessageID != "" {
					mailIDs[res.MessageID] = true
				}
				// Delivered: stamp the fire time that starts the send gap.
				setState(ctx, deps, &sum, rows[id], State{Status: StatusActive, AboveArmed: f.Decision.AboveArmed, BelowArmed: f.Decision.BelowArmed, LastFiredAt: &now})
			case errors.Is(res.Err, ErrDailyLimit):
				sum.skipped++
				sum.deferred++
				setState(ctx, deps, &sum, rows[id], State{Status: StatusActive, AboveArmed: f.Alert.AboveArmed, BelowArmed: f.Alert.BelowArmed, LastError: "daily email limit reached, will retry"})
			case isPermanent(res.Err):
				deps.logf("alerts: %d refused: %v", id, res.Err)
				setState(ctx, deps, &sum, rows[id], State{Status: StatusUndeliverable, AboveArmed: f.Decision.AboveArmed, BelowArmed: f.Decision.BelowArmed, LastError: permanentReason(res.Err)})
			default:
				sum.fail(deps, fmt.Sprintf("send %d", id), res.Err)
				setState(ctx, deps, &sum, rows[id], State{Status: StatusActive, AboveArmed: f.Alert.AboveArmed, BelowArmed: f.Alert.BelowArmed, LastError: "delivery failed, will retry"})
			}
		}
	}
	sum.mails = len(mailIDs)
	if deps.Since != nil {
		if since := deps.Since(); !since.IsZero() {
			n, err := deps.Store.ChannelsDisabledSince(ctx, since, now)
			if err != nil {
				sum.fail(deps, "disabled", err)
			} else {
				sum.disabled = n
			}
		}
	}
	if deps.PruneDue == nil || deps.PruneDue(now) {
		_, err := deps.Store.PruneEvents(ctx, now.Add(-eventRetention))
		if err != nil {
			sum.fail(deps, "prune", err)
		}
		_, err = deps.Store.PruneUnverifiedChannels(ctx, now.Add(-unverifiedChannelMaxAge))
		if err != nil {
			sum.fail(deps, "prune channels", err)
		}
	}
	return sum
}

// sendNotice tells a user their alerts were parked: a Discord DM when they
// have that channel, else a mail to their address, the one the tier just
// dropped included; with neither, nobody is told and the run says so.
func sendNotice(ctx context.Context, deps EvalDeps, sum *evalSummary, userHash string, notice ParkNotice) {
	if n, ok := delivererFor(deps.Deliverers, ChannelDiscord).(notifier); ok {
		ch, found, err := deps.ChannelFor(ctx, userHash, ChannelDiscord)
		if err != nil {
			sum.fail(deps, "park notice", err)
			return
		}
		if found {
			if err := n.notify(ch.Address, parkedEmbed(notice.Parked, notice.Reason)); err != nil {
				sum.fail(deps, "park notice", err)
				return
			}
			sum.notices++
			return
		}
	}
	if m, ok := delivererFor(deps.Deliverers, ChannelEmail).(ParkNotifier); ok {
		ch, found, err := deps.ChannelFor(ctx, userHash, ChannelEmail)
		if err != nil {
			sum.fail(deps, "park notice", err)
			return
		}
		if found {
			if err := m.NotifyPark(ctx, ch, notice); err != nil {
				sum.fail(deps, "park notice", err)
				return
			}
			sum.notices++
			return
		}
	}
	sum.skipped++
}

// netParked is the alerts newly parked, split by the step that parked them.
func netParked(channel, allowance []Moved) (byAllowance, byChannel []Moved) {
	first := map[int64]Status{}
	last := map[int64]Moved{}
	fromChannel := map[int64]bool{}
	var ids []int64
	for i, moves := range [][]Moved{channel, allowance} {
		for _, m := range moves {
			_, seen := first[m.ID]
			if !seen {
				first[m.ID] = m.Status
				ids = append(ids, m.ID)
			}
			last[m.ID] = m
			fromChannel[m.ID] = i == 0
		}
	}
	for _, id := range ids {
		if first[id] != StatusOverAllowance || last[id].Status != StatusOverAllowance {
			continue
		}
		if fromChannel[id] {
			byChannel = append(byChannel, last[id])
		} else {
			byAllowance = append(byAllowance, last[id])
		}
	}
	return byAllowance, byChannel
}

// delivererFor is the deliverer of a kind, nil when there is none.
func delivererFor(ds []Deliverer, kind ChannelKind) Deliverer {
	for _, d := range ds {
		if d.Kind() == kind {
			return d
		}
	}
	return nil
}

// resultFor is an alert's delivery, an error when the deliverer gave none.
func resultFor(results []Delivery, id int64) Delivery {
	for _, r := range results {
		if r.AlertID == id {
			return r
		}
	}
	return Delivery{AlertID: id, Err: errors.New("deliverer returned no result")}
}

// othersFor is the digest user's other alerts still active in this run,
// oldest first, at most maxOthers.
func othersFor(active []ActiveAlert, dg *Digest, stopped map[int64]bool) []Alert {
	var out []Alert
	for _, a := range active {
		if a.Contact.UserHash != dg.UserHash || a.Status != StatusActive || stopped[a.ID] {
			continue
		}
		if slices.ContainsFunc(dg.Firings, func(f Firing) bool { return f.Alert.ID == a.ID }) {
			continue
		}
		out = append(out, a.Alert)
	}
	slices.SortStableFunc(out, func(x, y Alert) int {
		return cmp.Or(x.CreatedAt.Compare(y.CreatedAt), cmp.Compare(x.ID, y.ID))
	})
	if len(out) > maxOthers {
		out = out[:maxOthers]
	}
	return out
}

// missingChannelReason is the error on an alert whose user has no channel of its kind.
func missingChannelReason(kind ChannelKind) string {
	if kind == ChannelEmail {
		return ParkNoAddress
	}
	return "no Discord account linked on Patreon"
}

// isPermanent is a recipient refusal on either channel.
func isPermanent(err error) bool {
	return isDMPermanent(err) || mailer.PermanentSendError(err)
}

// mailRefusedReason is the user-facing error for a permanent mail refusal.
const mailRefusedReason = "this address refused our mail"

// permanentReason is the user-facing error for a permanent refusal; the
// provider's own text stays in the event and the log.
func permanentReason(err error) string {
	if isDMPermanent(err) {
		return undeliverableReason(err)
	}
	return mailRefusedReason
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
func recordEvents(ctx context.Context, deps EvalDeps, sum *evalSummary, id int64, d Decision, now time.Time, sendErr error, messageID string) {
	msg := ""
	if sendErr != nil {
		// fmt recovers if Error() itself panics; a bare .Error() call would not.
		msg = fmt.Sprint(sendErr)
	}
	add := func(threshold string, hits []Quote) {
		for _, q := range hits {
			err := deps.Store.AddEvent(ctx, Event{AlertID: id, FiredAt: now, Threshold: threshold, Store: q.Store, Price: q.Price, Delivered: sendErr == nil, Error: msg, MessageID: messageID})
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
