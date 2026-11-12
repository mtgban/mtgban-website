package alerts

import (
	"context"
	"fmt"
	"slices"
)

// GameValue keys a count by game and one bounded value.
type GameValue struct{ Game, Value string }

// GameCount keys a count by game and a size.
type GameCount struct {
	Game string
	N    int
}

// Stock is what the alert tables hold, as counts and nothing else.
// Keyed by the stored game; the caller drops games it does not know.
type Stock struct {
	BySide, ByDelivery, ByStatus, ByCondition map[GameValue]int64
	ByStores                                  map[GameCount]int64 // stores an alert names -> alerts
	Channels                                  map[string]int64    // kind -> channels
	ChannelsDisabled                          map[string]int64    // reason -> disabled channels
	Events                                    map[GameValue]int64 // delivered or failed -> firings
}

// stockQueries is every query StockCounts runs; none reads a column naming a reader.
var stockQueries = map[string]string{
	"alerts":   `SELECT game, side, delivery, status, condition, cardinality(stores), count(*) FROM alerts GROUP BY 1, 2, 3, 4, 5, 6`,
	"channels": `SELECT kind, disabled_at IS NOT NULL, CASE WHEN disabled_reason IN ('bounced', 'complained', 'unsubscribed') THEN disabled_reason ELSE 'other' END, count(*) FROM alert_channels GROUP BY 1, 2, 3`,
	"events":   `SELECT a.game, e.delivered, count(*) FROM alert_events e JOIN alerts a ON a.id = e.alert_id GROUP BY 1, 2`,
}

// The values each bounded column may be counted under; anything else is skipped.
var (
	stockSides      = []string{string(SideRetail), string(SideBuylist)}
	stockDeliveries = []string{string(DeliveryDiscord), string(DeliveryEmail)}
	stockStatuses   = []string{string(StatusActive), string(StatusPaused), string(StatusOverAllowance), string(StatusUndeliverable), string(StatusUnresolvable)}
	stockKinds      = []string{string(ChannelDiscord), string(ChannelEmail)}
	stockReasons    = []string{ReasonBounced, ReasonComplained, ReasonUnsubscribed, stockOtherReason}
)

// stockOtherReason is what the channels query folds an unlisted reason to.
const stockOtherReason = "other"

// StockCounts counts what the alert tables hold, one grouped pass each.
func (s *Store) StockCounts(ctx context.Context) (Stock, error) {
	st := Stock{
		BySide: map[GameValue]int64{}, ByDelivery: map[GameValue]int64{},
		ByStatus: map[GameValue]int64{}, ByCondition: map[GameValue]int64{},
		ByStores: map[GameCount]int64{}, Channels: map[string]int64{},
		ChannelsDisabled: map[string]int64{}, Events: map[GameValue]int64{},
	}
	if err := s.stockAlerts(ctx, &st); err != nil {
		return Stock{}, fmt.Errorf("alerts: stock alerts: %w", err)
	}
	if err := s.stockChannels(ctx, &st); err != nil {
		return Stock{}, fmt.Errorf("alerts: stock channels: %w", err)
	}
	if err := s.stockEvents(ctx, &st); err != nil {
		return Stock{}, fmt.Errorf("alerts: stock events: %w", err)
	}
	return st, nil
}

// stockAlerts adds the alerts by game and each bounded column.
func (s *Store) stockAlerts(ctx context.Context, st *Stock) error {
	rows, err := s.db.QueryContext(ctx, stockQueries["alerts"])
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var game, side, delivery, status, condition string
		var stores int
		var n int64
		if err := rows.Scan(&game, &side, &delivery, &status, &condition, &stores, &n); err != nil {
			return err
		}
		addKnown(st.BySide, game, side, stockSides, n)
		addKnown(st.ByDelivery, game, delivery, stockDeliveries, n)
		addKnown(st.ByStatus, game, status, stockStatuses, n)
		addKnown(st.ByCondition, game, condition, Conditions, n)
		st.ByStores[GameCount{game, stores}] += n
	}
	return rows.Err()
}

// stockChannels adds every channel by kind and the disabled ones by reason.
func (s *Store) stockChannels(ctx context.Context, st *Stock) error {
	rows, err := s.db.QueryContext(ctx, stockQueries["channels"])
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var kind, reason string
		var disabled bool
		var n int64
		if err := rows.Scan(&kind, &disabled, &reason, &n); err != nil {
			return err
		}
		tallyChannels(st, kind, disabled, reason, n)
	}
	return rows.Err()
}

// tallyChannels adds n channels of kind, and under reason when disabled; unlisted words are skipped.
func tallyChannels(st *Stock, kind string, disabled bool, reason string, n int64) {
	if slices.Contains(stockKinds, kind) {
		st.Channels[kind] += n
	}
	if disabled && slices.Contains(stockReasons, reason) {
		st.ChannelsDisabled[reason] += n
	}
}

// stockEvents adds the firings by their alert's game, delivered or failed.
func (s *Store) stockEvents(ctx context.Context, st *Stock) error {
	rows, err := s.db.QueryContext(ctx, stockQueries["events"])
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var game string
		var delivered bool
		var n int64
		if err := rows.Scan(&game, &delivered, &n); err != nil {
			return err
		}
		outcome := "failed"
		if delivered {
			outcome = "delivered"
		}
		st.Events[GameValue{game, outcome}] += n
	}
	return rows.Err()
}

// addKnown adds n at game and value when value is one of known.
func addKnown(m map[GameValue]int64, game, value string, known []string, n int64) {
	if slices.Contains(known, value) {
		m[GameValue{game, value}] += n
	}
}
