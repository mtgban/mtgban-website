package metricsreport

import (
	"fmt"

	"github.com/mtgban/mtgban-website/observability"
)

// The trend words PreviousText gives.
const (
	TrendUp   = "up"
	TrendDown = "down"
	TrendFlat = "flat"
)

// Comparable reports whether two periods can be compared: each needs MinDaysMeasured counted days.
func Comparable(days, prevDays int) bool {
	return days >= minDaysMeasured && prevDays >= minDaysMeasured
}

// WindowDays are the days the counter flushed in the window and in the window before it.
func WindowDays(totals []observability.DayTotal, w Window) (days, prevDays int) {
	k := windowPeriods(w)
	rows := groupByName(totals)[flushName]
	return flushDays(rows, 0, k), flushDays(rows, k, 2*k)
}

// PreviousText is a row's Previous cell and its trend word, given the window's counted days
// and the window before's. Walls and failures get a trend only when both are Comparable,
// a rate row by its rates, any other row by its count per counted day; a growing row
// gets its Previous alone; any other section gets nothing. Within flatPercent the word is flat.
func PreviousText(s Signal, days, prevDays int) (text, trend string) {
	switch {
	case s.NotMeasured:
		return "", ""
	case s.Section == SectionGrowing:
		return fmt.Sprintf("%d", s.Previous), ""
	case s.Section != SectionWalls && s.Section != SectionFailures:
		return "", ""
	case prevDays == 0:
		return "the earlier period was not counted, so no trend", ""
	case prevDays < minDaysMeasured:
		return fmt.Sprintf("%d in %d counted days; the earlier period was not fully counted, so no trend", s.Previous, prevDays), ""
	case days < minDaysMeasured:
		return fmt.Sprintf("%d; this period has %d counted days, too few to compare", s.Previous, days), ""
	}
	var now, before int64
	if s.Denom > 0 {
		if s.PrevDenom < minRateDenom {
			return fmt.Sprintf("%d of %d, too few to compare rates", s.Previous, s.PrevDenom), ""
		}
		now, before = s.Count*s.PrevDenom, s.Previous*s.Denom
	} else {
		now, before = s.Count*int64(prevDays), s.Previous*int64(days)
	}
	trend = trendOf(now, before)
	if s.Denom > 0 {
		return fmt.Sprintf("%d of %d (%.1f%%), %s", s.Previous, s.PrevDenom, float64(s.Previous)*100/float64(s.PrevDenom), trend), trend
	}
	return fmt.Sprintf("%d in %d counted days, %s", s.Previous, prevDays, trend), trend
}

// trendOf words a figure against the earlier one: within flatPercent of the earlier one is flat,
// and from an earlier zero any later figure is up; both are scaled alike, so integers compare exactly.
func trendOf(now, before int64) string {
	switch diff := now - before; {
	case before == 0 && now == 0:
		return TrendFlat
	case before == 0:
		return TrendUp
	case max(diff, -diff)*100 <= flatPercent*before:
		return TrendFlat
	case diff > 0:
		return TrendUp
	}
	return TrendDown
}
