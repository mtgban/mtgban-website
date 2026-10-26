// Package timeseries keeps price history in Postgres and answers the
// chart and mover queries the site draws from it.
package timeseries

import "time"

// NormalizeUUID strips the suffixes mtgmatcher appends for a printing's
// finishes and for its copies, returning a clean UUID suitable for Postgres.
// A standard UUID is 36 characters; anything appended after that (e.g. _f,
// _e, _alt) is stripped.
func NormalizeUUID(uuid string) string {
	if len(uuid) > 36 {
		uuid = uuid[:36]
	}
	return uuid
}

// NormalizeLanguage treats "English" and "" as equivalent, storing both as "".
func NormalizeLanguage(lang *string) *string {
	if lang != nil && *lang == "English" {
		empty := ""
		return &empty
	}
	return lang
}

// Lookback is a number of days of history to consider.
type Lookback int

// Days returns the lookback as a day count.
func (l Lookback) Days() int {
	return int(l)
}

// Since returns the moment the lookback starts from.
func (l Lookback) Since() time.Time {
	return time.Now().AddDate(0, 0, -l.Days())
}
