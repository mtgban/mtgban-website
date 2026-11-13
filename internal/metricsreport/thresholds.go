package metricsreport

// The report thresholds, the roadmap's starting values in one place.
const (
	rarePerThousandLoads = 1.0
	rareRequestShare     = 0.005
	rareReaderShare      = 0.01 // read by 2e's setting rows
	rareReaderDays       = 3    // read by 2e's setting rows
	minDaysMeasured      = 14
	newAfterDays         = 30
	growthFactor         = 1.5
	growthFloor          = 50
	minRateDenom         = 50 // a rate needs this many in its denominator to rank
	periodDays           = 30 // the Step every bundle query uses
	newFloor             = 20 // uses in the window before a name is called new
	digestWeekDays       = 7  // the digest's week
	minWeekDays          = 7  // flushed days each week needs before Moved most compares
	minMovePercent       = 20 // a Moved most line needs this percent change, of its rate for a rate row
	minMoveCount         = 20 // and this change in its count
	flatPercent          = 10 // a trend within this percent of the earlier figure reads flat
)

// MinDaysMeasured is the days a candidate's denominator must have rows before it is classed.
const MinDaysMeasured = minDaysMeasured

// The rare lines in uses per 1,000 of the denominator, exact, for integer comparison.
const (
	rareLoadsLine    = int64(rarePerThousandLoads)
	rareRequestsLine = int64(rareRequestShare * 1000)
)

// widerDenom names the candidates whose Denom counts a wider population than
// they are counted on, with that Denom; they are never classed rare.
var widerDenom = map[string]string{
	"api.option":          "api.call",
	"upload.option":       "upload.mode",
	"upload.price_source": "upload.mode",
}
