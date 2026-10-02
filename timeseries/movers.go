package timeseries

// MoverRow is one card's price movement over the requested window.
type MoverRow struct {
	MtgjsonUUID string
	IsFoil      bool
	IsEtched    bool

	// Non-Magic rows have no mtgjson uuid; they are keyed by their
	// TCGplayer product instead (see GetMoversLong)
	TCGProductID int
	TCGSubType   string

	Current float64
	Prior   float64
}
