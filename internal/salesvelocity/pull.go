package salesvelocity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"
)

const (
	// The share of a day's rows over five orders under which its pull looks signed
	// out, when TCGplayer returns only the newest five sales of a product. Signed
	// in it has not gone below 5% in a year.
	signedInShare = 0.01
	// How old the newest sale day may be. It is under 56 hours just before the
	// next pull starts, so this means a whole day's pull did not write anything.
	pullStaleAfter = 72 * time.Hour
	// How many rows a day still being written needs before its share counts. It
	// starts below the finished day's, 3.5% at this many rows against 10%.
	judgedRows = 10000
)

// NewestSaleQuery is the newest day with a sale, across every game.
const NewestSaleQuery = `SELECT max(sale_date) FROM tcgplayersalesdata`

const saleDayQuery = `
	SELECT count(*), count(*) FILTER (WHERE num_orders > 5)
	  FROM tcgplayersalesdata
	 WHERE sale_date = $1::date`

// CheckPull says what the newspaper's latest sales pull looks like and, in
// problem, whether it looks signed out or stopped.
func CheckPull(ctx context.Context, db *sql.DB) (result, problem string) {
	var newest sql.NullTime
	err := db.QueryRowContext(ctx, NewestSaleQuery).Scan(&newest)
	if err == nil && !newest.Valid {
		err = errors.New("no sales")
	}
	if err != nil {
		log.Println("newspaper sales:", err)
		return "", "cannot read the newspaper: " + err.Error()
	}

	// The newest day may still be being written, and may have only just started.
	day := newest.Time
	rows, overFive, err := readPullDay(ctx, db, day)
	if err == nil && rows < judgedRows {
		day = day.AddDate(0, 0, -1)
		rows, overFive, err = readPullDay(ctx, db, day)
	}
	if err != nil {
		log.Println("newspaper sales:", err)
		return "", "cannot read the newspaper: " + err.Error()
	}

	return judgePull(newest.Time, day, rows, overFive, time.Now())
}

// readPullDay is day's rows and those over five orders, across every game.
func readPullDay(ctx context.Context, db *sql.DB, day time.Time) (rows, overFive int64, err error) {
	err = db.QueryRowContext(ctx, saleDayQuery, day.Format(time.DateOnly)).Scan(&rows, &overFive)
	return rows, overFive, err
}

// judgePull says what the latest pull looks like, and what is wrong
// with it: day's rows and those over five orders, and the newest sale day, as of now.
func judgePull(newest, day time.Time, rows, overFive int64, now time.Time) (result, problem string) {
	result = fmt.Sprintf("newest sale day %s; on %s, %d of %d rows over five orders",
		newest.Format(time.DateOnly), day.Format(time.DateOnly), overFive, rows)
	switch {
	case now.Sub(newest) > pullStaleAfter:
		problem = "has had no new sale day since " + newest.Format(time.DateOnly) + ": the sales pull stopped, perhaps on TCGplayer logins"
	case rows > 0 && float64(overFive) < signedInShare*float64(rows):
		problem = fmt.Sprintf("saw only %d of %d rows over five orders on %s: TCGplayer logins look expired",
			overFive, rows, day.Format(time.DateOnly))
	}
	return result, problem
}
