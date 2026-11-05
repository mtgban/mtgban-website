package main

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
	newspaperSignedInShare = 0.01
	// How old the newest sale day may be. It is under 56 hours just before the
	// next pull starts, so this means a whole day's pull did not write anything.
	newspaperSalesStaleAfter = 72 * time.Hour
	// How many rows a day still being written needs before its share counts. It
	// starts below the finished day's, 3.5% at this many rows against 10%.
	newspaperJudgedRows = 10000
)

const newspaperNewestSaleQuery = `SELECT max(sale_date) FROM tcgplayersalesdata`

const newspaperSaleDayQuery = `
	SELECT count(*), count(*) FILTER (WHERE num_orders > 5)
	  FROM tcgplayersalesdata
	 WHERE sale_date = $1::date`

// checkNewspaperSales reports on the job's row when the newspaper's sales pull
// looks signed out or stopped, which checkJobHealth then announces.
func checkNewspaperSales() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var newest sql.NullTime
	err := NewNewspaperDB.QueryRowContext(ctx, newspaperNewestSaleQuery).Scan(&newest)
	if err == nil && !newest.Valid {
		err = errors.New("no sales")
	}
	if err != nil {
		log.Println("newspaper sales:", err)
		backgroundJobs.Report(jobNewspaperSales, "", "cannot read the newspaper: "+err.Error())
		return
	}

	// The newest day may still be being written, and may have only just started.
	day := newest.Time
	rows, overFive, err := readNewspaperSaleDay(ctx, day)
	if err == nil && rows < newspaperJudgedRows {
		day = day.AddDate(0, 0, -1)
		rows, overFive, err = readNewspaperSaleDay(ctx, day)
	}
	if err != nil {
		log.Println("newspaper sales:", err)
		backgroundJobs.Report(jobNewspaperSales, "", "cannot read the newspaper: "+err.Error())
		return
	}

	result, problem := judgeNewspaperSales(newest.Time, day, rows, overFive, time.Now())
	backgroundJobs.Report(jobNewspaperSales, result, problem)
}

// readNewspaperSaleDay is day's rows and those over five orders, across every game.
func readNewspaperSaleDay(ctx context.Context, day time.Time) (rows, overFive int64, err error) {
	err = NewNewspaperDB.QueryRowContext(ctx, newspaperSaleDayQuery, day.Format(time.DateOnly)).Scan(&rows, &overFive)
	return rows, overFive, err
}

// judgeNewspaperSales says what the latest pull looks like, and what is wrong
// with it: day's rows and those over five orders, and the newest sale day, as of now.
func judgeNewspaperSales(newest, day time.Time, rows, overFive int64, now time.Time) (result, problem string) {
	result = fmt.Sprintf("newest sale day %s; on %s, %d of %d rows over five orders",
		newest.Format(time.DateOnly), day.Format(time.DateOnly), overFive, rows)
	switch {
	case now.Sub(newest) > newspaperSalesStaleAfter:
		problem = "has had no new sale day since " + newest.Format(time.DateOnly) + ": the sales pull stopped, perhaps on TCGplayer logins"
	case rows > 0 && float64(overFive) < newspaperSignedInShare*float64(rows):
		problem = fmt.Sprintf("saw only %d of %d rows over five orders on %s: TCGplayer logins look expired",
			overFive, rows, day.Format(time.DateOnly))
	}
	return result, problem
}
