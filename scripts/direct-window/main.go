// Measures which trailing window of Direct prices best stands in for a
// precon SYP card's missing Direct price, from the newspaper's listings.
//
//	go run ./scripts/direct-window -config ../config.json -datastore allprintings5.json -syp syp.txt
//
// syp.txt lists one card uuid per line, the SYP list as the site loads it
// (dump the SYP vendor's uuids from a dev server, see the README).
package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	_ "github.com/mtgban/go-mtgban/mtgmatcher/games"
	"github.com/mtgban/go-mtgban/mtgmatcher/sealed"
)

type conn struct {
	Host, User, Password, DBName, SSLMode string
	Port                                  int
}

func main() {
	configPath := flag.String("config", "config.json", "site config with new_newspaper_sql_config")
	dsPath := flag.String("datastore", "allprintings5.json", "the Magic datastore")
	sypPath := flag.String("syp", "syp.txt", "one SYP card uuid per line")
	flag.Parse()

	var cfg map[string]json.RawMessage
	f, err := os.Open(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		log.Fatal(err)
	}
	var c conn
	if err := json.Unmarshal(cfg["new_newspaper_sql_config"], &c); err != nil {
		log.Fatal(err)
	}
	db, err := sql.Open("postgres", fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.DBName, c.SSLMode))
	if err != nil {
		log.Fatal(err)
	}

	ds, err := os.Open(*dsPath)
	if err != nil {
		log.Fatal(err)
	}
	b, err := mtgmatcher.Open(mtgmatcher.GameMagic, ds)
	if err != nil {
		log.Fatal(err)
	}

	syp := map[string]bool{}
	raw, err := os.ReadFile(*sypPath)
	if err != nil {
		log.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			syp[line] = true
		}
	}

	// Every SYP card a precon holds, with the TCGplayer product and
	// printing its listings are filed under.
	type printing struct {
		product  int64
		printing string
	}
	cards := map[string]printing{}
	precons, skipped := 0, 0
	for _, code := range b.GetAllSets() {
		set, err := b.GetSet(code)
		if err != nil {
			continue
		}
		for _, product := range set.SealedProduct {
			if len(product.Contents["deck"]) == 0 || !sealed.HasDecklist(b, code, product.UUID) {
				continue
			}
			uuids, err := sealed.ProductDecklist(b, code, product.UUID)
			if err != nil {
				continue
			}
			precons++
			for _, uuid := range uuids {
				if !syp[uuid] {
					continue
				}
				co, err := b.GetUUID(uuid)
				if err != nil {
					continue
				}
				pid, err := strconv.ParseInt(co.Identifiers["tcgplayerProductId"], 10, 64)
				if err != nil {
					skipped++
					continue
				}
				p := printing{product: pid, printing: "Normal"}
				if co.Foil {
					p.printing = "Foil"
				}
				cards[uuid] = p
			}
		}
	}
	fmt.Printf("precons with a decklist: %d, SYP cards in them: %d, skipped without a product id: %d\n", precons, len(cards), skipped)

	// The lowest Direct NM listing per product, printing and day over the
	// newspaper's rolling window, the way the TCGDirect scraper prices.
	rows, err := db.Query(`
		SELECT l.product_id, l.printing, l.date, MIN(l.price)
		  FROM tcgplayersellerproductlistingmodel l
		 WHERE l.direct_inventory > 0 AND l.condition = 'Near Mint'
		 GROUP BY 1, 2, 3`)
	if err != nil {
		log.Fatal(err)
	}
	type series map[string]float64 // date -> price
	history := map[printing]series{}
	days := map[string]bool{}
	for rows.Next() {
		var p printing
		var day time.Time
		var price float64
		if err := rows.Scan(&p.product, &p.printing, &day, &price); err != nil {
			log.Fatal(err)
		}
		d := day.Format("2006-01-02")
		days[d] = true
		if history[p] == nil {
			history[p] = series{}
		}
		history[p][d] = price
	}
	rows.Close()
	var dayList []string
	for d := range days {
		dayList = append(dayList, d)
	}
	sort.Strings(dayList)
	if len(dayList) < 4 {
		log.Fatalf("only %d days of listings, need at least 4", len(dayList))
	}
	today := dayList[len(dayList)-1]
	fmt.Printf("listings: %d days ending on the newest day, today = the newest\n", len(dayList))

	// Trailing averages excluding today, per window and sample floor.
	windows := []int{3, 7}
	type stat struct {
		errors   []float64 // absolute percentage errors on cards priced today
		covered  int       // unpriced-today cards the window holds something for
		unpriced int
	}
	stats := map[string]*stat{}
	key := func(w, floor int) string { return fmt.Sprintf("%dd floor %d", w, floor) }
	for _, w := range windows {
		for _, floor := range []int{1, 2} {
			stats[key(w, floor)] = &stat{}
		}
	}
	for _, p := range cards {
		s := history[p]
		todayPrice, pricedToday := s[today]
		for _, w := range windows {
			var sum float64
			var n int
			for i := 1; i <= w && len(dayList)-1-i >= 0; i++ {
				if v, ok := s[dayList[len(dayList)-1-i]]; ok {
					sum += v
					n++
				}
			}
			for _, floor := range []int{1, 2} {
				st := stats[key(w, floor)]
				if pricedToday {
					if n >= floor {
						st.errors = append(st.errors, math.Abs(sum/float64(n)-todayPrice)/todayPrice*100)
					}
				} else {
					st.unpriced++
					if n >= floor {
						st.covered++
					}
				}
			}
		}
	}

	fmt.Println()
	fmt.Println("| window | priced today, predicted | median APE | mean APE | within 10% | unpriced today | covered |")
	fmt.Println("|---|---|---|---|---|---|---|")
	for _, w := range windows {
		for _, floor := range []int{1, 2} {
			st := stats[key(w, floor)]
			sort.Float64s(st.errors)
			n := len(st.errors)
			median, mean, within := 0.0, 0.0, 0
			if n > 0 {
				median = st.errors[n/2]
				for _, e := range st.errors {
					mean += e
					if e <= 10 {
						within++
					}
				}
				mean /= float64(n)
			}
			fmt.Printf("| %s | %d | %.1f%% | %.1f%% | %.0f%% | %d | %d |\n",
				key(w, floor), n, median, mean, 100*float64(within)/math.Max(1, float64(n)), st.unpriced, st.covered)
		}
	}
}
