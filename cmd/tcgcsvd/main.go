// Command tcgcsvd runs the tcgcsv ingestion jobs on their own, without the web
// server: the daily price pull, the weekly product catalog sync, and the
// historical backfill. It reads the same config.json the server does, uses only
// the sql_config and tcgcsv_config sections of it, and runs the two scheduled
// jobs under the same cross-process crawl lock, so it can run beside a server
// that still has its crons enabled without both crawling tcgcsv.com at once.
// The backfill stays outside that lock, as it does everywhere else: it is
// operator-driven and runs for hours, and holding the lock for that long would
// starve the daily pull. Time a long backfill so it doesn't sit on top of a
// server's 21:00 ingest.
//
//	go install github.com/mtgban/mtgban-website/cmd/tcgcsvd@latest
//
//	tcgcsvd -games                       # what we ingest, and from when
//	tcgcsvd -daily                       # today's prices for every game
//	tcgcsvd -products                    # refresh the product catalog
//	tcgcsvd -backfill                    # fill every game's history to date
//	tcgcsvd -backfill -categories 71 -from 2026-07-08 -to 2026-07-14 -force
//
// Each invocation runs one job and exits, non-zero on failure, so cron or a
// systemd timer can drive it. See the tcgcsvd package docs for what the chosen
// categories are and how a newly added game gets backfilled.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/mtgban/mtgban-website/internal/notify"
	"github.com/mtgban/mtgban-website/tcgcsv"
	"github.com/mtgban/mtgban-website/tcgcsvd"
	"github.com/mtgban/mtgban-website/timeseries"
	"github.com/mtgban/simplecloud"
)

// config is the subset of the server's config.json this service reads. Unknown
// keys are ignored, so it loads the deployment's existing file unchanged.
type config struct {
	SQLConfig        *timeseries.SQLConfig `json:"sql_config"`
	TCGCSVConfig     *tcgcsv.Config        `json:"tcgcsv_config"`
	DiscordNotifHook string                `json:"discord_notif_hook"`

	TimeseriesConfig struct {
		LongFormWrites bool `json:"long_form_writes"`
	} `json:"timeseries_config"`
}

// loadConfig reads the config from wherever the path names - a local file, a
// b2:// bucket URL, or any other scheme simplecloud.Open knows - so a droplet
// can point this at the very config.json it already deploys with (b2 needs
// BAN_CONFIG_KEY and BAN_CONFIG_SECRET in the environment). An empty path
// falls back to BAN_CONFIG_PATH.
func loadConfig(ctx context.Context, path string) (*config, error) {
	if path == "" {
		path = os.Getenv("BAN_CONFIG_PATH")
	}
	if path == "" {
		return nil, errors.New("no config path given; pass -config or set BAN_CONFIG_PATH")
	}

	reader, err := simplecloud.Open(ctx, path,
		simplecloud.WithB2Credentials(os.Getenv("BAN_CONFIG_KEY"), os.Getenv("BAN_CONFIG_SECRET")))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	var cfg config
	if err := json.NewDecoder(reader).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if cfg.SQLConfig == nil {
		return nil, fmt.Errorf("%s: no sql_config section; there is no price database to write to", path)
	}
	if cfg.TCGCSVConfig == nil || len(cfg.TCGCSVConfig.Games) == 0 {
		return nil, fmt.Errorf("%s: no tcgcsv_config.games; nothing to ingest", path)
	}
	return &cfg, nil
}

func main() {
	configPath := flag.String("config", "", "Path or b2:// URL of the server config file (default: $BAN_CONFIG_PATH)")
	games := flag.Bool("games", false, "Print the configured games and what is stored for each, then exit")
	daily := flag.Bool("daily", false, "Pull the current price snapshot for every configured game")
	products := flag.Bool("products", false, "Refresh the product catalog for every configured game")
	backfill := flag.Bool("backfill", false, "Fill prices from tcgcsv's daily archives")
	from := flag.String("from", "", "Backfill start date YYYY-MM-DD (default: earliest archive, 2024-02-08; an explicit date fetches the whole range, bypassing the resume cursor)")
	to := flag.String("to", "", "Backfill end date YYYY-MM-DD (default: today)")
	force := flag.Bool("force", false, "Re-ingest dates already stored (ignore the resume cursor)")
	categories := flag.String("categories", "", "Restrict the backfill to these TCGplayer category ids, comma-separated (default: every configured game)")
	flag.Parse()

	var chosen int
	for _, job := range []bool{*games, *daily, *products, *backfill} {
		if job {
			chosen++
		}
	}
	if chosen != 1 {
		fmt.Fprintln(os.Stderr, "tcgcsvd: pick exactly one of -games, -daily, -products, -backfill")
		flag.Usage()
		os.Exit(2)
	}

	// A backfill runs for hours; Ctrl-C or a systemd stop should end the day it
	// is on and leave what it already wrote, not be killed mid-upsert.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := loadConfig(ctx, *configPath)
	if err != nil {
		log.Fatalln("tcgcsvd:", err)
	}

	db, err := timeseries.NewClient(*cfg.SQLConfig)
	if err != nil {
		log.Fatalln("tcgcsvd: opening the price database:", err)
	}

	opts := []tcgcsvd.Option{tcgcsvd.WithLongFormWrites(cfg.TimeseriesConfig.LongFormWrites)}
	if cfg.DiscordNotifHook != "" {
		// Synchronous on purpose: a one-shot process would exit before a
		// backgrounded post ever left the machine.
		opts = append(opts, tcgcsvd.WithNotifier(func(kind, message string) {
			notify.Post(cfg.DiscordNotifHook, kind, message, false)
		}))
	}
	svc, err := tcgcsvd.New(*cfg.TCGCSVConfig, db, opts...)
	if err != nil {
		log.Fatalln("tcgcsvd:", err)
	}

	// Every job but -games writes. A read-only client makes each write a silent
	// no-op, so refuse here rather than exit 0 having stored nothing.
	if db.ReadOnly() && !*games {
		log.Fatalln("tcgcsvd: the configured price database is read-only; nothing would be written")
	}

	switch {
	case *games:
		err = printGames(ctx, svc, db)
	case *daily:
		// Under the crawl lock, so a server whose crons are still armed and this
		// process never crawl tcgcsv.com at the same time. A skipped run (the
		// other process holds the lock) is logged and exits 0.
		err = svc.WithCrawlLock(ctx, "tcgcsvd -daily", func() error { return svc.IngestLatest(ctx) })
	case *products:
		err = svc.WithCrawlLock(ctx, "tcgcsvd -products", func() error { return svc.SyncProducts(ctx) })
	case *backfill:
		// Outside the lock on purpose: hours of archives under a session
		// advisory lock would block every daily ingest for the whole run.
		err = svc.Backfill(ctx, tcgcsvd.BackfillOptions{
			From: *from, To: *to, Categories: *categories, Force: *force,
		})
	}
	if err != nil {
		log.Fatalln("tcgcsvd:", err)
	}
}

// printGames lists the chosen categories — the games we support — with the
// newest date stored for each, so an operator can see at a glance which game is
// behind and needs a backfill.
func printGames(ctx context.Context, svc *tcgcsvd.Service, db *timeseries.Client) error {
	fmt.Printf("%-24s %-8s %s\n", "GAME", "CATEGORY", "LATEST STORED")
	for _, g := range svc.Games() {
		stored := "none"
		latest, ok, err := db.GetTCGLatestDate(ctx, g.CategoryID)
		if err != nil {
			return fmt.Errorf("latest date for category %d: %w", g.CategoryID, err)
		}
		if ok {
			stored = latest.Format("2006-01-02")
		}
		fmt.Printf("%-24s %-8d %s\n", g.Name, g.CategoryID, stored)
	}
	return nil
}
