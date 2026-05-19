package main

import (
	"context"
	"fmt"
	"log"
	"slices"
	"strconv"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/timeseries"
)

type TimeseriesConfig struct {
	Address  string          `json:"address"`
	Datasets []DatasetConfig `json:"datasets"`
}

type DatasetConfig struct {
	Retail     []string `json:"retail,omitempty"`
	Buylist    []string `json:"buylist,omitempty"`
	PublicName string   `json:"public_name"`
	Index      int      `json:"index"`
	Color      string   `json:"color"`
	HasSealed  bool     `json:"has_sealed,omitempty"`
	OnlySealed bool     `json:"only_sealed,omitempty"`
}

type Dataset struct {
	Name   string
	Data   []string
	Color  string
	AxisID string
	Sealed bool
}

// getDateAxisValues generates daily date labels from today back to earliest.
func getDateAxisValues(earliest time.Time) []string {
	var dates []string
	today := time.Now()
	for d := today; !d.Before(earliest); d = d.AddDate(0, 0, -1) {
		dates = append(dates, d.Format("2006-01-02"))
	}
	return dates
}

func lookbackForTier(tier string) timeseries.Lookback {
	switch tier {
	case "Vintage":
		return timeseries.LookbackVintage
	case "Legacy":
		return timeseries.LookbackLegacy
	case "Modern":
		return timeseries.LookbackModern
	default:
		return timeseries.LookbackStandard
	}
}

// getDatasets returns one Dataset per applicable config. All datasets for a
// given card read different columns from the same (uuid, foil, etched,
// language=nil, lookback) result set, so we fetch HGetAll exactly once and
// fan the rows out to every per-dataset render rather than firing N
// identical SQL queries (and discarding 15/16 of each result).
func getDatasets(cardId string, sealed bool, keys []string, userTier string) []Dataset {
	if PricesArchiveDB == nil {
		return nil
	}

	// Pre-filter applicable configs so we don't pay for a DB round-trip
	// or a UUID lookup when nothing will render.
	var configs []DatasetConfig
	for _, c := range Config.TimeseriesConfig.Datasets {
		if sealed && !c.HasSealed {
			continue
		}
		if !sealed && c.OnlySealed {
			continue
		}
		configs = append(configs, c)
	}
	if len(configs) == 0 {
		return nil
	}

	co, err := mtgmatcher.GetUUID(cardId)
	if err != nil {
		log.Println(err)
		return nil
	}

	results, err := PricesArchiveDB.HGetAll(context.Background(), co.UUID, co.Foil, co.Etched, nil, lookbackForTier(userTier))
	if err != nil {
		log.Println(err)
		return nil
	}

	datasets := make([]Dataset, 0, len(configs))
	for _, config := range configs {
		datasets = append(datasets, buildDataset(results, keys, config))
	}
	return datasets
}

// buildDataset projects a single column out of the shared HGetAll result
// map. Missing dates and null prices both render as Number.NaN so the
// front-end chart leaves a gap rather than drawing a zero.
func buildDataset(results map[string]timeseries.PriceRow, labels []string, config DatasetConfig) Dataset {
	var data []string
	if len(results) > 0 {
		data = make([]string, len(labels))
		for i, label := range labels {
			if row, ok := results[label]; ok {
				price := row.PriceForDataset(config.Index)
				if price != nil {
					data[i] = fmt.Sprintf("%g", *price)
				} else {
					data[i] = "Number.NaN"
				}
			} else {
				data[i] = "Number.NaN"
			}
		}
	}
	return Dataset{
		Name:  config.PublicName,
		Data:  data,
		Color: config.Color,
	}
}

// A default scale for converting non-NM prices to NM
var defaultGradeMap = map[string]float64{
	"NM": 1, "SP": 1.25, "MP": 1.67, "HP": 2.5, "PO": 4,
}

// snapshotDate returns now's date when ts falls on "today" or "tomorrow"
// relative to now, otherwise ts's own calendar date. Scrapers that straddle
// midnight (or run slightly ahead of the server clock) get collapsed onto
// today's row so the COALESCE merge in UpsertRows can fold their columns
// together, while genuinely stale scrapes keep their true observation date.
func snapshotDate(ts time.Time, now time.Time) string {
	today := now.Format("2006-01-02")
	tomorrow := now.AddDate(0, 0, 1).Format("2006-01-02")
	tsDay := ts.In(now.Location()).Format("2006-01-02")
	if tsDay == today || tsDay == tomorrow {
		return today
	}
	return tsDay
}

// getRow returns the accumulator row for a card variant, creating it if
// needed. The dedup key must match the Postgres unique index on
// product_prices: (date, mtgjson_uuid, is_foil, is_etched, language, is_alt).
// Without NormalizeUUID + isAlt, two distinct mtgmatcher UUIDs (e.g. a base
// and its "_alt" sibling) collapse into the same conflict bucket on insert
// and Postgres rejects the whole batch.
func getRow(accumulated map[string]*timeseries.PriceRow, uuid string, isFoil bool, isEtched bool, isAlt bool, language string, date string) *timeseries.PriceRow {
	uuid = timeseries.NormalizeUUID(uuid)
	key := date + "|" + uuid + "|" + strconv.FormatBool(isFoil) + "|" + strconv.FormatBool(isEtched) + "|" + strconv.FormatBool(isAlt) + "|" + language
	row, ok := accumulated[key]
	if !ok {
		row = &timeseries.PriceRow{
			Date:        date,
			MtgjsonUUID: uuid,
			IsFoil:      isFoil,
			IsEtched:    isEtched,
			IsAlt:       isAlt,
			Language:    &language,
		}
		accumulated[key] = row
	}
	return row
}

var StashingInProgress bool

func stashInTimeseries() {
	if PricesArchiveDB == nil {
		log.Println("PricesArchiveDB not initialized, skipping stash")
		return
	}

	start := time.Now()
	ServerNotify("timeseries", "Taking snapshot...")
	StashingInProgress = true

	// Accumulate all prices into a single row per (date, uuid, foil, etched).
	accumulated := map[string]*timeseries.PriceRow{}

	// Collect retail prices from sellers
	for _, seller := range Sellers {
		for _, config := range Config.TimeseriesConfig.Datasets {
			if !slices.Contains(config.Retail, seller.Info().Shorthand) {
				continue
			}

			date := snapshotDate(*seller.Info().InventoryTimestamp, start)
			log.Println("Stashing", seller.Info().Shorthand, "in", config.PublicName, "timeseries")

			for id, entries := range seller.Inventory() {
				price := entries[0].Price * defaultGradeMap[entries[0].Conditions]

				// Check if there is a specific price entry
				realRetail, found := entries[0].CustomFields["RetailPrice"]
				if entries[0].Conditions != "NM" && found {
					price, _ = strconv.ParseFloat(realRetail, 64)
				}

				if price == 0 {
					continue
				}

				card, err := mtgmatcher.GetUUID(id)
				if err != nil {
					log.Println("Error getting card for", id, err)
					continue
				}

				row := getRow(accumulated, card.UUID, card.Foil, card.Etched, card.IsAlternative, card.Language, date)
				row.SetPriceForDataset(config.Index, price)
			}
		}
	}

	// Collect buylist prices from vendors
	for _, vendor := range Vendors {
		for _, config := range Config.TimeseriesConfig.Datasets {
			if !slices.Contains(config.Buylist, vendor.Info().Shorthand) {
				continue
			}

			date := snapshotDate(*vendor.Info().BuylistTimestamp, start)
			log.Println("Stashing", vendor.Info().Shorthand, "in", config.PublicName, "timeseries")

			for id, entries := range vendor.Buylist() {
				price := entries[0].BuyPrice * defaultGradeMap[entries[0].Conditions]
				if price == 0 {
					continue
				}

				card, err := mtgmatcher.GetUUID(id)
				if err != nil {
					log.Println("Error getting card for", id, err)
					continue
				}

				row := getRow(accumulated, card.UUID, card.Foil, card.Etched, card.IsAlternative, card.Language, date)
				row.SetPriceForDataset(config.Index, price)
			}
		}
	}

	// Upsert all accumulated rows in batches
	rows := make([]timeseries.PriceRow, 0, len(accumulated))
	for _, row := range accumulated {
		rows = append(rows, *row)
	}

	upserted, err := PricesArchiveDB.UpsertRows(context.Background(), rows, 500)
	var errCount int
	if err != nil {
		errCount = len(rows) - upserted
		ServerNotify("timeseries", fmt.Sprintf("batch upsert error: %s", err))
	}

	LastStashUpdate = time.Now()
	StashingInProgress = false
	msg := fmt.Sprintf("Snapshot completed in %s: %d upserted, %d errors", time.Since(start), upserted, errCount)
	ServerNotify("timeseries", msg)
}
