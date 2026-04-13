package main

import (
	"context"
	"fmt"
	"log"
	"slices"
	"strconv"
	"strings"
	"time"

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

func getDatasets(cardId string, sealed bool, keys []string, userTier string) []Dataset {
	var datasets []Dataset
	for _, config := range Config.TimeseriesConfig.Datasets {
		if sealed && !config.HasSealed {
			continue
		}
		if !sealed && config.OnlySealed {
			continue
		}

		dataset, err := getDataset(cardId, keys, config, userTier)
		if err != nil {
			log.Println(err)
			continue
		}
		datasets = append(datasets, dataset)
	}
	return datasets
}

func getDataset(cardId string, labels []string, config DatasetConfig, userTier string) (Dataset, error) {
	if PricesArchiveDB == nil {
		return Dataset{}, nil
	}

	isFoil := strings.HasSuffix(cardId, "_f")
	if isFoil {
		cardId = strings.TrimSuffix(cardId, "_f")
	}

	results, err := PricesArchiveDB.HGetAll(context.Background(), cardId, isFoil, nil, lookbackForTier(userTier))
	if err != nil {
		return Dataset{}, err
	}

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
	}, nil
}

// A default scale for converting non-NM prices to NM
var defaultGradeMap = map[string]float64{
	"NM": 1, "SP": 1.25, "MP": 1.67, "HP": 2.5, "PO": 4,
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

	// Accumulate all prices into a single row per (date, uuid, foil).
	accumulated := map[string]*timeseries.PriceRow{}

	getRow := func(uuid string, isFoil bool, date string) *timeseries.PriceRow {
		key := date + "|" + uuid
		if isFoil {
			key += "_f"
		}
		row, ok := accumulated[key]
		if !ok {
			lang := ""
			row = &timeseries.PriceRow{
				Date:        date,
				MtgjsonUUID: uuid,
				IsFoil:      isFoil,
				Language:    &lang,
			}
			accumulated[key] = row
		}
		return row
	}

	// parseFoil strips the _f suffix and returns the clean UUID + foil flag
	parseFoil := func(id string) (string, bool) {
		if strings.HasSuffix(id, "_f") {
			return strings.TrimSuffix(id, "_f"), true
		}
		return id, false
	}

	// Collect retail prices from sellers
	for _, seller := range Sellers {
		for _, config := range Config.TimeseriesConfig.Datasets {
			if !slices.Contains(config.Retail, seller.Info().Shorthand) {
				continue
			}

			date := seller.Info().InventoryTimestamp.Format("2006-01-02")
			log.Println("Stashing", seller.Info().Shorthand, "in", config.PublicName, "timeseries")

			for id, entries := range seller.Inventory() {
				price := entries[0].Price * defaultGradeMap[entries[0].Conditions]

				realRetail, found := entries[0].CustomFields["RetailPrice"]
				if entries[0].Conditions != "NM" && found {
					price, _ = strconv.ParseFloat(realRetail, 64)
				}

				if price == 0 {
					continue
				}

				uuid, isFoil := parseFoil(id)
				row := getRow(uuid, isFoil, date)
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

			date := vendor.Info().BuylistTimestamp.Format("2006-01-02")
			log.Println("Stashing", vendor.Info().Shorthand, "in", config.PublicName, "timeseries")

			for id, entries := range vendor.Buylist() {
				price := entries[0].BuyPrice * defaultGradeMap[entries[0].Conditions]
				if price == 0 {
					continue
				}

				uuid, isFoil := parseFoil(id)
				row := getRow(uuid, isFoil, date)
				row.SetPriceForDataset(config.Index, price)
			}
		}
	}

	// Upsert all accumulated rows
	var upserted, errCount int
	for _, row := range accumulated {
		err := PricesArchiveDB.UpsertRow(context.Background(), *row)
		if err != nil {
			errCount++
			if errCount <= 5 {
				ServerNotify("timeseries", fmt.Sprintf("upsert error for %s: %s", row.MtgjsonUUID, err))
			}
			continue
		}
		upserted++
	}

	LastStashUpdate = time.Now()
	StashingInProgress = false
	msg := fmt.Sprintf("Snapshot completed in %s: %d upserted, %d errors", time.Since(start), upserted, errCount)
	ServerNotify("timeseries", msg)
}
