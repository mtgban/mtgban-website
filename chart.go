package main

import (
	"context"
	"fmt"
	"log"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
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
	if Config.TimeseriesConfig.Address == "" {
		log.Println("Timeseries address not set")
		return
	}

	start := time.Now()
	ServerNotify("timeseries", "Taking snapshot...")
	StashingInProgress = true

	for _, seller := range Sellers {
		for _, config := range Config.TimeseriesConfig.Datasets {
			if !slices.Contains(config.Retail, seller.Info().Shorthand) {
				continue
			}

			key := seller.Info().InventoryTimestamp.Format("2006-01-02")

			db := redis.NewClient(&redis.Options{
				Addr: Config.TimeseriesConfig.Address,
				DB:   config.Index,
			})

			log.Println("Stashing", seller.Info().Shorthand, "in", config.PublicName, "timeseries")

			for uuid, entries := range seller.Inventory() {
				// Adjust price through defaultGradeMap in case NM is not available
				price := entries[0].Price * defaultGradeMap[entries[0].Conditions]

				// Check if there is a specific price entry
				realRetail, found := entries[0].CustomFields["RetailPrice"]
				if entries[0].Conditions != "NM" && found {
					price, _ = strconv.ParseFloat(realRetail, 64)
				}

				// Skip empty
				if price == 0 {
					continue
				}

				err := db.HSetNX(context.Background(), uuid, key, price).Err()
				if err != nil {
					ServerNotify("timeseries", err.Error())
					break
				}
			}
		}
	}

	for _, vendor := range Vendors {
		for _, config := range Config.TimeseriesConfig.Datasets {
			if !slices.Contains(config.Buylist, vendor.Info().Shorthand) {
				continue
			}

			key := vendor.Info().BuylistTimestamp.Format("2006-01-02")

			db := redis.NewClient(&redis.Options{
				Addr: Config.TimeseriesConfig.Address,
				DB:   config.Index,
			})

			log.Println("Stashing", vendor.Info().Shorthand, "in", config.PublicName, "timeseries")

			for uuid, entries := range vendor.Buylist() {
				// Adjust price through defaultGradeMap in case NM is not available
				price := entries[0].BuyPrice * defaultGradeMap[entries[0].Conditions]
				if price == 0 {
					continue
				}

				err := db.HSetNX(context.Background(), uuid, key, price).Err()
				if err != nil {
					ServerNotify("timeseries", err.Error())
					break
				}
			}
		}
	}

	LastStashUpdate = time.Now()
	StashingInProgress = false
	ServerNotify("timeseries", "Snapshot completed in "+fmt.Sprint(time.Since(start)))
}
