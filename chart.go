package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/go-redis/redis/v8"
	"golang.org/x/exp/slices"
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

// Get all the keys that will be used as x asis labels
func getDateAxisValues(cardId string) []string {
	var dates []string

	// Set the current date
	today := time.Now()

	// Set the earliest date as six months ago
	sixMonthsAgo := today.AddDate(0, -6, 0)

	// Loop from today back to six months ago
	for d := today; !d.Before(sixMonthsAgo); d = d.AddDate(0, 0, -1) {
		dates = append(dates, d.Format("2006-01-02"))
	}

	return dates
}

func getDatasets(cardId string, sealed bool, keys []string) []Dataset {
	var datasets []Dataset
	for _, config := range Config.TimeseriesConfig.Datasets {
		if sealed && !config.HasSealed {
			continue
		}
		if !sealed && config.OnlySealed {
			continue
		}

		dataset, err := getDataset(cardId, keys, config)
		if err != nil {
			log.Println(err)
			continue
		}
		datasets = append(datasets, dataset)
	}
	return datasets
}

func getDataset(cardId string, labels []string, config DatasetConfig) (Dataset, error) {
	db := redis.NewClient(&redis.Options{
		Addr: Config.TimeseriesConfig.Address,
		DB:   config.Index,
	})

	results, err := db.HGetAll(context.Background(), cardId).Result()
	if err != nil {
		return Dataset{}, err
	}

	var data []string
	var found bool
	if len(results) > 0 {
		// Fill in missing points with NaNs so that the values
		// can be mapped consistently on the chart
		data = make([]string, len(labels))
		for i := range labels {
			data[i], found = results[labels[i]]
			if !found {
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

func deleteEntry(cardId, dataset, key string) error {
	var db *redis.Client
	for _, config := range Config.TimeseriesConfig.Datasets {
		if config.PublicName != dataset {
			continue
		}
		db = redis.NewClient(&redis.Options{
			Addr: Config.TimeseriesConfig.Address,
			DB:   config.Index,
		})
		break
	}
	if db == nil {
		return errors.New("redis database not found")
	}

	return db.HDel(context.Background(), cardId, key).Err()
}

// A default scale for converting non-NM prices to NM
var defaultGradeMap = map[string]float64{
	"NM": 1, "SP": 1.25, "MP": 1.67, "HP": 2.5, "PO": 4,
}

func stashInTimeseries() {
	if Config.TimeseriesConfig.Address == "" {
		log.Println("Timeseries address not set")
		return
	}

	start := time.Now()
	ServerNotify("timeseries", "Taking snapshot...")

	for _, seller := range Sellers {
		if seller == nil {
			continue
		}
		for _, config := range Config.TimeseriesConfig.Datasets {
			if !slices.Contains(config.Retail, seller.Info().Shorthand) {
				continue
			}

			inv, err := seller.Inventory()
			if err != nil {
				continue
			}
			key := seller.Info().InventoryTimestamp.Format("2006-01-02")

			db := redis.NewClient(&redis.Options{
				Addr: Config.TimeseriesConfig.Address,
				DB:   config.Index,
			})

			log.Println("Stashing", seller.Info().Shorthand, "in", config.PublicName, "timeseries")

			for uuid, entries := range inv {
				// Adjust price through defaultGradeMap in case NM is not available
				price := entries[0].Price * defaultGradeMap[entries[0].Conditions]
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
		if vendor == nil {
			continue
		}
		for _, config := range Config.TimeseriesConfig.Datasets {
			if !slices.Contains(config.Buylist, vendor.Info().Shorthand) {
				continue
			}

			inv, err := vendor.Buylist()
			if err != nil {
				continue
			}
			key := vendor.Info().BuylistTimestamp.Format("2006-01-02")

			db := redis.NewClient(&redis.Options{
				Addr: Config.TimeseriesConfig.Address,
				DB:   config.Index,
			})

			log.Println("Stashing", vendor.Info().Shorthand, "in", config.PublicName, "timeseries")

			for uuid, entries := range inv {
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
	ServerNotify("timeseries", "Snapshot completed in "+fmt.Sprint(time.Since(start)))
}
