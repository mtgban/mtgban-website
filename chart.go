package main

import (
	"context"
	"errors"
	"time"

	"github.com/go-redis/redis/v8"
)

type Dataset struct {
	Name   string
	Data   []string
	Color  string
	AxisID string
	Hidden bool
	Sealed bool
}

type scraperConfig struct {
	PublicName  string
	ScraperName string
	KindName    string
	Color       string
	Hidden      bool
	HasSealed   bool
	OnlySealed  bool
}

/*
	red: 'rgb(255, 99, 132)'
	orange: 'rgb(255, 159, 64)'
	yellow: 'rgb(255, 205, 86)'
	green: 'rgb(75, 192, 192)'
	blue: 'rgb(54, 162, 235)'
	purple: 'rgb(153, 102, 255)'
	grey: 'rgb(201, 203, 207)'
	darkblue: 'rgb(23,42,72)'
*/

var enabledDatasets = []scraperConfig{
	{
		PublicName:  "TCGplayer Low",
		ScraperName: "tcg_index",
		KindName:    "TCGLow",
		Color:       "rgb(255, 99, 132)",
		HasSealed:   true,
	},
	{
		PublicName:  "TCGplayer Market",
		ScraperName: "tcg_index",
		KindName:    "TCGMarket",
		Color:       "rgb(255, 159, 64)",
		Hidden:      true,
	},
	{
		PublicName:  "Card Kingdom Retail",
		ScraperName: "cardkingdom",
		KindName:    "retail",
		Color:       "rgb(162, 235, 54)",
		HasSealed:   true,
	},
	{
		PublicName:  "Card Kingdom Buylist",
		ScraperName: "cardkingdom",
		KindName:    "buylist",
		Color:       "rgb(54, 162, 235)",
		HasSealed:   true,
	},
	{
		PublicName:  "Cardmarket Low",
		ScraperName: "cardmarket",
		KindName:    "MKMLow",
		Color:       "rgb(235, 205, 86)",
		HasSealed:   true,
	},
	{
		PublicName:  "Cardmarket Trend",
		ScraperName: "cardmarket",
		KindName:    "MKMTrend",
		Color:       "rgb(201, 203, 207)",
		Hidden:      true,
	},
	{
		PublicName:  "Star City Games Buylist",
		ScraperName: "starcitygames",
		KindName:    "buylist",
		Color:       "rgb(23,42,72)",
	},
	{
		PublicName:  "ABU Games Buylist",
		ScraperName: "abugames",
		KindName:    "ABUGames",
		Color:       "rgb(153, 102, 255)",
	},
	{
		PublicName:  "Sealed EV (TCG Low)",
		ScraperName: "sealed_ev",
		KindName:    "TCGLowEV",
		Color:       "rgb(201, 203, 207)",
		HasSealed:   true,
		OnlySealed:  true,
	},
	{
		PublicName:  "Cool Stuff Inc Buylist",
		ScraperName: "coolstuffinc",
		KindName:    "buylist",
		Color:       "rgb(124, 211, 224)",
	},
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

func getDataset(cardId string, labels []string, config scraperConfig) (*Dataset, error) {
	db, found := ScraperOptions[config.ScraperName].RDBs[config.KindName]
	if !found {
		return nil, errors.New("redis database not found")
	}
	results, err := db.HGetAll(context.Background(), cardId).Result()
	if err != nil {
		return nil, err
	}

	var data []string
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

	return &Dataset{
		Name:   config.PublicName,
		Data:   data,
		Color:  config.Color,
		Hidden: config.Hidden,
	}, nil
}

func deleteEntry(cardId, dataset, key string) error {
	var db *redis.Client
	for _, config := range enabledDatasets {
		if config.PublicName == dataset {
			db = ScraperOptions[config.ScraperName].RDBs[config.KindName]
			break
		}
	}
	if db == nil {
		return errors.New("redis database not found")
	}

	return db.HDel(context.Background(), cardId, key).Err()
}
