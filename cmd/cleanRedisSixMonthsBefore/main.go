package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
)

func main() {
	ctx := context.Background()

	// Adjust for your Redis instance
	addr := "localhost:6379"
	maxDBIndex := 10 // default Redis has 16 DBs but we use only 10

	// Calculate cutoff date (6 months and 3 days ago, to round up)
	cutoffDate := time.Now().AddDate(0, -6, -3)

	for dbIndex := 0; dbIndex <= maxDBIndex; dbIndex++ {
		rdb := redis.NewClient(&redis.Options{
			Addr:     addr,
			Password: "",
			DB:       dbIndex,
		})

		fmt.Printf("Checking DB %d...\n", dbIndex)

		// Use SCAN to iterate over all keys
		var cursor uint64
		for {
			keys, cur, err := rdb.Scan(ctx, cursor, "*", 100).Result()
			if err != nil {
				log.Fatalf("failed to scan db %d: %v", dbIndex, err)
			}

			for _, key := range keys {
				// Check if key is a hash
				keyType, err := rdb.Type(ctx, key).Result()
				if err != nil {
					fmt.Printf("Failed to get type for key %s: %v\n", key, err)
					continue
				}

				if keyType != "hash" {
					continue
				}

				// Get fields in the hash
				fields, err := rdb.HKeys(ctx, key).Result()
				if err != nil {
					fmt.Printf("Failed to get fields for hash %s: %v\n", key, err)
					continue
				}

				// Check each field for date and delete if older than cutoff
				for _, field := range fields {
					fieldDate, err := time.Parse("2006-01-02", field)
					if err != nil {
						// Not a date, skip
						continue
					}

					if fieldDate.Before(cutoffDate) {
						_, err := rdb.HDel(ctx, key, field).Result()
						if err != nil {
							fmt.Printf("Failed to delete field %s from %s: %v\n", field, key, err)
						} else {
							fmt.Printf("Deleted field %s from %s in DB %d\n", field, key, dbIndex)
						}
					}
				}
			}

			cursor = cur
			if cursor == 0 {
				break
			}
		}

		// Close the connection for the current DB
		_ = rdb.Close()
	}

	fmt.Println("Cleanup complete.")
}
