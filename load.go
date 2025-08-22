package main

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/Backblaze/blazer/b2"
	"github.com/dsnet/compress/bzip2"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	xzReader "github.com/xi2/xz"

	"github.com/mtgban/go-mtgban/mtgban"
)

var B2Bucket *b2.Bucket

type ScraperConfig struct {
	BucketAccessKey  string `json:"bucket_access_key"`
	BucketSecretKey  string `json:"bucket_access_secret"`
	BucketPath       string `json:"bucket_path"`
	BucketFileFormat string `json:"bucket_file_format"`

	Config map[string]map[string][]string `json:"config"`

	Icons        map[string]string `json:"icons"`
	NameOverride map[string]string `json:"name_override"`
}

func loadScrapersNG(config ScraperConfig) error {
	u, err := url.Parse(config.BucketPath)
	if err != nil {
		return err
	}

	switch u.Scheme {
	case "", "http", "https":
	case "b2":
		if B2Bucket == nil {
			client, err := b2.NewClient(context.Background(), config.BucketAccessKey, config.BucketSecretKey)
			if err != nil {
				return err
			}

			B2Bucket, err = client.Bucket(context.Background(), u.Host)
			if err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported path scheme %s", u.Scheme)
	}

	for name, scrapersConfig := range config.Config {
		for kind, list := range scrapersConfig {
			for _, shorthand := range list {
				err := loadScraper(config.BucketPath, Config.Game, name, kind, shorthand, config.BucketFileFormat)
				if err != nil {
					log.Println(err)
					continue
				}
			}
		}
	}

	ServerNotify("reload", "Server loaded")

	return nil
}

func loadScraper(path, game, name, kind, shorthand, format string) error {
	u, err := url.Parse(path)
	if err != nil {
		return err
	}

	u.Path = filepath.Join(game, name, kind, shorthand) + "." + format

	log.Println("loading", u.String())

	reader, err := loadData(u.String())
	if err != nil {
		return err
	}
	defer reader.Close()

	switch kind {
	case "retail":
		scraper, err := mtgban.ReadSellerFromJSON(reader)
		if err != nil {
			return err
		}
		updateSellers(scraper)
	case "buylist":
		scraper, err := mtgban.ReadVendorFromJSON(reader)
		if err != nil {
			return err
		}
		updateVendors(scraper)
	}

	return nil
}

func loadData(pathOpt string) (io.ReadCloser, error) {
	var reader io.ReadCloser

	u, err := url.Parse(pathOpt)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "http", "https":
		resp, err := cleanhttp.DefaultClient().Get(pathOpt)
		if err != nil {
			return nil, err
		}

		reader = resp.Body
	case "b2":
		src := strings.TrimPrefix(u.Path, "/")
		obj := B2Bucket.Object(src).NewReader(context.Background())
		obj.ConcurrentDownloads = 20

		reader = obj
	default:
		file, err := os.Open(pathOpt)
		if err != nil {
			return nil, err
		}

		reader = file
	}

	if strings.HasSuffix(pathOpt, "xz") {
		xzReader, err := xzReader.NewReader(reader, 0)
		if err != nil {
			return nil, err
		}
		reader = io.NopCloser(xzReader)
	} else if strings.HasSuffix(pathOpt, "bz2") {
		bz2Reader, err := bzip2.NewReader(reader, nil)
		if err != nil {
			return nil, err
		}
		reader = bz2Reader
	} else if strings.HasSuffix(pathOpt, "gz") {
		zipReader, err := gzip.NewReader(reader)
		if err != nil {
			return nil, err
		}
		reader = zipReader
	}

	return reader, err
}
