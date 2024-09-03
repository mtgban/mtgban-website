package main

import (
	"errors"
	"fmt"
	"path"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
)

func reloadCK() {
	reload("cardkingdom")
}

func reloadSCG() {
	reload("starcitygames")
}

func reloadTCG() {
	reload("tcg_index")
	reload("tcg_market")

	reload("tcg_directnet")

	ServerNotify("refresh", "tcg fully refreshed")
}

func reload(name string) {
	defer recoverPanicScraper()

	ServerNotify("refresh", "Reloading "+name)

	opt, found := ScraperOptions[name]
	if !found {
		msg := fmt.Sprintf("refresh %s not found", name)
		ServerNotify("refresh", msg, true)
		return
	}

	// Lock because we plan to load both sides of the scraper
	opt.Mutex.Lock()
	opt.Busy = true
	defer func() {
		opt.Busy = false
		opt.Mutex.Unlock()
	}()

	scraper, err := opt.Init(opt.Logger)
	if err != nil {
		msg := fmt.Sprintf("error initializing %s: %s", name, err.Error())
		ServerNotify("refresh", msg, true)
		return
	}
	if scraper.Info().Game != Config.Game {
		return
	}

	newbc := mtgban.NewClient()

	if !ScraperOptions[name].OnlyVendor {
		if len(opt.Keepers) == 0 {
			newbc.RegisterSeller(scraper)
		}
		for _, keeper := range opt.Keepers {
			newbc.RegisterMarket(scraper.(mtgban.Market), keeper)
		}
	}
	if !ScraperOptions[name].OnlySeller {
		if len(opt.KeepersBL) == 0 {
			newbc.RegisterVendor(scraper)
		}
		for _, keeper := range opt.KeepersBL {
			newbc.RegisterTrader(scraper.(mtgban.Trader), keeper)
		}
	}

	err = newbc.Load()
	if err != nil {
		msg := fmt.Sprintf("error loading new data for %s: %s", name, err.Error())
		ServerNotify("refresh", msg, true)
		return
	}

	sellers := newbc.Sellers()
	for _, seller := range sellers {
		updateSellers(seller)
	}
	vendors := newbc.Vendors()
	for _, vendor := range vendors {
		updateVendors(vendor)
	}

	ServerNotify("refresh", name+" refresh completed")
}

func updateSellers(scraper mtgban.Scraper) {
	for i := range Sellers {
		if Sellers[i] != nil && Sellers[i].Info().Shorthand == scraper.Info().Shorthand {
			err := updateSellerAtPosition(scraper.(mtgban.Seller), i, false)
			if err != nil {
				msg := fmt.Sprintf("seller %s %s - %s", scraper.Info().Name, scraper.Info().Shorthand, err.Error())
				ServerNotify("refresh", msg, true)
			} else {
				msg := fmt.Sprintf("%s inventory updated at position %d", scraper.Info().Shorthand, i)
				ServerNotify("refresh", msg)

				currentDir := path.Join(InventoryDir, fmt.Sprintf("%03d", time.Now().YearDay()))
				fname := path.Join(InventoryDir, scraper.Info().Shorthand+"-latest.json")
				dumpInventoryToFile(scraper.(mtgban.Seller), currentDir, fname)
			}
			return
		}
	}
}

func updateSellerAtPosition(seller mtgban.Seller, i int, andLock bool) error {
	opts, found := ScraperOptions[ScraperMap[seller.Info().Shorthand]]
	if !found {
		panic(fmt.Sprintf("%s not found in ScraperMap", seller.Info().Shorthand))
	}

	if andLock {
		opts.Mutex.Lock()
		opts.Busy = true
		defer func() {
			opts.Busy = false
			opts.Mutex.Unlock()
		}()
	}

	// Load inventory
	inv, err := seller.Inventory()
	if err != nil {
		return err
	}

	// Do not update in case the new inventory wasn't completely loaded
	// for example due to API problems
	if i >= 0 {
		old, _ := Sellers[i].Inventory()
		if len(inv) < len(old)/2 {
			return errors.New("new inventory is missing too many entries")
		}
	}

	// Make sure the input seller is _only_ a Seller and not anything
	// else, so that filtering works like expected
	outSeller := mtgban.NewSellerFromInventory(inv, seller.Info())

	// Save seller in global array
	if i < 0 {
		Sellers = append(Sellers, outSeller)
	} else {
		Sellers[i] = outSeller
	}

	return nil
}

func updateVendors(scraper mtgban.Scraper) {
	for i := range Vendors {
		if Vendors[i] != nil && Vendors[i].Info().Shorthand == scraper.Info().Shorthand {
			err := updateVendorAtPosition(scraper.(mtgban.Vendor), i, false)
			if err != nil {
				msg := fmt.Sprintf("vendor %s %s - %s", scraper.Info().Name, scraper.Info().Shorthand, err.Error())
				ServerNotify("refresh", msg, true)
			} else {
				msg := fmt.Sprintf("%s buylist updated at position %d", scraper.Info().Shorthand, i)
				ServerNotify("refresh", msg)

				currentDir := path.Join(BuylistDir, fmt.Sprintf("%03d", time.Now().YearDay()))
				fname := path.Join(BuylistDir, scraper.Info().Shorthand+"-latest.json")
				dumpBuylistToFile(scraper.(mtgban.Vendor), currentDir, fname)
			}
			return
		}
	}
}

func updateVendorAtPosition(vendor mtgban.Vendor, i int, andLock bool) error {
	opts, found := ScraperOptions[ScraperMap[vendor.Info().Shorthand]]
	if !found {
		panic(fmt.Sprintf("%s not found in ScraperMap", vendor.Info().Shorthand))
	}

	if andLock {
		opts.Mutex.Lock()
		opts.Busy = true
		defer func() {
			opts.Busy = false
			opts.Mutex.Unlock()
		}()
	}

	// Load buylist
	bl, err := vendor.Buylist()
	if err != nil {
		return err
	}

	// Do not update in case the new inventory wasn't completely loaded
	// for example due to API problems
	if i >= 0 {
		old, _ := Vendors[i].Buylist()
		if len(bl) < len(old)/2 {
			return errors.New("new buylist is missing too many entries")
		}
	}

	// Save vendor in global array, making sure it's _only_ a Vendor
	// and not anything esle, so that filtering works like expected
	outVendor := mtgban.NewVendorFromBuylist(bl, vendor.Info())

	// Save vendor in global array
	if i < 0 {
		Vendors = append(Vendors, outVendor)
	} else {
		Vendors[i] = outVendor
	}

	return nil
}
