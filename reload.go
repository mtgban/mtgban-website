package main

import (
	"errors"
	"fmt"

	"github.com/mtgban/go-mtgban/mtgban"
	"golang.org/x/exp/slices"
)

func reloadCK() {
	reloadSingle("cardkingdom")
}

func reloadSCG() {
	reloadSingle("starcitygames")
}

func reloadSingle(name string) {
	defer recoverPanicScraper()

	ServerNotify("refresh", "Reloading "+name)

	// Lock because we plan to load both sides of the scraper
	ScraperOptions[name].Mutex.Lock()
	ScraperOptions[name].Busy = true
	defer func() {
		ScraperOptions[name].Busy = false
		ScraperOptions[name].Mutex.Unlock()
	}()

	scraper, err := ScraperOptions[name].Init(ScraperOptions[name].Logger)
	if err != nil {
		msg := fmt.Sprintf("error initializing %s: %s", name, err.Error())
		ServerNotify("refresh", msg, true)
		return
	}

	// These functions will update the global scraper only if it was
	// previously added to the slice of Sellers or Vendors via the
	// client Register functions
	updateSellers(scraper)
	updateVendors(scraper)

	ServerNotify("refresh", name+" refresh completed")
}

func reloadTCG() {
	reloadMarket("tcg_index")
	reloadMarket("tcg_market")

	reloadSingle("tcg_directnet")

	ServerNotify("refresh", "tcg fully refreshed")
}

func reloadMarket(name string) {
	defer recoverPanicScraper()

	ServerNotify("refresh", "Reloading "+name)

	// Lock because we plan to load both sides of the scraper
	ScraperOptions[name].Mutex.Lock()
	ScraperOptions[name].Busy = true
	defer func() {
		ScraperOptions[name].Busy = false
		ScraperOptions[name].Mutex.Unlock()
	}()

	scraper, err := ScraperOptions[name].Init(ScraperOptions[name].Logger)
	if err != nil {
		msg := fmt.Sprintf("error initializing %s: %s", name, err.Error())
		ServerNotify("refresh", msg, true)
		return
	}

	multiSellers, err := mtgban.Seller2Sellers(scraper.(mtgban.Market))
	if err != nil {
		msg := fmt.Sprintf("error separating %s: %s", name, err.Error())
		ServerNotify("refresh", msg)
		return
	}

	keepers := ScraperOptions[name].Keepers
	for i := range multiSellers {
		// Skip subsellers not explicitly enabled
		if !slices.Contains(keepers, multiSellers[i].Info().Shorthand) {
			continue
		}
		updateSellers(multiSellers[i])
	}

	// This can be done because only the already-registered scrapers
	// will be updated, no effect otherwise
	updateVendors(scraper)

	ServerNotify("refresh", name+" market refresh completed")
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
			}
			return
		}
	}
}

func updateSellerAtPosition(seller mtgban.Seller, i int, andLock bool) error {
	opts := ScraperOptions[ScraperMap[seller.Info().Shorthand]]

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
	if len(inv) == 0 {
		return errors.New("empty inventory")
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
			}
			return
		}
	}
}

func updateVendorAtPosition(vendor mtgban.Vendor, i int, andLock bool) error {
	opts := ScraperOptions[ScraperMap[vendor.Info().Shorthand]]

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
	if len(bl) == 0 {
		return errors.New("empty buylist")
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
