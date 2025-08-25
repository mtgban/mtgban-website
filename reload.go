package main

import (
	"errors"
	"fmt"
	"strings"

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

	ServerNotify("refresh", "tcg fully refreshed")
}

func reloadCSI() {
	reload("coolstuffinc")
}

func reloadMP() {
	reload("manapool")
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
	if !opt.TryStart() {
		return
	}
	defer func() {
		opt.Done()
	}()

	scraper, err := opt.Init(opt.Logger)
	if err != nil {
		msg := fmt.Sprintf("error initializing %s: %s", name, err.Error())
		opt.Logger.Println(msg)
		ServerNotify("refresh", msg, true)
		return
	}
	if strings.ToLower(scraper.Info().Game) != strings.ToLower(strings.TrimSuffix(Config.Game, "magic")) {
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
		opt.Logger.Println(msg)
		ServerNotify("refresh", msg, true)
		return
	}
	opt.Logger.Println("Data update successful, updating cache")

	sellers := newbc.Sellers()
	for _, seller := range sellers {
		updateSellers(seller)
	}
	vendors := newbc.Vendors()
	for _, vendor := range vendors {
		updateVendors(vendor)
	}

	opt.Logger.Println("Reload completed")
	ServerNotify("refresh", name+" refresh completed")
}

func updateSellers(scraper mtgban.Scraper) {
	sellerIndex := -1
	for i, seller := range Sellers {
		if seller != nil && seller.Info().Shorthand == scraper.Info().Shorthand {
			sellerIndex = i
			break
		}
	}

	err := updateSellerAtPosition(scraper.(mtgban.Seller), sellerIndex)
	if err != nil {
		msg := fmt.Sprintf("seller %s %s - %s", scraper.Info().Name, scraper.Info().Shorthand, err.Error())
		ServerNotify("refresh", msg, true)
		return
	}

	msg := fmt.Sprintf("%s inventory updated at position %d", scraper.Info().Shorthand, sellerIndex)
	ServerNotify("refresh", msg)

	return
}

func updateSellerAtPosition(seller mtgban.Seller, i int) error {
	// Save seller in global array
	if i < 0 {
		Sellers = append(Sellers, seller)
		return nil
	}

	// Load inventory
	inv, err := seller.Inventory()
	if err != nil {
		return err
	}

	// Do not update in case the new inventory wasn't completely loaded
	// for example due to API problems
	old, _ := Sellers[i].Inventory()
	if len(inv) > 0 && len(inv) < len(old)/2 {
		return errors.New("new inventory is missing too many entries")
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
	vendorIndex := -1
	for i, vendor := range Vendors {
		if vendor != nil && Vendors[i].Info().Shorthand == scraper.Info().Shorthand {
			vendorIndex = i
			break
		}
	}

	err := updateVendorAtPosition(scraper.(mtgban.Vendor), vendorIndex)
	if err != nil {
		msg := fmt.Sprintf("vendor %s %s - %s", scraper.Info().Name, scraper.Info().Shorthand, err.Error())
		ServerNotify("refresh", msg, true)
		return
	}

	msg := fmt.Sprintf("%s buylist updated at position %d", scraper.Info().Shorthand, vendorIndex)
	ServerNotify("refresh", msg)

	return
}

func updateVendorAtPosition(vendor mtgban.Vendor, i int) error {
	// Save vendor in global array
	if i < 0 {
		Vendors = append(Vendors, vendor)
		return nil
	}

	// Load buylist
	bl, err := vendor.Buylist()
	if err != nil {
		return err
	}

	// Do not update in case the new buylist wasn't completely loaded
	// for example due to API problems
	old, _ := Vendors[i].Buylist()
	if len(bl) > 0 && len(bl) < len(old)/2 {
		return errors.New("new buylist is missing too many entries")
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
