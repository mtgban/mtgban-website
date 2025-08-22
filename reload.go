package main

import (
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
