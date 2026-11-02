package main

import "github.com/mtgban/go-mtgban/mtgban"

// sellersPtr, vendorsPtr and scraperIndexPtr are the tests' way of storing
// one part of the prices snapshot: each Store publishes a whole snapshot with
// that part replaced, and Load points into the published one, so a Load
// handed back to Store restores what it read. They publish without
// scrapersWriteMu, as a test may hold it, and compare-and-swap on the raw
// pointer, nil before the first publish, so two sides stored from two
// goroutines both land.
var (
	sellersPtr      sellersPoke
	vendorsPtr      vendorsPoke
	scraperIndexPtr scrapersPoke
)

type sellersPoke struct{}

func (sellersPoke) Load() *[]mtgban.Seller {
	return &currentPrices().sellers
}

func (sellersPoke) Store(sellers *[]mtgban.Seller) {
	var list []mtgban.Seller
	if sellers != nil {
		list = *sellers
	}
	for {
		old := pricesPtr.Load()
		p := currentPrices()
		if pricesPtr.CompareAndSwap(old, newPrices(list, p.vendors, p.scrapers)) {
			return
		}
	}
}

type vendorsPoke struct{}

func (vendorsPoke) Load() *[]mtgban.Vendor {
	return &currentPrices().vendors
}

func (vendorsPoke) Store(vendors *[]mtgban.Vendor) {
	var list []mtgban.Vendor
	if vendors != nil {
		list = *vendors
	}
	for {
		old := pricesPtr.Load()
		p := currentPrices()
		if pricesPtr.CompareAndSwap(old, newPrices(p.sellers, list, p.scrapers)) {
			return
		}
	}
}

type scrapersPoke struct{}

func (scrapersPoke) Load() *scraperIndex {
	return &currentPrices().scrapers
}

func (scrapersPoke) Store(scrapers *scraperIndex) {
	if scrapers == nil {
		scrapers = newScraperIndex()
	}
	for {
		old := pricesPtr.Load()
		next := *currentPrices()
		next.scrapers = *scrapers
		if pricesPtr.CompareAndSwap(old, &next) {
			return
		}
	}
}
