package main

import (
	"net/http"
	"slices"
	"strings"
	"time"
)

// sleepersGapPresets are the Ocean Gap pairs the page links, reference first.
var sleepersGapPresets = [][2]string{{"TCGLow", "MKMLow"}, {"TCGLow", "MKMTrend"}, {"MKMTrend", "CK"}, {"MKMTrend", "SCG"}, {"MKMTrend", "MP"}}

// sleepersRun is what one sleepers page was built with.
type sleepersRun struct {
	page, ref, target          string
	sellers, vendors, editions bool // which of the three hide cookies are not empty
	elapsed                    time.Duration
}

// sleepersFacts lists what one sleepers page was built with.
func sleepersFacts(run sleepersRun) []fact {
	facts := []fact{newFact("", "sleepers.page", run.page)}
	if run.page == "gap" {
		origin := "custom"
		if slices.Contains(sleepersGapPresets, [2]string{run.ref, run.target}) {
			origin = "preset"
		}
		facts = append(facts, newFact("", "sleepers.gap", origin),
			newFact("", "sleepers.ref", run.ref), newFact("", "sleepers.target", run.target))
	}
	for _, list := range []struct {
		on  bool
		key string
	}{{run.sellers, "sellers"}, {run.vendors, "vendors"}, {run.editions, "editions"}} {
		if list.on {
			facts = append(facts, newFact("", "sleepers.lists", list.key))
		}
	}
	if run.page != "index" {
		facts = append(facts, newFact("", "sleepers.duration", durationBucket(run.elapsed)))
	}
	return facts
}

// countSleepers reports whether a sleepers page view will be counted.
func countSleepers(r *http.Request) bool {
	return FeatureCounter != nil && isPageView(r)
}

// sleepersListKept reports whether a hide-list cookie names anything.
func sleepersListKept(cookie string) bool {
	return nonEmpty(strings.Split(cookie, ",")) > 0
}

// readSleepersRun reads the hide cookies of one sleepers page.
func readSleepersRun(page, ref, target, sellers, vendors, editions string, elapsed time.Duration) sleepersRun {
	return sleepersRun{
		page: page, ref: ref, target: target,
		sellers:  sleepersListKept(sellers),
		vendors:  sleepersListKept(vendors),
		editions: sleepersListKept(editions),
		elapsed:  elapsed,
	}
}
