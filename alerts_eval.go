package main

import (
	"log"
	"net/url"

	"github.com/mtgban/go-mtgban/mtgmatcher"

	"github.com/mtgban/mtgban-website/internal/alerts"
)

// alertEvalDeps wires the ACL, prices and the live datastore into the
// evaluator; PerRun binds them to the site's data at the start of each run.
func (s *site) alertEvalDeps() alerts.EvalDeps {
	return alerts.EvalDeps{
		Allowance: alertAllowance, StoreLabel: alertStoreLabel, Log: log.Printf,
		Report: func(summary, problem string) { backgroundJobs.Report(jobAlerts, summary, problem) },
		PerRun: func(d alerts.EvalDeps) alerts.EvalDeps {
			b := s.backend()
			// Indexed once per run rather than once per user per alert.
			idx := indexGrants(PatreonGrants())
			d.Sender = liveAlertSender(s.alertsSend)
			d.Ready = func() bool { return alertsReady(b) }
			d.Values = func(userHash, tier string) url.Values {
				return aclValuesWith(ACL(), idx, userHash, tier)
			}
			d.Prices, d.SiteURL = alertVisiblePrices, alertSiteURL()
			d.Resolve = func(cardID string) (alerts.Card, bool, bool) { return alertCardSnapshot(b, cardID) }
			d.Game = string(Config().Game)
			return d
		},
	}
}

// startAlertEvaluator runs the debounced loop when the store is configured.
func (s *site) startAlertEvaluator() {
	if s.alerts.Store() == nil {
		return
	}
	if alertSiteURL() == "" {
		log.Println("alerts: site_url is not set, DM links are omitted")
	}
	s.alerts.StartEvaluator(func(fn func()) func() { return tracked(jobAlerts, fn) })
}

// alertSideOfKind maps a dump kind to the alert side it prices.
func alertSideOfKind(kind string) (alerts.Side, bool) {
	switch kind {
	case "retail":
		return alerts.SideRetail, true
	case "buylist":
		return alerts.SideBuylist, true
	}
	return "", false
}

// pokeAlerts queues an evaluation of the sides the reloaded kinds price.
func (s *site) pokeAlerts(kinds ...string) {
	var sides []alerts.Side
	for _, kind := range kinds {
		side, ok := alertSideOfKind(kind)
		if ok {
			sides = append(sides, side)
		}
	}
	if len(sides) > 0 {
		s.alerts.RequestEvaluate(sides...)
	}
}

// alertsReady is the datastore in and at least one market side loaded.
func alertsReady(b *mtgmatcher.Backend) bool {
	return alertsReadyFrom(len(b.GetUUIDs()), len(GetSellers()), len(GetVendors()))
}

// alertsReadyFrom is alertsReady on counts, for tests.
func alertsReadyFrom(uuids, sellers, vendors int) bool {
	return uuids != 0 && (sellers != 0 || vendors != 0)
}
