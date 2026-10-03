package main

import (
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/mtgban/mtgban-website/internal/alerts"
)

// devAlertAllowance stands in for an ACL entry in dev without signing.
const devAlertAllowance = 100

// allowanceFromValues reads AlertsMax off ACL values that grant the page; 0 means alerts are off.
func allowanceFromValues(v url.Values) int {
	if v.Get("Alerts") != "true" {
		return 0
	}
	n, err := strconv.Atoi(v.Get("AlertsMax"))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// alertAllowance is allowanceFromValues, with dev's stand-in when nothing is signed.
func alertAllowance(v url.Values) int {
	if DevMode && !SigCheck {
		return devAlertAllowance
	}
	return allowanceFromValues(v)
}

// devAlertChannels stands in for AlertChannels in dev without signing.
const devAlertChannels = "discord,email"

// channelsFromValues reads AlertChannels off ACL values that grant the
// page, keeping known channels once each in the order listed.
func channelsFromValues(v url.Values) []alerts.ChannelKind {
	if v.Get("Alerts") != "true" {
		return nil
	}
	// No key at all: a cookie signed before the property existed, Discord only.
	if _, found := v["AlertChannels"]; !found {
		return []alerts.ChannelKind{alerts.ChannelDiscord}
	}
	return parseAlertChannels(v.Get("AlertChannels"))
}

// parseAlertChannels reads a comma list of channel names, dropping unknown ones.
func parseAlertChannels(list string) []alerts.ChannelKind {
	var out []alerts.ChannelKind
	for _, name := range strings.Split(list, ",") {
		kind := alerts.ChannelKind(strings.ToLower(strings.TrimSpace(name)))
		if kind != alerts.ChannelDiscord && kind != alerts.ChannelEmail {
			continue
		}
		if !slices.Contains(out, kind) {
			out = append(out, kind)
		}
	}
	return out
}

// alertChannels is channelsFromValues, with dev's stand-in when nothing is
// signed, and without email while nothing can send it: the page then
// offers no channel that fails every run, and the evaluator parks what
// chose it until the key is set.
func alertChannels(v url.Values) []alerts.ChannelKind {
	out := channelsFromValues(v)
	if DevMode && !SigCheck {
		out = parseAlertChannels(devAlertChannels)
	}
	if !alertMailConfigured() {
		out = slices.DeleteFunc(out, func(k alerts.ChannelKind) bool { return k == alerts.ChannelEmail })
	}
	return out
}
