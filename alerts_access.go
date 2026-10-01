package main

import (
	"net/url"
	"strconv"
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
