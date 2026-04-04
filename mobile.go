package main

import (
	"net/http"

	"github.com/mileusna/useragent"
)

// isMobileRequest returns true if the request comes from a mobile or tablet device.
func isMobileRequest(r *http.Request) bool {
	ua := useragent.Parse(r.UserAgent())
	return ua.Mobile || ua.Tablet
}
