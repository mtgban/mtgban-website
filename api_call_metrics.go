package main

import (
	"errors"
	"net/http"
	"strings"

	"github.com/mtgban/mtgban-website/apisig"
	"github.com/mtgban/mtgban-website/observability"
)

// apiTier is a price API call's tier: the gateway's, any other verified signature's, or none.
func apiTier(email string, verified bool) (tier string, signed bool) {
	switch {
	case !verified:
		return "Any", false
	case email == apiGatewayUser:
		return "api", true
	default:
		return "api-legacy", true
	}
}

// apiDims is a price API call's dimensions, read off its signature rather than a cookie.
func apiDims(email string, verified bool) observability.Dims {
	tier, signed := apiTier(email, verified)
	return observability.Dims{Instance: observabilityInstance, Tier: tier, Device: "api", Signed: signed}
}

// withAPIDims fills r's holder with apiDims when counting is on.
func withAPIDims(r *http.Request, email string, verified bool) *http.Request {
	if FeatureCounter == nil {
		return r
	}
	return withMetricDims(r, apiDims(email, verified))
}

// apiFormat is the format a price API path asks for: json, csv or other.
func apiFormat(path string) string {
	switch {
	case strings.HasSuffix(path, ".json"):
		return "json"
	case strings.HasSuffix(path, ".csv"):
		return "csv"
	default:
		return "other"
	}
}

// apiRefusal is why the signing middleware refused a signature.
func apiRefusal(sig string, err error) string {
	switch {
	case sig == "":
		return "no_key"
	case errors.Is(err, apisig.ErrExpired):
		return "expired"
	default:
		return "bad_sig"
	}
}
