// Package siteorigin says which public origin a request reached the site
// at, behind the proxy, and whether a host is one of the site's own. It is
// what redirects, OAuth targets, absolute links and the secure flag of a
// cookie are built from, so it trusts a host only when the hostname check
// passes.
package siteorigin

import (
	"net/http"
	"strconv"
	"strings"
)

// Of returns the public origin for this request. The proxy must
// overwrite the forwarded headers before they reach the application; the
// hostname check prevents an arbitrary Host value from becoming a redirect or
// OAuth target.
func Of(r *http.Request) string {
	if r == nil {
		return ""
	}

	scheme := FirstForwarded(r.Header.Get("X-Forwarded-Proto"))
	if scheme == "" {
		scheme = "http"
		if r.TLS != nil {
			scheme = "https"
		}
	}
	if scheme != "http" && scheme != "https" {
		return ""
	}

	host := Host(r)
	if !Trusted(host) {
		return ""
	}

	return scheme + "://" + host
}

// FirstForwarded is the first value of a forwarded header, trimmed.
func FirstForwarded(value string) string {
	// The edge must strip/overwrite client-supplied values, or prepend its own
	// value. An edge that appends instead leaves the client in control of the
	// first hop, so that proxy contract must be enforced outside the app.
	if comma := strings.IndexByte(value, ','); comma >= 0 {
		value = value[:comma]
	}
	return strings.TrimSpace(value)
}

// Host is the host the request was made to: the edge's X-Forwarded-Host
// if it sent one, else the request's own, with the port if either has one.
func Host(r *http.Request) string {
	host := FirstForwarded(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = r.Host
	}
	return host
}

// Trusted reports whether a host belongs to this site: localhost in
// dev, or an mtgban.com host in production. Matched on the hostname exactly
// (dropping any :port) and by suffix rather than substring, so a spoofed
// "…mtgban.com.evil.tld" can't slip through.
func Trusted(host string) bool {
	name, ok := validHostname(FirstForwarded(host))
	if !ok {
		return false
	}
	return name == "localhost" || name == "mtgban.com" || strings.HasSuffix(name, ".mtgban.com")
}

func validHostname(host string) (string, bool) {
	if strings.Count(host, ":") == 1 {
		name, port, _ := strings.Cut(host, ":")
		if port == "" {
			return "", false
		}
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return "", false
		}
		host = name
	} else if strings.Contains(host, ":") {
		return "", false
	}

	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return "", false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return "", false
			}
		}
	}
	return host, true
}
