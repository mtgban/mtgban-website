package observability

import "strings"

// apiFamilies are the price API's path prefixes and their labels; a longer
// prefix comes before any prefix of it.
var apiFamilies = []struct{ prefix, label string }{
	{"/api/mtgban/search/", "api.v1.search"},
	{"/api/mtgban/", "api.v1"},
	{"/api/v2/search/", "api.v2.search"},
	{"/api/v2/history/", "api.v2.history"},
	{"/api/v2/newspaper/", "api.v2.newspaper"},
	{"/api/v2/", "api.v2"},
	{"/api/load/", "api.load"},
}

// APIFamily names the price API family a request path belongs to, or
// "other"; pass r.URL.Path, never the raw URL. No part of path is returned.
func APIFamily(path string) string {
	for _, f := range apiFamilies {
		if strings.HasPrefix(path, f.prefix) {
			return f.label
		}
	}
	return "other"
}

// APIFamilies returns every label APIFamily can return but "other", in a fresh slice.
func APIFamilies() []string {
	out := make([]string, 0, len(apiFamilies))
	for _, f := range apiFamilies {
		out = append(out, f.label)
	}
	return out
}
