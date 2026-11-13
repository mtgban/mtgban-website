package observability

import "slices"

// SharedInstance is the instance stored-state counts are written under.
const SharedInstance = "shared"

// StockGames are the games a game-scoped stock name is written under; a copy, so no caller widens the registry.
func StockGames() []string { return slices.Clone(stockGames) }

// StockPrefKeys are the PREF_KEYS of js/user-state.js, in its order; a copy, as StockGames.
func StockPrefKeys() []string { return slices.Clone(stockPrefKeys) }

// stockGames are the games a game-scoped stock name is written under.
var stockGames = []string{"magic", "lorcana", "riftbound", "onepiece", "yugioh", "fleshandblood", "pokemon", "gundam", "palworld"}

// stockPrefKeys are the PREF_KEYS of js/user-state.js, in its order.
var stockPrefKeys = []string{
	"mtgban_fav_sort", "mtgban_fav_sort_dir", "theme", "chartDateRange", "mtgban_nav_layout_v1",
	"chartReleasesLongRange", "chartCheckpointTypes", "offline_mode", "offline_stores", "offline_editions",
	"offline_img_editions", "mtgban_search_layout", "mtgban_popular_collapsed", "mtgban_store_factors",
	"mtgban_upload_presets", "mtgban_arbit_filters", "mtgban_arbit_presets", "mtgban_arbit_pins",
	"mtgban_backpack_tabs", "mtgban_backpack_sort", "mtgban_news_filters", "mtgban_upload_sort",
}

// stockEdges are the bucket edges of each bucketed stock name.
var stockEdges = map[string][]int64{
	"stock.favorites":      {1, 10, 25, 50},
	"stock.recents":        {1, 5, 10, 15},
	"stock.backpack":       {1, 10, 50, 100},
	"stock.backpack_tabs":  {1, 2, 3, 5},
	"stock.upload_presets": {1, 2, 5, 10},
	"stock.arbit_presets":  {1, 2, 5, 10},
	"stock.alerts_stores":  {1, 2, 5},
}

// stockBuckets is the enum of every label Bucket gives under name's edges.
func stockBuckets(name string) []string {
	edges := stockEdges[name]
	labels := []string{"0"}
	for _, e := range edges {
		labels = append(labels, Bucket(edges, e))
	}
	return labels
}

// BucketFor labels n under name's edges; false for a name with none.
func BucketFor(name string, n int64) (string, bool) {
	edges, ok := stockEdges[name]
	if !ok {
		return "", false
	}
	return Bucket(edges, n), true
}
