package imgmirror

import (
	"log"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// EnumerateImages maps every uuid, sealed included, to its "full" image URL,
// skipping printings with no image. A nil filter means all sets.
func EnumerateImages(setsFilter map[string]bool) map[string]Card {
	out := map[string]Card{}
	skipped := 0
	for _, uuid := range mtgmatcher.GetUUIDs() {
		co, err := mtgmatcher.GetUUID(uuid)
		if err != nil {
			continue
		}
		if setsFilter != nil && !setsFilter[co.SetCode] {
			continue
		}
		imgURL := co.Images["full"]
		if imgURL == "" {
			skipped++
			continue
		}
		out[uuid] = Card{URL: imgURL, SetCode: co.SetCode, Sealed: co.Sealed}
	}
	if skipped > 0 {
		log.Printf("skipped %d printings with no image URL", skipped)
	}
	return out
}
