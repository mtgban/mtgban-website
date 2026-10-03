package main

import "testing"

// The printing picker offers only the printings the page has details for,
// so every alias a row lists has to be in the map, including the aliases of
// a row whose own card an earlier row already listed as an alias.
func TestUploadMetadataHasEveryOfferedPrinting(t *testing.T) {
	skipWithoutDatastore(t)
	uuids := backend().GetUUIDs()[:3]
	rows := []UploadEntry{
		{CardID: uuids[0], PossibleAliases: []string{uuids[0], uuids[1]}},
		{CardID: uuids[1], PossibleAliases: []string{uuids[1], uuids[2]}},
	}

	metadata := uploadMetadata(backend(), uploadSettings{}, rows)
	for _, id := range uuids {
		if _, ok := metadata[id]; !ok {
			t.Errorf("no details for %s, which a row offers", id)
		}
	}
}
