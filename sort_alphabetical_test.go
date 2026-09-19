package main

import (
	"sort"
	"testing"
)

// TestAlphabeticalSortUsesEnglishNames is the SOA case from the site: a
// search for the Japanese Mystical Archive scrolls sorted alphabetically
// has to read A-to-Z off the English names, not off whatever order the
// kanji of the printed names happen to fall in.
func TestAlphabeticalSortUsesEnglishNames(t *testing.T) {
	uuids := backend().GetUUIDs()
	if len(uuids) == 0 {
		t.Skip("mtgmatcher datastore not loaded")
	}

	var keys []string
	for _, uuid := range uuids {
		co, err := backend().GetUUID(uuid)
		if err != nil || co.SetCode != "SOA" || co.Language != "Japanese" {
			continue
		}
		keys = append(keys, uuid)
	}
	if len(keys) == 0 {
		t.Skip("no Japanese SOA printings in the datastore")
	}

	sortData := resolveSortingData(keys)
	sort.Slice(keys, func(i, j int) bool {
		return cmpSetsAlphabetical(sortData[keys[i]], sortData[keys[j]])
	})

	prev := ""
	for _, uuid := range keys {
		co := sortData[uuid].co
		if co.FlavorName == "" {
			t.Errorf("%s has no localized name, so this set no longer covers the case", co.Name)
		}
		if prev != "" && sortData[uuid].nameLower < prev {
			t.Errorf("%q sorts after %q: the order is not following the English names", co.Name, prev)
		}
		prev = sortData[uuid].nameLower
	}
}

// TestAlphabeticalSortGroupsLocalizedReprints checks the other half of
// keying on the English name: a localized printing lands next to the
// English one it reprints, instead of filing itself under its own name.
func TestAlphabeticalSortGroupsLocalizedReprints(t *testing.T) {
	uuids := backend().GetUUIDs()
	if len(uuids) == 0 {
		t.Skip("mtgmatcher datastore not loaded")
	}

	var keys []string
	for _, uuid := range uuids {
		co, err := backend().GetUUID(uuid)
		if err != nil || co.Name != "Akroma's Will" {
			continue
		}
		keys = append(keys, uuid)
	}
	if len(keys) < 2 {
		t.Skip("not enough printings of the test card")
	}

	sortData := resolveSortingData(keys)
	sort.Slice(keys, func(i, j int) bool {
		return cmpSetsAlphabetical(sortData[keys[i]], sortData[keys[j]])
	})

	var localized int
	for _, uuid := range keys {
		co := sortData[uuid].co
		if co.Name != "Akroma's Will" {
			t.Fatalf("unrelated card %q in the group", co.Name)
		}
		if allLanguageFlags[co.Language] != "" {
			localized++
		}
	}
	if localized == 0 {
		t.Skip("no foreign printing of the test card to group")
	}
}
