package main

import (
	"math/rand/v2"
	"slices"
	"sort"
	"testing"
)

// TestAlphabeticalSortUsesEnglishNames is the SOA case from the site: a
// search for the Japanese Mystical Archive scrolls sorted alphabetically
// has to read A-to-Z off the English names, not off whatever order the
// kanji of the printed names happen to fall in.
func TestAlphabeticalSortUsesEnglishNames(t *testing.T) {
	skipWithoutDatastore(t)
	uuids := backend().GetUUIDs()

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

	sortData := resolveSortingData(backend(), keys)
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
	skipWithoutDatastore(t)
	uuids := backend().GetUUIDs()

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

	sortData := resolveSortingData(backend(), keys)
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

func wrathOfGodKeys(t *testing.T) []string {
	t.Helper()
	skipWithoutDatastore(t)
	var keys []string
	for _, uuid := range backend().GetUUIDs() {
		co, err := backend().GetUUID(uuid)
		if err != nil || co.Name != "Wrath of God" || co.Sealed {
			continue
		}
		keys = append(keys, uuid)
	}
	if len(keys) < 2 {
		t.Skip("not enough printings of the test card")
	}
	return keys
}

// TestHybridSortFilesReprintsUnderParent checks that Alternate Fourth
// Edition and Foreign Black Border sort right after the set they reprint,
// not under A and F.
func TestHybridSortFilesReprintsUnderParent(t *testing.T) {
	keys := wrathOfGodKeys(t)
	sortData := resolveSortingData(backend(), keys)
	fileReprintsUnderParent(sortData, getReprintParents(backend()))
	sort.Slice(keys, func(i, j int) bool {
		return cmpSetsAlphabeticalSet(sortData[keys[i]], sortData[keys[j]])
	})

	var sets []string
	for _, uuid := range keys {
		code := sortData[uuid].co.SetCode
		if len(sets) == 0 || sets[len(sets)-1] != code {
			sets = append(sets, code)
		}
	}
	for want, after := range map[string]string{"4EDALT": "4ED", "4BB": "4EDALT", "FBB": "3ED"} {
		i := slices.Index(sets, want)
		if i < 1 || sets[i-1] != after {
			t.Errorf("%s does not follow %s: %v", want, after, sets)
		}
	}
}

// TestAlphabeticalSortBreaksSameDateTies checks that printings sharing a
// name, date and number (4ED, 4EDALT, 4BB) sort the same way every time.
func TestAlphabeticalSortBreaksSameDateTies(t *testing.T) {
	keys := wrathOfGodKeys(t)
	sortData := resolveSortingData(backend(), keys)
	less := func(k []string) func(i, j int) bool {
		return func(i, j int) bool {
			return cmpSetsAlphabetical(sortData[k[i]], sortData[k[j]])
		}
	}
	sort.Slice(keys, less(keys))
	rng := rand.New(rand.NewPCG(1, 2))
	for range 20 {
		shuffled := slices.Clone(keys)
		rng.Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})
		sort.Slice(shuffled, less(shuffled))
		if !slices.Equal(keys, shuffled) {
			t.Fatal("order depends on the input order")
		}
	}
}
