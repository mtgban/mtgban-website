package main

import (
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// publishCSIShelf installs a Cool Stuff Inc shelf as the site's sellers for
// the duration of a test, and puts the snapshot back afterwards.
func publishCSIShelf(t *testing.T, shorthand string, inventory mtgban.InventoryRecord) {
	t.Helper()

	prev := sellersPtr.Load()
	t.Cleanup(func() { sellersPtr.Store(prev) })

	sellers := []mtgban.Seller{mtgban.NewSellerFromInventory(
		inventory, mtgban.ScraperInfo{Name: "Cool Stuff Inc", Shorthand: shorthand})}
	sellersPtr.Store(&sellers)
}

// checkForLinksResult asks the bot what it would answer a message with, and
// fails the test where it would answer nothing: whatever the title says, the
// affiliate link is the thing the bot exists to add.
//
// The single call site is deliberate - it is the one place these tests touch
// checkForLinks, so its shape is a line to change rather than a search.
func checkForLinksResult(t *testing.T, message string) (string, string) {
	t.Helper()

	title, link := checkForLinks(discordGuildID(), message)
	if title == "" || link == "" {
		t.Fatalf("the affiliate link itself went missing: title=%q link=%q", title, link)
	}
	return title, link
}

// A Cool Stuff Inc link carries the storefront's own product id and nothing
// else - no name, no set, no number - so reading the path as a name had the
// bot announce the id: "1435 at Cool Stuff Inc". The id is answered from the
// inventory that prices it, which is the only thing that knows it.
func TestCoolstuffincTitleNamesTheCardItPrices(t *testing.T) {
	uuid := randomUUID(false)
	if uuid == "" {
		t.Skip("no datastore loaded")
	}
	co, err := backend().GetUUID(uuid)
	if err != nil {
		t.Fatalf("a single: %v", err)
	}

	const pid = "1435"

	// The two shapes the scrapers publish: the singles shelves fill the
	// field meant for the id, and the sealed shelf's Magic path stamps only
	// the link. Magic is the game the bot reads links for, so a title that
	// worked for one shape and not the other would be half a fix.
	for _, tt := range []struct {
		name  string
		entry *mtgban.InventoryEntry
	}{
		{"the id in the field meant for it", &mtgban.InventoryEntry{
			OriginalID: pid,
			URL:        "https://www.coolstuffinc.com/p/" + pid,
			Price:      1,
		}},
		{"the id in the link alone", &mtgban.InventoryEntry{
			URL:   "https://coolstuffinc.com/p/" + pid,
			Price: 1,
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			inventory := mtgban.InventoryRecord{}
			inventory.Add(uuid, tt.entry)
			publishCSIShelf(t, "CSI", inventory)

			title, link := checkForLinksResult(t, "https://www.coolstuffinc.com/p/"+pid)

			if !strings.HasPrefix(title, co.Name) {
				t.Errorf("titled %q, want it to name %s", title, co.Name)
			}
			if !strings.HasSuffix(title, " at Cool Stuff Inc") {
				t.Errorf("titled %q, want it to credit the store", title)
			}
			if strings.HasPrefix(title, pid) {
				t.Errorf("titled %q, which is the product id the fix is about", title)
			}
			if !strings.Contains(link, "/p/"+pid) {
				t.Errorf("linked to %q, want the product that was posted", link)
			}
		})
	}
}

// An id nothing prices is answered with the same fallback every other store
// uses, rather than with the number - and the affiliate link itself, which is
// what the bot exists to add, is still handed over.
func TestCoolstuffincTitleFallsBackRatherThanNamingTheID(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	uuid := randomUUID(false)
	inventory := mtgban.InventoryRecord{}
	inventory.Add(uuid, &mtgban.InventoryEntry{
		OriginalID: "1435",
		URL:        "https://www.coolstuffinc.com/p/1435",
		Price:      1,
	})
	publishCSIShelf(t, "CSI", inventory)

	// A product the shelf does not price: an accessory, a case, a card that
	// has since sold out.
	const missing = "999999999"
	title, link := checkForLinksResult(t, "https://www.coolstuffinc.com/p/"+missing)

	if title != "Your search at Cool Stuff Inc" {
		t.Errorf("titled %q, want the fallback every other store uses", title)
	}
	if !strings.Contains(link, "/p/"+missing) {
		t.Errorf("linked to %q, want the product that was posted", link)
	}
}

// Two printings under one product id name neither, so the title falls back
// rather than picking whichever the walk reached first.
func TestCoolstuffincTitleNamesNothingWhenTheIDIsShared(t *testing.T) {
	uuids := backend().GetUUIDs()
	if len(uuids) < 2 {
		t.Skip("no datastore loaded")
	}

	const pid = "1435"
	inventory := mtgban.InventoryRecord{}
	for _, uuid := range distinctPrintings(t, 2) {
		inventory.Add(uuid, &mtgban.InventoryEntry{OriginalID: pid, Price: 1})
	}
	publishCSIShelf(t, "CSI", inventory)

	title, _ := checkForLinksResult(t, "https://www.coolstuffinc.com/p/"+pid)
	if title != "Your search at Cool Stuff Inc" {
		t.Errorf("titled %q, want the fallback: the id names two cards", title)
	}
}

// distinctPrintings answers with uuids naming different cards, which is what
// a shared id has to hold to be a disagreement rather than two finishes of
// the one printing.
func distinctPrintings(t *testing.T, want int) []string {
	t.Helper()

	var found []string
	names := map[string]bool{}
	for _, uuid := range backend().GetUUIDs() {
		co, err := backend().GetUUID(uuid)
		if err != nil || co.Sealed || names[co.Name] {
			continue
		}
		names[co.Name] = true
		found = append(found, uuid)
		if len(found) == want {
			return found
		}
	}
	t.Skip("not enough printings in this datastore")
	return nil
}
