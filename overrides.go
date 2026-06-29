package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync/atomic"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/simplecloud"
)

// keyOverridesFile is the name of the overrides object, stored as a sibling of
// the main config file in the same bucket.
const keyOverridesFile = "key_overrides.json"

// Override kinds: retail remaps apply to a seller's inventory, buylist remaps
// to a vendor's buylist. Keeping them separate means the same shorthand can be
// corrected independently on each side.
const (
	overrideKindRetail  = "retail"
	overrideKindBuylist = "buylist"
)

// KeyOverrides maps a seller/vendor shorthand and a kind (retail/buylist) to a
// set of UUID remappings applied when its inventory/buylist is (re)loaded. Each
// remapping is keyed by the wrongly-matched UUID and points at the correct one;
// a correct UUID of "" drops the entries entirely (the listing matches no card).
//
//	{ "CK": { "retail": { "wrong-uuid": "correct-uuid" }, "buylist": { ... } } }
type KeyOverrides map[string]map[string]map[string]string

var keyOverridesPtr atomic.Pointer[KeyOverrides]

// GetKeyOverrides returns the currently loaded overrides, or nil when none are
// configured.
func GetKeyOverrides() KeyOverrides {
	p := keyOverridesPtr.Load()
	if p == nil {
		return nil
	}
	return *p
}

// keyOverridesPath returns the bucket path of the overrides file: a sibling of
// the main config file, so it lives in the same place and bucket.
func keyOverridesPath() string {
	p := Config.sourcePath
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i+1] + keyOverridesFile
	}
	return keyOverridesFile
}

// loadKeyOverrides (re)reads the overrides file from the config bucket. A
// missing or unreadable file is not fatal: overrides are simply treated as
// empty, mirroring how a missing main config falls back to safe defaults.
func loadKeyOverrides() error {
	reader, err := simplecloud.InitReader(context.Background(), ConfigBucket, keyOverridesPath())
	if err != nil {
		log.Println("no key overrides loaded:", err)
		empty := KeyOverrides{}
		keyOverridesPtr.Store(&empty)
		return nil
	}
	defer reader.Close()

	var overrides KeyOverrides
	if err := json.NewDecoder(reader).Decode(&overrides); err != nil {
		return err
	}
	keyOverridesPtr.Store(&overrides)
	return nil
}

// saveKeyOverrides writes the overrides to the config bucket and publishes them
// for subsequent loads. It does not itself re-apply them to already-loaded
// scrapers; callers reload the affected shorthands for that.
func saveKeyOverrides(overrides KeyOverrides) error {
	writer, err := simplecloud.InitWriter(context.Background(), ConfigBucket, keyOverridesPath())
	if err != nil {
		return err
	}
	defer writer.Close()

	enc := json.NewEncoder(writer)
	enc.SetIndent("", "  ")
	if err := enc.Encode(overrides); err != nil {
		return err
	}

	keyOverridesPtr.Store(&overrides)
	return nil
}

// validateKeyOverrides returns a list of human-readable problems with the
// overrides: any non-empty target UUID that does not resolve to a known card.
// Wrong-key UUIDs are not validated — a stale/typo'd key is a harmless no-op at
// load time, whereas a bogus target would silently create a dead inventory key.
func validateKeyOverrides(overrides KeyOverrides) []string {
	var bad []string
	for shorthand, byKind := range overrides {
		for kind, remap := range byKind {
			for wrong, correct := range remap {
				if correct == "" {
					continue // "" means drop the listing, always valid
				}
				if _, err := mtgmatcher.GetUUID(correct); err != nil {
					bad = append(bad, fmt.Sprintf("%s/%s: %s → %s (unknown card)", shorthand, kind, wrong, correct))
				}
			}
		}
	}
	return bad
}

// detectOverrideChains finds remaps whose target is itself remapped within the
// same store (A→B while B→C exists). Such chains are ambiguous when applied at
// load, since entry order is undefined. Returns human-readable descriptions.
func detectOverrideChains(overrides KeyOverrides) []string {
	var chains []string
	for shorthand, byKind := range overrides {
		for kind, remap := range byKind {
			for wrong, correct := range remap {
				if correct == "" {
					continue
				}
				if next, ok := remap[correct]; ok {
					chains = append(chains, fmt.Sprintf("%s/%s: %s → %s, but %s → %s also exists", shorthand, kind, wrong, correct, correct, next))
				}
			}
		}
	}
	return chains
}

// OverrideCard is a card rendered into the overrides builder (the wrong match
// and the candidate printings). Plain template data — no endpoint involved.
type OverrideCard struct {
	UUID  string
	Label string
	Image string
}

// uuidCardLabel renders a card as "Name · Edition (SET) #Number · Finish".
func uuidCardLabel(co *mtgmatcher.CardObject) string {
	label := fmt.Sprintf("%s · %s (%s) #%s", co.Name, co.Edition, co.SetCode, co.Number)
	switch {
	case co.Sealed:
		label += " · Sealed"
	case co.Etched:
		label += " · Etched"
	case co.Foil:
		label += " · Foil"
	}
	return label
}

// newOverrideCard builds the display data for a card uuid, or nil if unknown.
func newOverrideCard(uuid string) *OverrideCard {
	co, err := mtgmatcher.GetUUID(uuid)
	if err != nil {
		return nil
	}
	image := co.Images["thumbnail"]
	if image == "" {
		image = co.Images["full"]
	}
	return &OverrideCard{UUID: uuid, Label: uuidCardLabel(co), Image: image}
}

// overrideFixCandidates resolves the wrongly-matched card and every other
// printing that shares its name — the realistic targets when fixing a bad
// match. Everything comes from the in-memory card database at render time;
// there is no lookup endpoint. Returns nil when the uuid is unknown.
func overrideFixCandidates(wrongUUID string) (wrong *OverrideCard, candidates []OverrideCard) {
	co, err := mtgmatcher.GetUUID(wrongUUID)
	if err != nil {
		return nil, nil
	}
	wrong = newOverrideCard(wrongUUID)

	uuids, err := mtgmatcher.SearchEquals(co.Name)
	if err != nil {
		return wrong, nil
	}
	for _, id := range uuids {
		if id == wrongUUID {
			continue
		}
		if card := newOverrideCard(id); card != nil {
			candidates = append(candidates, *card)
		}
	}
	return wrong, candidates
}

// currentKeyOverridesJSON returns the loaded overrides as pretty JSON, for the
// admin editor. An empty/unloaded set renders as "{}".
func currentKeyOverridesJSON() (string, error) {
	overrides := GetKeyOverrides()
	if overrides == nil {
		overrides = KeyOverrides{}
	}
	out, err := json.MarshalIndent(overrides, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// reloadOverriddenScrapers re-reads from the data bucket every scraper whose
// shorthand is in the set, so freshly-saved overrides take effect immediately
// instead of waiting for the next scheduled load. It is a no-op without a data
// bucket (e.g. API mode), where scrapers pick up changes on their next load.
func reloadOverriddenScrapers(shorthands map[string]struct{}) {
	if DataBucket == nil || len(shorthands) == 0 {
		return
	}
	cfg := Config.ScraperConfig
	for name, scrapersConfig := range cfg.Config {
		for kind, list := range scrapersConfig {
			for _, shorthand := range list {
				if _, ok := shorthands[shorthand]; ok {
					go loadScraperWithRetry(DataBucket, cfg.BucketPath, Config.Game, name, kind, shorthand, cfg.BucketFileFormat)
				}
			}
		}
	}
}

// remapRecord moves entries from each wrong UUID to its correct UUID in place,
// merging into any entries already there. A correct UUID of "" drops the wrong
// entries. It is generic over the inventory and buylist record element types.
func remapRecord[E any](record map[string][]E, remap map[string]string) {
	for wrong, correct := range remap {
		entries, ok := record[wrong]
		if !ok {
			continue
		}
		delete(record, wrong)
		if correct == "" {
			continue
		}
		record[correct] = append(record[correct], entries...)
	}
}

// applyInventoryOverrides returns a seller whose inventory has had this seller's
// wrong->correct UUID remappings applied. The seller is returned untouched when
// it has no configured overrides.
func applyInventoryOverrides(seller mtgban.Seller) mtgban.Seller {
	remap := GetKeyOverrides()[seller.Info().Shorthand][overrideKindRetail]
	if len(remap) == 0 {
		return seller
	}
	inv := seller.Inventory()
	remapRecord(inv, remap)
	return mtgban.NewSellerFromInventory(inv, seller.Info())
}

// applyBuylistOverrides is the buylist counterpart of applyInventoryOverrides.
func applyBuylistOverrides(vendor mtgban.Vendor) mtgban.Vendor {
	remap := GetKeyOverrides()[vendor.Info().Shorthand][overrideKindBuylist]
	if len(remap) == 0 {
		return vendor
	}
	bl := vendor.Buylist()
	remapRecord(bl, remap)
	return mtgban.NewVendorFromBuylist(bl, vendor.Info())
}
