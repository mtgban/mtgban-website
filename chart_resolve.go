package main

import (
	"context"
	"errors"
	"log"
	"slices"
	"strconv"
	"strings"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/timeseries"
)

// errChartIDNotFound means a syntactically valid id resolved to no chartable card.
var errChartIDNotFound = errors.New("chart id not found")

// chartTarget is a resolved, game-agnostic chart identity. The read mode is:
//   - BanID != 0: chart this exact variant via HGetAllByBanID (a ban: id, or a
//     resolved TCGplayer product). Precise about language/finish/alt/sub-type.
//   - BanID == 0: canonical uuid path via (UUID, Foil, Etched) through HGetAllLong.
//
// Datasets are derived from whichever providers have data (see getChartDatasets),
// so the target carries no game flag or provider list — a new game just works.
type chartTarget struct {
	BanID  int64
	UUID   string // mtgjson uuid, for the canonical path and display
	Foil   bool
	Etched bool
	Name   string
}

// resolveChartTarget turns any supported id string into a chartable target.
// Supported forms:
//   - ban:<n>            our surrogate ban_id (Magic or non-Magic) — forced
//   - tcg:<n>            a TCGplayer product id — forced
//   - scryfall:<uuid>    a Scryfall id (via mtgmatcher's external map)
//   - mtgjson:<uuid>     an mtgjson uuid
//   - a bare <n>/<uuid>  resolved by trying each id space in turn (below)
//
// The integer id spaces overlap — a ban_id, a TCGplayer product id, and a game's
// own numeric id (e.g. LorcanaJSON) can all be the same number — so a bare integer
// is resolved in this order: the game-native id through mtgmatcher, then our
// ban_id, then a TCGplayer product (via mtgmatcher's external map, else the
// variants table). Prefix ban: or tcg: to force one interpretation.
//
// The game's own id has to win, because it is the one that travels in urls: the
// search UI charts a card by its mtgmatcher id ("Chart the top results", the
// sidebar's foil switch, any shared link), and a game that numbers its cards
// (LorcanaJSON) hands us a bare integer from the same small range our ban_id
// sequence starts in — sampling 60 Lorcana ids against the live variants table,
// all 60 also existed as a ban_id, so those links charted an unrelated card
// rather than failing. A ban_id only ever leaves this process carrying its ban:
// marker, so it loses nothing by yielding. Magic is untouched either way: an
// mtgjson uuid never parses as an integer.
func resolveChartTarget(ctx context.Context, raw string) (*chartTarget, error) {
	// Every resolution branch can reach the variants table (targetFromBanID,
	// targetFromTCGID, and matcherTarget's retired-uuid fallback dereference
	// PricesArchiveDB directly). Both current callers are behind their own nil
	// checks; this guard keeps a future caller from turning a chartless deploy
	// into a panic.
	if PricesArchiveDB == nil {
		return nil, errChartIDNotFound
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errChartIDNotFound
	}
	prefix, val := splitIDPrefix(raw)
	switch prefix {
	case "ban":
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return nil, errChartIDNotFound
		}
		return targetFromBanID(ctx, n)
	case "tcg":
		n, err := strconv.Atoi(val)
		if err != nil {
			return nil, errChartIDNotFound
		}
		return targetFromTCGID(ctx, n)
	case "", "mtgjson", "scryfall":
		// An integer mtgmatcher doesn't carry as a card of its own can still be
		// our ban_id; on a miss it falls through to the product resolution below.
		if n, err := strconv.ParseInt(val, 10, 64); err == nil {
			if _, gerr := mtgmatcher.GetUUID(val); gerr != nil {
				if t, berr := targetFromBanID(ctx, n); berr == nil {
					return t, nil
				} else if !errors.Is(berr, errChartIDNotFound) {
					return nil, berr
				}
			}
		}
		return matcherTarget(ctx, val)
	default:
		return nil, errChartIDNotFound
	}
}

// splitIDPrefix splits a "<prefix>:<value>" id. Bare uuids and integers have no
// colon, so they return an empty prefix and the whole string as the value.
func splitIDPrefix(raw string) (prefix, val string) {
	if i := strings.IndexByte(raw, ':'); i > 0 {
		return strings.ToLower(raw[:i]), raw[i+1:]
	}
	return "", raw
}

// maybeUUIDString reports whether s has the shape of a UUID (36 chars, 4 dashes).
func maybeUUIDString(s string) bool {
	return len(s) == 36 && strings.Count(s, "-") == 4
}

// matcherTarget resolves a game-native card id through mtgmatcher — an mtgjson
// uuid or mtgmatcher variant string (Magic), a LorcanaJSON id (Lorcana), or an
// external id (Scryfall / TCGplayer) via the matcher's id map. mtgmatcher holds
// whichever game the deployment serves, so this is game-agnostic. When mtgmatcher
// doesn't know the id it falls back to our own price history: a retired Magic
// uuid, or a non-Magic TCGplayer product id.
func matcherTarget(ctx context.Context, id string) (*chartTarget, error) {
	co, err := mtgmatcher.GetUUID(id)
	if err != nil {
		// Not a direct mtgmatcher id; try the external id map (Scryfall/TCGplayer).
		if matched, merr := mtgmatcher.MatchID(id); merr == nil {
			co, err = mtgmatcher.GetUUID(matched)
		}
	}
	if err == nil {
		// Prefer the resolved ban_id so the chart reads the exact variant (skips
		// the canonical resolution HGetAllLong does in SQL); a cold cache / unknown
		// product leaves BanID 0 and the canonical uuid path takes over.
		return &chartTarget{
			UUID: co.UUID, Foil: co.Foil, Etched: co.Etched, Name: co.Name,
			BanID: resolveBanIDForCard(ctx, co),
		}, nil
	}

	// mtgmatcher doesn't know the id — fall back to our own price history.
	if maybeUUIDString(id) {
		// A Magic uuid we have prices for but the datastore retired.
		if banID, ok, lerr := PricesArchiveDB.LookupMagicBanIDByUUID(ctx, id); lerr == nil && ok {
			return &chartTarget{BanID: banID, UUID: id}, nil
		}
		return nil, errChartIDNotFound
	}
	// A bare integer mtgmatcher can't map is a non-Magic product id in variants.
	if n, aerr := strconv.Atoi(id); aerr == nil {
		if vi, ok, lerr := PricesArchiveDB.LookupTCGBanID(ctx, n); lerr == nil && ok {
			return nonMagicTarget(ctx, vi), nil
		}
	}
	return nil, errChartIDNotFound
}

// cachedBanIDForCard maps a resolved mtgmatcher card to our surrogate ban_id from
// the in-memory variant caches, game-agnostically and with no DB round-trip, using
// whichever identity the variants table keys on for its game: the mtgjson uuid for
// Magic, otherwise the card's TCGplayer product id for non-Magic games (Lorcana,
// Pokemon, ...), which have no uuid. Returns 0 when nothing is cached (cold cache /
// new printing), so a caller can fall back to the game-native id. Safe to call per
// card while rendering a results page.
func cachedBanIDForCard(co *mtgmatcher.CardObject) int64 {
	if PricesArchiveDB == nil {
		return 0
	}
	if banID, ok := PricesArchiveDB.CachedMagicBanID(timeseries.MagicVariant{
		MtgjsonUUID: co.UUID, IsFoil: co.Foil, IsEtched: co.Etched,
		IsAlt: co.IsAlternative, Language: co.Language,
	}); ok {
		return banID
	}
	if pid, ok := tcgProductID(co); ok {
		// One product covers every finish, so the card's own sub-type decides
		// which variant it charts; without it a foil would read the product's
		// canonical ("Normal") prices.
		if subTypes, ok := PricesArchiveDB.CachedTCGSubTypeBanIDs(pid); ok {
			return tcgBanIDForCard(co, subTypes)
		}
		if banID, ok := PricesArchiveDB.CachedTCGBanID(pid); ok {
			return banID
		}
	}
	return 0
}

// chartIDForCard maps a card id to the id the UI hands the chart system: the
// internal ban:<id> once long-form reads serve charts (so lookups skip the
// canonical re-resolution), else the card id itself (legacy path). It costs a
// variant-cache lookup per call, so it is invoked only while rendering pages
// that chart cards (search results) — not from uuid2card, which also feeds
// chartless pages (upload, arbit, news, ...) at thousands of cards a request.
func chartIDForCard(cardId string) string {
	if !Config.TimeseriesConfig.LongFormReads {
		return cardId
	}
	co, err := mtgmatcher.GetUUID(cardId)
	if err != nil {
		return cardId
	}
	banID := cachedBanIDForCard(co)
	if banID == 0 {
		return cardId
	}
	return "ban:" + strconv.FormatInt(banID, 10)
}

// resolveBanIDForCard is cachedBanIDForCard for the single chart-open path, where a
// DB round-trip is affordable: on an in-memory miss it resolves a non-Magic product
// against the variants table, so a cold cache (or a product ingested since warm-up)
// still charts precisely. A Magic miss stays 0 — the canonical uuid path covers it.
func resolveBanIDForCard(ctx context.Context, co *mtgmatcher.CardObject) int64 {
	if banID := cachedBanIDForCard(co); banID != 0 {
		return banID
	}
	if PricesArchiveDB == nil {
		return 0
	}
	if pid, ok := tcgProductID(co); ok {
		if subTypes, err := PricesArchiveDB.LookupTCGSubTypeBanIDs(ctx, pid); err == nil {
			return tcgBanIDForCard(co, subTypes)
		}
	}
	return 0
}

// tcgBanIDForCard is the ban_id of the variant carrying a card's own finish, or
// 0 when the product has no listing for it.
func tcgBanIDForCard(co *mtgmatcher.CardObject, subTypes map[string]int64) int64 {
	subType := tcgSubTypeForCard(co, subTypes)
	if subType == "" {
		return 0
	}
	return subTypes[subType]
}

// TCGplayer prices one product under several sub-types, one per finish, and the
// variants table keys a non-Magic printing on (product, sub-type) — so a
// non-Magic card's finish lives in the sub-type, while mtgmatcher gives each
// finish a uuid of its own. tcgSubTypeForCard and tcgFinishIDForSubType are
// inverses that bridge the two, and both read the finish off the sub-types the
// product is actually priced under, since the names vary by game: "Normal" is
// the nonfoil, the first foil sub-type is the primary foil ("Foil" for
// Riftbound, "Cold Foil" for Lorcana), and the ones after it are Lorcana's
// extra foil sub-types, which TCGplayer calls "Holofoil" (mtgmatcher/lorcana's
// selectFinish reads the same naming from the other direction).

// foilSubTypes returns a product's foil sub-types in the order they pair with a
// card's foil finishes: alphabetical, which puts the primary foil ("Cold Foil",
// "Foil") ahead of the "Holofoil" the extra sub-types are sold as.
//
// The pairing is positional over this list and the sorted one extraFoilFinishes
// returns, so it rests on an invariant nothing in the data enforces: on a
// product priced under more than one foil, the primary foil's name sorts before
// the extras'. It holds for every name in use, but that is a naming coincidence
// carrying structural weight — a new foil sub-type sorting ahead of "Cold Foil"
// would re-pair every finish on its product. TestFoilSubTypeOrdering pins the
// names we know, so a new one gets added there and the order gets checked
// rather than assumed.
func foilSubTypes(subTypes map[string]int64) []string {
	foils := make([]string, 0, len(subTypes))
	for subType := range subTypes {
		if subType != "" && subType != "Normal" {
			foils = append(foils, subType)
		}
	}
	slices.Sort(foils)
	return foils
}

// extraFoilFinishes returns the keys of a card's foil finishes past the primary
// one (Lorcana's RainbowPillars and friends), ordered to match foilSubTypes.
// Sorted, so with more than one extra the pairing would also depend on the
// finish keys sorting into the same order as the sub-type names; today no
// product carries a second extra, so the ordering above is the live constraint.
func extraFoilFinishes(co *mtgmatcher.CardObject) []string {
	extras := make([]string, 0, len(co.FoilUUIDs))
	for finish := range co.FoilUUIDs {
		if finish != mtgmatcher.FinishNonfoil && finish != mtgmatcher.FinishFoil {
			extras = append(extras, finish)
		}
	}
	slices.Sort(extras)
	return extras
}

// tcgSubTypeForCard names the sub-type a card's own finish is priced under.
// Returns "" when the product carries no sub-type for that finish (a foil with
// no foil listing yet), so the caller charts nothing rather than the wrong
// finish's prices.
func tcgSubTypeForCard(co *mtgmatcher.CardObject, subTypes map[string]int64) string {
	if !co.Foil {
		if _, ok := subTypes["Normal"]; ok {
			return "Normal"
		}
		return ""
	}
	foils := foilSubTypes(subTypes)
	if len(foils) == 0 {
		return ""
	}
	for i, finish := range extraFoilFinishes(co) {
		if co.FoilUUIDs[finish] != co.UUID {
			continue
		}
		// An extra sub-type the product isn't priced under is not the primary
		// foil's data in disguise, so leave it unmapped.
		if i+1 < len(foils) {
			return foils[i+1]
		}
		return ""
	}
	return foils[0]
}

// tcgFinishIDForSubType is the inverse: given a product's base card, the id of
// the finish the sub-type names, or "" when the card carries no finish for it.
// A sub-type the product doesn't list resolves to the primary foil, since
// "Normal" is the only nonfoil name.
func tcgFinishIDForSubType(co *mtgmatcher.CardObject, subTypes map[string]int64, subType string) string {
	if subType == "" || subType == "Normal" {
		if id, ok := co.FoilUUIDs[mtgmatcher.FinishNonfoil]; ok {
			return id
		}
		return co.UUID
	}
	if idx := slices.Index(foilSubTypes(subTypes), subType); idx > 0 {
		extras := extraFoilFinishes(co)
		if idx-1 >= len(extras) {
			// The mirror of tcgSubTypeForCard's refusal to map an extra
			// sub-type onto the primary foil: a product priced under one more
			// foil than the card has finishes would otherwise hand both
			// sub-types the same id, and a roster holding both would render
			// two rows for one printing.
			return ""
		}
		return co.FoilUUIDs[extras[idx-1]]
	}
	if id, ok := co.FoilUUIDs[mtgmatcher.FinishFoil]; ok {
		return id
	}
	if id, err := mtgmatcher.MatchID(co.UUID, true); err == nil {
		return id
	}
	return co.UUID
}

// tcgVariantSearchID maps a non-Magic variant to the mtgmatcher id of the card
// and finish it names, for the results table the chart lives inside. ok=false
// when mtgmatcher doesn't know the product (a game it doesn't carry, or a
// product with no card), or when the card has no finish for the variant's
// sub-type — charting the wrong finish is worse than charting nothing.
func tcgVariantSearchID(ctx context.Context, vi timeseries.VariantInfo) (string, bool) {
	matched, err := mtgmatcher.MatchID(strconv.Itoa(vi.TCGProductID))
	if err != nil {
		return "", false
	}
	co, err := mtgmatcher.GetUUID(matched)
	if err != nil {
		return matched, true
	}
	subTypes, ok := PricesArchiveDB.CachedTCGSubTypeBanIDs(vi.TCGProductID)
	if !ok {
		// Without the product's sub-types there is nothing to pair the
		// variant's own against, and tcgFinishIDForSubType reads an unknown
		// sub-type as the primary foil — which is the wrong finish rather
		// than no finish. Say so instead.
		subTypes, err = PricesArchiveDB.LookupTCGSubTypeBanIDs(ctx, vi.TCGProductID)
		if err != nil {
			log.Printf("chart: sub-types for product %d: %v", vi.TCGProductID, err)
			return "", false
		}
	}
	id := tcgFinishIDForSubType(co, subTypes, vi.TCGSubType)
	if id == "" {
		return "", false
	}
	return id, true
}

// tcgProductID extracts a card's TCGplayer product id from its identifiers.
func tcgProductID(co *mtgmatcher.CardObject) (int, bool) {
	pidStr, ok := co.Identifiers["tcgplayerProductId"]
	if !ok {
		return 0, false
	}
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0, false
	}
	return pid, true
}

// targetFromTCGID resolves a TCGplayer product id: Magic first (mtgmatcher knows
// Magic TCGplayer ids), otherwise a non-Magic product in the variants table.
func targetFromTCGID(ctx context.Context, tcgID int) (*chartTarget, error) {
	idStr := strconv.Itoa(tcgID)
	if matched, err := mtgmatcher.MatchID(idStr); err == nil {
		if co, err := mtgmatcher.GetUUID(matched); err == nil {
			return &chartTarget{
				UUID: co.UUID, Foil: co.Foil, Etched: co.Etched, Name: co.Name,
				BanID: resolveBanIDForCard(ctx, co),
			}, nil
		}
	}
	vi, ok, err := PricesArchiveDB.LookupTCGBanID(ctx, tcgID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errChartIDNotFound
	}
	return nonMagicTarget(ctx, vi), nil
}

// targetFromBanID resolves our surrogate ban_id via the variants table, to the
// exact printing (Magic or non-Magic).
func targetFromBanID(ctx context.Context, banID int64) (*chartTarget, error) {
	vi, ok, err := PricesArchiveDB.LookupVariant(ctx, banID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errChartIDNotFound
	}
	if vi.IsMagic() {
		t := &chartTarget{
			BanID:  banID,
			UUID:   vi.MtgjsonUUID,
			Foil:   vi.IsFoil,
			Etched: vi.IsEtched,
		}
		// Display name comes from mtgmatcher; the base uuid suffices since the
		// name is finish-independent (the chart uses BanID for data).
		if co, err := mtgmatcher.GetUUID(vi.MtgjsonUUID); err == nil {
			t.Name = co.Name
		}
		return t, nil
	}
	return nonMagicTarget(ctx, vi), nil
}

// nonMagicTarget builds a non-Magic chart target, resolving the display name from
// the tcg_products catalog and tagging the printing's sub-type when it is not the
// base ("Normal").
func nonMagicTarget(ctx context.Context, vi timeseries.VariantInfo) *chartTarget {
	t := &chartTarget{BanID: vi.BanID}
	if p, ok, _ := PricesArchiveDB.GetTCGProduct(ctx, vi.TCGProductID); ok {
		t.Name = p.Name
		if vi.TCGSubType != "" && vi.TCGSubType != "Normal" {
			t.Name += " (" + vi.TCGSubType + ")"
		}
	}
	return t
}
