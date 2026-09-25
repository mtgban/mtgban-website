package main

import (
	"context"
	"errors"
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
	// SearchID is the mtgmatcher id of this exact printing, which is what the
	// results table below the chart resolves a row from. Resolving a roster id
	// answers both questions at once - the chart's target and the table's row -
	// and they have to agree, or a card is charted with no row beneath it.
	// Empty when nothing in the matcher corresponds to it, e.g. a uuid the
	// datastore retired but the archive still has prices for.
	SearchID string
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
			if _, gerr := backend().GetUUID(val); gerr != nil {
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

// hasCanonicalIdentity reports whether a target that resolved to no ban_id can
// still be read by the canonical path. That path keys on mtgjson_uuid, which is
// a Postgres uuid column, so only a Magic uuid qualifies: a non-Magic card
// arrives carrying its mtgmatcher id ("omn071_695162_rainbow"), and handing that
// to a uuid column earns a 22P02 rather than an empty result.
//
// Normalise first, since mtgmatcher tags the finish onto the id it hands back
// ("<uuid>_f") while the archive stores the base uuid beside a finish flag.
func hasCanonicalIdentity(target *chartTarget) bool {
	return maybeUUIDString(timeseries.NormalizeUUID(target.UUID))
}

// matcherTarget resolves a game-native card id through mtgmatcher — an mtgjson
// uuid or mtgmatcher variant string (Magic), a LorcanaJSON id (Lorcana), or an
// external id (Scryfall / TCGplayer) via the matcher's id map. mtgmatcher holds
// whichever game the deployment serves, so this is game-agnostic. When mtgmatcher
// doesn't know the id it falls back to our own price history: a retired Magic
// uuid, or a non-Magic TCGplayer product id.
func matcherTarget(ctx context.Context, id string) (*chartTarget, error) {
	searchID := id
	co, err := backend().GetUUID(id)
	if err != nil {
		// Not a direct mtgmatcher id; try the external id map (Scryfall/TCGplayer).
		if matched, merr := backend().MatchID(id); merr == nil {
			searchID = matched
			co, err = backend().GetUUID(matched)
		}
	}
	if err == nil {
		// Prefer the resolved ban_id so the chart reads the exact variant (skips
		// the canonical resolution HGetAllLong does in SQL); a cold cache / unknown
		// product leaves BanID 0 and the canonical uuid path takes over.
		return &chartTarget{
			UUID: co.UUID, Foil: co.Foil, Etched: co.Etched, Name: co.Name,
			BanID:    resolveBanIDForCard(ctx, co),
			SearchID: searchID,
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
func chartIDForCard(cardID string) string {
	if !Config.TimeseriesConfig.LongFormReads {
		return cardID
	}
	co, err := backend().GetUUID(cardID)
	if err != nil {
		return cardID
	}
	banID := cachedBanIDForCard(co)
	if banID == 0 {
		return cardID
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
// finish a uuid of its own. mtgmatcher names a finish the way TCGplayer names
// the sub-type (mtgmatcher.FinishSlug), so tcgSubTypeForCard and tcgFinishID
// are lookups on that one name, in either direction.

// tcgSubTypeForCard names the sub-type a card's own finish is priced under.
// Returns "" when the product carries no sub-type for that finish (a foil with
// no foil listing yet), so the caller charts nothing rather than the wrong
// finish's prices.
func tcgSubTypeForCard(co *mtgmatcher.CardObject, subTypes map[string]int64) string {
	for subType := range subTypes {
		if mtgmatcher.FinishSlug(subType) == co.Finish {
			return subType
		}
	}
	return ""
}

// tcgFinishID is the inverse: the id of the product's printing sold under the
// sub-type, or "" when the product is not sold in it, since charting the wrong
// finish is worse than charting nothing. No sub-type at all is the product's
// own printing.
func tcgFinishID(productID int, subType string) string {
	pid := strconv.Itoa(productID)
	var id string
	var err error
	if subType == "" {
		id, err = backend().MatchID(pid)
	} else {
		id, err = backend().MatchIDFinish(pid, subType)
	}
	if err != nil {
		return ""
	}
	return id
}

// tcgVariantSearchID maps a non-Magic variant to the mtgmatcher id of the card
// and finish it names, for the results table the chart lives inside. ok=false
// when mtgmatcher doesn't know the product (a game it doesn't carry, or a
// product with no card), or when the card is not sold in the variant's
// sub-type.
func tcgVariantSearchID(vi timeseries.VariantInfo) (string, bool) {
	id := tcgFinishID(vi.TCGProductID, vi.TCGSubType)
	return id, id != ""
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
	if matched, err := backend().MatchID(idStr); err == nil {
		if co, err := backend().GetUUID(matched); err == nil {
			return &chartTarget{
				UUID: co.UUID, Foil: co.Foil, Etched: co.Etched, Name: co.Name,
				BanID:    resolveBanIDForCard(ctx, co),
				SearchID: matched,
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
			// The uuid, kept on the finish the ban_id names.
			SearchID: magicFinishSearchID(vi.MtgjsonUUID, vi.IsFoil, vi.IsEtched),
		}
		// Display name comes from mtgmatcher; the base uuid suffices since the
		// name is finish-independent (the chart uses BanID for data).
		if co, err := backend().GetUUID(vi.MtgjsonUUID); err == nil {
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
	// The product id maps back to the game's own card id, on the finish the
	// variant's sub-type names.
	if searchID, ok := tcgVariantSearchID(vi); ok {
		t.SearchID = searchID
	}
	if p, ok, _ := PricesArchiveDB.GetTCGProduct(ctx, vi.TCGProductID); ok {
		t.Name = p.Name
		if vi.TCGSubType != "" && vi.TCGSubType != "Normal" {
			t.Name += " (" + vi.TCGSubType + ")"
		}
	}
	return t
}
