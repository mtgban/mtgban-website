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
// is resolved most-specific first: our ban_id, then the game-native id through
// mtgmatcher (a LorcanaJSON id matches directly, a TCGplayer id via the external
// map), then a non-Magic product in the variants table. Prefix ban: or tcg: to
// force one interpretation.
func resolveChartTarget(ctx context.Context, raw string) (*chartTarget, error) {
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
		// A bare integer tries our ban_id first (the internal primary key); on a
		// miss it falls through to the game-native / product resolution below.
		if n, err := strconv.ParseInt(val, 10, 64); err == nil {
			if t, berr := targetFromBanID(ctx, n); berr == nil {
				return t, nil
			} else if !errors.Is(berr, errChartIDNotFound) {
				return nil, berr
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
		if matched, merr := mtgmatcher.MatchId(id); merr == nil {
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
		if banID, ok := PricesArchiveDB.CachedTCGBanID(pid); ok {
			return banID
		}
	}
	return 0
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
		if vi, ok, err := PricesArchiveDB.LookupTCGBanID(ctx, pid); err == nil && ok {
			return vi.BanID
		}
	}
	return 0
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
	if matched, err := mtgmatcher.MatchId(idStr); err == nil {
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
