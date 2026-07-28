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
//   - ban:<n>                 our surrogate ban_id (Magic or non-Magic)
//   - tcg:<n> or a bare <n>   a TCGplayer product id (Magic via mtgmatcher, else non-Magic)
//   - scryfall:<uuid>         a Scryfall id (via mtgmatcher's external map)
//   - mtgjson:<uuid> or bare  an mtgjson uuid / mtgmatcher variant string
//
// A bare integer is a TCGplayer id (mtgmatcher's existing convention); ban_ids
// must carry the ban: marker because the two integer spaces overlap.
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
		// A bare integer is a TCGplayer id; everything else is a uuid / external id.
		if n, err := strconv.Atoi(val); err == nil {
			return targetFromTCGID(ctx, n)
		}
		return magicTargetFromCardID(ctx, val)
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

// magicTargetFromCardID resolves a Magic card id (mtgjson uuid, mtgmatcher
// variant string, or a Scryfall id) to a chart target. If mtgmatcher does not
// know the id but it is an mtgjson uuid still present in our price history (e.g.
// retired from the datastore), it falls back to charting that variant by ban_id.
func magicTargetFromCardID(ctx context.Context, id string) (*chartTarget, error) {
	co, err := mtgmatcher.GetUUID(id)
	if err != nil {
		// Not a direct mtgmatcher id; try the external id map (Scryfall/TCGplayer).
		if matched, merr := mtgmatcher.MatchId(id); merr == nil {
			co, err = mtgmatcher.GetUUID(matched)
		}
	}
	if err == nil {
		t := &chartTarget{UUID: co.UUID, Foil: co.Foil, Etched: co.Etched, Name: co.Name}
		// Prefer the cached ban_id so the chart reads the exact variant (skips the
		// canonical resolution HGetAllLong does in SQL). Falls back to the uuid
		// path when the cache is cold.
		if PricesArchiveDB != nil {
			if id, ok := PricesArchiveDB.CachedMagicBanID(timeseries.MagicVariant{
				MtgjsonUUID: co.UUID, IsFoil: co.Foil, IsEtched: co.Etched,
				IsAlt: co.IsAlternative, Language: co.Language,
			}); ok {
				t.BanID = id
			}
		}
		return t, nil
	}

	// Datastore fallback: a uuid we have prices for but mtgmatcher no longer knows.
	if maybeUUIDString(id) {
		if banID, ok, lerr := PricesArchiveDB.LookupMagicBanIDByUUID(ctx, id); lerr == nil && ok {
			return &chartTarget{BanID: banID, UUID: id}, nil
		}
	}
	return nil, errChartIDNotFound
}

// targetFromTCGID resolves a TCGplayer product id: Magic first (mtgmatcher knows
// Magic TCGplayer ids), otherwise a non-Magic product in the variants table.
func targetFromTCGID(ctx context.Context, tcgID int) (*chartTarget, error) {
	idStr := strconv.Itoa(tcgID)
	if matched, err := mtgmatcher.MatchId(idStr); err == nil {
		if co, err := mtgmatcher.GetUUID(matched); err == nil {
			return &chartTarget{
				UUID: co.UUID, Foil: co.Foil, Etched: co.Etched, Name: co.Name,
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
