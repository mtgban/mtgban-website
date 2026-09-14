# Rarity badges

Magic sets draw their set symbol from the keyrune webfont, one glyph per set
that font already ships. No other game is in that font, so every non-Magic
card needs its rarity painted a different way: a shape (drawn here, or a
plain circle when there is no real shape to draw) filled with a colour, and
the card's set code cut out of the fill in the page's own background colour.

The pieces, and where each lives:

- `colorRarityMap` (`utils.go`) — one hex (or `var(--normal)`) per rarity
  string, keyed exactly as the game's datastore spells it. `co.Rarity` reaches
  this map verbatim, with no normalising in between, so the keys have to be a
  byte-for-byte match — case included.
- `img/setsymbol/<game>/*.svg` (optional) — one outline per rarity, loaded at
  startup by `loadRarityBadges`. A game with no directory here — or no file
  for a given rarity — draws `img/setsymbol/default.svg`, a plain circle.
- `templates/partials/set-symbol.html` — the block that actually paints:
  a published symbol image where one exists, falling back to the keyrune
  glyph or the drawn badge above if the image fails to load or none exists.
- `gameMap` / `gameBadgeMap` (`news.go`) — every game a deployment can be
  configured as. Missing from `gameMap` panics the newspaper cache at
  startup, so this has to exist before the game is stood up, not after.
- `img/backs/<game>.webp` — the card back, served at `/img/backs/<game>.webp`
  by the `card_back` template func.
- `registeredGames` (`games_coverage_test.go`) — kept in step with
  go-mtgban's `mtgmatcher/games/games.go` by hand; nothing generates it.

## Adding a game

1. **Get the exact rarity vocabulary.** If go-mtgban's
   `mtgmatcher/<game>/<game>.go` defines a `<game>RarityMap` (most do — it is
   what sorts a set's rarity list commonest-first), its keys are the literal
   strings `colorRarityMap` must use, and its values are the climb order for
   step 3. Cross-check against the real datastore JSON (paths in
   go-mtgban's `.env`): count cards per rarity, and confirm nothing in the
   ranking map is actually empty and nothing the datastore carries is
   missing from it.

2. **Look at real cards.** Pull one sample image per rarity from the
   datastore's own image URLs — prefer a recent, canonical printing — and
   crop tight on wherever the game prints its rarity mark. Zoom in. Two
   questions: does colour actually differ by rarity, and does shape?
   Sample the most saturated pixels of a mark, not the brightest ones — a
   foil or gem highlight reads near-white and washes an average out.

3. **Decide sample vs. place.** Genuinely identical print colour across
   different rarities is common, not an edge case: Lorcana's common and
   superrare are the same grey, Gundam's rarity banner is black, silver or
   gold purely by *parallel run* (the same black sits under Common and under
   Legend Rare), Palworld's one coloured mark is a foil watermark shared by
   every parallel print regardless of tier. Sampling those would collide two
   real rarities onto one hex. Place them instead: climb the same swatch
   bank every other game already uses (see each entry's comment in
   `colorRarityMap`), in the order the game's own `<game>RarityMap` ranks
   them. Reusing a hex across games is fine and expected — the bank is
   shared by design.

4. **Decide shapes.** Only worth drawing when the card gives a real, distinct
   outline per rarity — Lorcana's ink drop / triangle / diamond / pentagon,
   Riftbound's sphere / pyramid / octahedron / gem / cube. A plain lettered
   code, or a mark that does not vary by rarity, is not that: leave the
   directory absent (or the specific rarity's file out of it) and let the
   default circle draw. That is the common case — One Piece, Yu-Gi-Oh,
   Pokemon, Gundam and Palworld all use it for most or all of their
   rarities.

   When you do draw one: `viewBox="0 0 20 20"`, `fill="currentColor"` on the
   path, plus three attributes on the root `<svg>` that size the code text —
   `data-code-size` (the font size the shape was cut for), `data-code-chars`
   (how many characters that size assumes), `data-code-y` (the vertical
   centre). `fitCode` (`utils.go`) scales the font by `chars / len(code)`,
   capped at 10 — past three characters a shape's room runs out almost
   exactly in proportion to length, so the ratio lands where measuring
   would. Watch stroked vertices: a stroke's miter at a sharp corner
   overhangs by `(strokeWidth/2) / sin(angle/2)`, which clips silently at
   low viewBox headroom — render with `overflow: visible` while iterating to
   see the true point rather than the clipped one.

5. **Contrast-check every colour.** The badge draws the code text in
   `var(--background)` — literally the page's own background colour cut out
   of the fill — so a fill needs contrast against *both* the light and the
   dark theme's background, not just the one you're looking at.

6. **Write the `colorRarityMap` entry**, with a comment stating what is
   sampled and what is placed, and why. That reasoning is the part a
   reviewer — or the next session — cannot re-derive from the hex codes
   alone.

7. **Register the game**, or it silently misbehaves rather than failing
   loudly: `gameMap` and `gameBadgeMap` in `news.go`, and
   `games_coverage_test.go`'s `registeredGames` list at the repo root.
   `TestEveryRegisteredGameIsNamed` only catches a `gameMap` gap for games
   that list already knows about.

8. **Add the card back** — `img/backs/<game>.webp`, roughly 450–600px on the
   long edge at the game's own card aspect ratio (~0.71), matching the
   existing files. Prefer the game's own official site; when that exposes
   nothing usable, a reputable fan TCG-database's dedicated card-back asset
   is an acceptable fallback if it is unwatermarked and matches the game's
   own branding — check that site's network requests for a `*.webp`/`*.svg`
   literally named "back" even when no visible page links to it, several
   ship one anyway. Downloading and committing a third-party asset is not
   something to do unasked: name the exact source, dimensions and size and
   let the human decide. In this repo, every card back so far was in fact
   added by a human directly rather than by a session — that is worth
   staying consistent with rather than defaulting to doing it yourself.

9. **Verify.** `go build ./...`, `go vet ./...`, `go test .` —
   `setsymbol_test.go`'s `TestSetSymbolsLoadForARegisteredGame` and
   `TestSetSymbolImages` cover the rendering path, `games_coverage_test.go`
   covers registration. None of this needs go.mod's go-mtgban pin bumped to
   a version that ships the game's `mtgmatcher` package — `colorRarityMap`
   is plain data with no import on it. Bumping the dependency is a separate,
   later step for actually deploying the game, not part of badge setup.

## Games so far

| Game | Shape | Colour | Card back |
|---|---|---|---|
| Lorcana | drawn, one per rarity | sampled from the printed symbols | added |
| Riftbound | drawn, one per rarity | sampled from the printed gems | added |
| One Piece | default circle | placed ladder; SEC sampled from its brass plate | added |
| Yu-Gi-Oh | default circle | placed ladder; 35 rarity names group into ~10 tiers by the tier their name claims | added |
| Flesh and Blood | default circle, except Fabled (diamond) and Gold (triangle) | sampled per glyph where the card prints one; placed for the four tiers that print none | added |
| Pokemon | default circle — the card does print real per-rarity shapes (circle / diamond / star / ★★ / ★★★), not drawn here yet | 4 tiers sampled from their tinted stars; rest placed, grouped by family | added |
| Gundam | default circle — the printed banner differentiates black/silver/gold by parallel run only, not by rarity | placed ladder, in `gundamRarityMap`'s rank order | added |
| Palworld | default circle — the one coloured mark is a foil watermark, not a rarity signal | placed ladder, in `palworldRarityMap`'s rank order; trial-deck rarities run beside their booster counterparts as their own adjacent step, not sharing its colour | added |

## Other things worth knowing

- Magic never touches any of this: `loadRarityBadges` returns immediately for
  `Config.Game == DefaultGame`, and the template branches on `.Keyrune`
  before it ever asks for a badge.
- A published symbol image (the `set_symbol` func, backed by a vendor's own
  CDN) takes precedence over both the keyrune glyph and the drawn badge, with
  the drawn badge kept hidden as its `onerror` fallback. That fallback is not
  hypothetical: every Pokemon symbol 404ed for nine days once, when the
  vendor changed where the file lived out from under a URL this site had
  already been handed.
- `default.svg` under the empty rarity key covers two cases at once: a game
  with no shapes directory at all, and one rarity within a shaped game's
  directory that the game doesn't distinguish by outline (Flesh and Blood's
  everything-but-Fabled-and-Gold).
