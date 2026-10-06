# Price API v2: speed and size against v1

Measured on 2026-10-06, on the live Magic site with v2 deployed (#832 to
#841), gzip requested as a client would. About 0.32 s of every request is
network: an unsigned `sets.json` takes that long.

## Before

| Request | First byte | Total | Gzipped | Raw |
|---|---|---|---|---|
| ZEN, v1 | 0.44 s | 0.54 s | 43 KB | 306 KB |
| ZEN, v1 `qty`+`conds` | 0.44 s | 0.65 s | 125 KB | 841 KB |
| ZEN, v2 | 0.43 s | 0.64 s | 94 KB | 722 KB |
| MH3, v1 | 0.43 s | 0.59 s | 85 KB | 595 KB |
| MH3, v1 `qty`+`conds` | 0.43 s | 0.75 s | 211 KB | 1,493 KB |
| MH3, v2 | 0.43 s | 0.68 s | 149 KB | 1,119 KB |
| Full retail, v1 | 6.4-6.5 s | 8.2-8.6 s | 13.2 MB | 88.5 MB |
| Full retail, v1 `qty`+`conds` | 6.4 s | 8.2 s | 15.4 MB | 99.0 MB |
| Full retail, v2 | 8.0-8.2 s | 10.5-10.8 s | 24.3 MB | 178.7 MB |

An edition costs the server about 0.1 s in either version. A full dump is
where v2 is slower. v1 ignores `conds` in a full dump of several stores, so
it has no equivalent of v2's conditions there.

## Where the full dump's time goes

A 12 s CPU profile of the live server during v2's full retail dump, against
the same profile for v1:

| Stage | v1 | v2 |
|---|---|---|
| Building the price map | 3.9 s | 5.4 s |
| Of which `Backend.GetUUID`, once per card per store | 1.1 s | 1.6 s |
| Of which filing entries (`V2.Add`), mostly map lookups | | 2.9 s |
| `encoding/json` | 2.0 s | 2.35 s |

`json.Encoder` builds the whole document in memory before its first byte
leaves, so the first byte waited for building and encoding both, and every
full-dump request held 179 MB besides the price map.

The v2 dump holds 160,350 card ids, 2.18 M store lists and 3.6 M entries,
1.65 per list.

## What changed

**Walking card by card.** A section of the response, retail or buylist, is
no longer gathered into one map of every card before it is written. It
takes the ids every enabled store prices, keys each printing once, sorts
them by id, and for each id merges every store's entries for its printings
and writes the card at once. `GetUUID` runs once per printing instead of
once per printing per store, nothing holds the whole response, and the
first cards leave as soon as they are made.

**Writing without reflection.** `banprice.Writer` writes each card exactly
as `encoding/json` would, keys sorted and escaped. On the live retail dump
decoded and written again:

| | Time | Allocated | Allocations |
|---|---|---|---|
| `json.Encoder` | 0.74-0.85 s | 736 MB | 5.0 M |
| `banprice.Writer` | 0.38-0.40 s | 14.3 MB | 64 |

Most of `encoding/json`'s allocations were the slices it sorts every map's
keys in; the writer reuses two.

Together, on sellers and vendors rebuilt from the live retail, buylist and
sealed dumps, best of 3, locally:

| Full dump | Gather, then write | Walk card by card |
|---|---|---|
| Retail, `mtgban` ids | 3.29 s | 1.73 s |
| Retail, `tcg` ids | 5.02 s | 1.80 s |
| Buylist, `mtgban` ids | 0.92 s | 0.66 s |

The responses are the same bytes: 140 of them, every id mode for retail,
buylist and both, full dumps with and without a finish filter, three
editions, a list of cards, and sealed, hashed before and after.

## Shapes considered

Before keeping the shape, the live retail dump was rewritten in others:

| Shape | Raw | gzip -6 |
|---|---|---|
| Card, finish, store, objects (kept) | 178.7 MB | 22.9 MB |
| The same with tuples for entries | 103.5 MB | 20.3 MB |
| Store first, tuples | 188.7 MB | 50.3 MB |
| Flat rows | 299.1 MB | 31.8 MB |

Grouping by card writes each 36-character uuid once; store-first and flat
rows repeat it, which gzip cannot fold. Tuples save bytes at the price of
positional fields. Keying entries by their condition, measured apart, saves
18% raw and 3.5% gzipped, and loses best-first order.

## After

To be measured on the live site once deployed.

## Prices as strings

A JSON string does not change rounding. Rounded to the cent and written as
a number, none of the dump's 3,615,391 prices prints more than two
decimals, and every one parses back to the same value; Python and
JavaScript read `26.57` as 26.57. Float noise appears only when a client
does arithmetic on prices, and a string avoids it only for a client that
parses it into a decimal type. Strings would add two bytes a price and
change the field's type for every client.

How to round is a separate choice: 768 prices sit on a half cent, such as
2.605, which `math.Round(p*100)/100` takes to 2.61 and `%.2f` to 2.60,
since the stored binary value is just below the half. 1,930,648 prices are
whole cents already.
