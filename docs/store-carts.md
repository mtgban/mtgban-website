# Loading a list into a store's cart

Neither ABU Games nor Cool Stuff Inc has a decklist or CSV import for its
buylist, and neither has a partner import like Card Kingdom's
`sellcart/partner_import`. Both have the cart call their own pages make,
and both calls take a list. MTG Mint Card and Card Kingdom's store have the
same kind of call, one card at a time, and Hareruya both: a form that takes
a whole store list, and one call per card for its buylist. Star City Games
and Strike Zone have a CSV import, but no way to hand it a list from
another site. The upload page reaches all seven through one bookmarklet,
BAN-to-Cart, run on the store's page. ABU was measured against a real
account on 2026-10-07, CSI, Strike Zone and Hareruya against a guest cart
and SCG and Mint against a real account on 2026-10-09, and Card Kingdom
against a guest cart on 2026-10-10.

## ABU: the calls

Both carts work the same way: a `POST` with the user's own token as
`Authorization: Bearer <token>` and a JSON array body.

```json
[{"item_id": "1110247", "quantity": 2}, {"item_id": "1110315", "quantity": 1}]
```

| | Buylist | Store |
|---|---|---|
| Add rows | `POST /buy-list-cart/item` | `POST /cart/item` |
| Read, empty | `GET`, `DELETE /buy-list-cart` | `GET`, `DELETE /cart` |
| Cart page | `/cartview/buylist` | `/cartview/shop` |
| Cap in ABU's browser code | 750 lines | 1,000 lines |

All paths are on `https://api.abugames.com`, and the cart pages on
`https://abugames.com`.

- `item_id` is ABU's per-condition row id, the `InstanceID` go-mtgban's
  `abugames` scraper stores on every buylist entry (`ABUGames`,
  `ABUCredit`) and every singles inventory entry (`ABUGames`, `ABUScans`,
  `ABUGraded`). Cash and credit share one buylist cart; the seller picks
  at checkout. Sealed entries carry no `InstanceID`, so sealed product
  cannot be loaded this way yet.
- ABU's site also sends prices, a title and a `ptype`. None of them are
  needed: ABU prices each row from its own catalog.
- Quantity 0 removes a row.
- Both carts answer 401 to a request with no token, an empty one or a
  made-up one, so nothing can be loaded without a token ABU issued.
- ABU gives every visitor who is not logged in a guest token, in the same
  `localStorage` key. With it the store cart loads normally, but the
  buylist cart answers 500 with a raw database error, since a buylist
  cart needs an account.
- A guest's store cart does not follow the user when they log in: rows
  loaded before logging in are gone afterwards. The user logs in first.
- CORS allows any origin for `POST` with `authorization` and
  `content-type`, but the token sits in `localStorage` on abugames.com,
  where no mtgban page can read it. It lasts a year.
- Both carts expire after 60 minutes of inactivity.

| Sent | Buylist | Store |
|---|---|---|
| many rows in one request | 500 rows in 5.4 s | 100 rows in about 100 s |
| more lines than ABU's browser cap | accepted (854) | not tested |
| a card already in the cart | quantity replaced | quantity replaced |
| the same id twice in one request | the first one kept | the first one kept |
| more than ABU has or wants | accepted as sent | trimmed to stock |
| a row ABU has none of | accepted, counted in the total | skipped, rest of the list kept |
| an id that does not exist | 422, stops part-way | 422, stops part-way |

A 422 keeps the rows before the bad id and drops the rows after it, and
does not say which id failed: its message is literally
`Item %d does not exist`.

The store side checks stock row by row, at about a second a row, so a
1,000-line list takes over a quarter of an hour.

## CSI: the call

CSI's sell list page adds a row with a form `POST` to
`https://www.coolstuffinc.com/ajax_buylist.php`, and the same call takes
many rows at once:

```
ajaxtype=addtocart
ajaxdata=uid_3813340qty_1||uid_3813344qty_2||
```

- `uid` is the sell list row's `PPQID`, one printing and finish. CSI buys
  NM only: its Magic sell list holds "Near Mint" and "Foil Near Mint"
  rows, plus sealed "New" rows. go-mtgban's `coolstuffinc` scraper stores
  the `PPQID` as `InstanceID` on every buylist entry (`CSI`,
  `CSISealed`), the graded entries it derives from a row included.
- The cart is the browser's, kept by CSI's cookies, guests included. No
  token is involved, but the cookies carry no SameSite attribute and the
  call sends no CORS headers, so only a page on coolstuffinc.com can
  reach the cart.
- The cart page is `/buylist_cart.php`, and keeps a `#` fragment even
  with an empty cart. Its form names one field per row, `bl_q[<PPQID>]`,
  which is how the bookmarklet reads the cart back.
  `/buylist_cart.php?pa=clean` empties it.
- A sell order needs $10 or more in the cart before CSI takes it.

| Sent | Result |
|---|---|
| many rows in one request | 300 rows in 11 s |
| a card already in the cart | quantity added to |
| an id CSI does not buy | skipped quietly, rest of the list kept |
| more than CSI wants | trimmed to CSI's own limit |

### CSI's store cart

CSI's store adds rows to its cart in one call, keyed by product and row:
each offer row of a product, one per condition and finish, carries its row
id on its Add to Cart button (`data-atc="atc[434190][10753983]"`).

```
POST /ajax_cart_qty_add.php   atc[434190][10753983]=1&atc[434190][10753986]=2&referrer=
GET  /main_view_cart.php      cartQty[<row id>] per row
GET  /main_view_cart.php?action=delete-<row id>
```

- go-mtgban's `coolstuffinc` scraper stores the product id as
  `OriginalID` and the row id as `InstanceID`, and `csiCartID` names a row
  `<product id>-<row id>`. The row id decides what lands; the product id
  only has to be non-zero.
- The add takes many rows at once, adds to a row already in the cart, trims
  to the stock and skips a row CSI does not sell. So the bookmarklet adds
  the difference for a row already there, and deletes and adds again a row
  the list wants fewer of.
- go-mtgban folds two offers of one card in the same grade and at the same
  price into one entry, keeping the first row's id, so such an entry's
  stock could span two rows and a large quantity come up short. No such
  entry was among 3,944 offers of five etched-heavy sets on 2026-10-10.

| Sent | Result |
|---|---|
| one add of 40 rows | 3.6 s, all 40 |
| a row already in the cart | added to |
| above the stock | trimmed to it |
| a delete | 0.34 s |

## Mint: the call

Mint's buylist cart page sets a row's quantity with a `GET`, and the same
call adds a card not yet in the cart:

```
https://www.mtgmintcard.com/ajax_index.php?ajax_main_page=ajax_buylist_cart_detail
    &action=update_buy_list_product&buylist_cart_product_id=8137&buylist_cart_product_qty=2
```

- The id is Mint's `products_id`, one printing and finish, which its feed
  carries as `Id` and go-mtgban's `mintcard` scraper stores as
  `InstanceID`. Mint's feed prices no foil on the buylist, though its
  buylist page buys foils, so those cannot be loaded.
- The cart is kept by Mint's `zenid` session cookie, guests included, so
  only a page on mtgmintcard.com can reach it.
- The call takes one id: given two, Mint keeps the last. The Sell buttons'
  own call (`ajax_buylist_cart`, `action=sell_now`) takes one id as well,
  and adds to a row's quantity instead of setting it.
- The cart page is `/buylist-cart`, with one `multiple_quantity_<id>`
  picker per row, which is how the bookmarklet reads the cart back.

| Sent | Result |
|---|---|
| one row per call | 10 calls in 10.4 s |
| a card already in the cart | quantity replaced |
| more than Mint wants | trimmed to Mint's own limit |
| an id Mint does not buy, or a store-only id | skipped quietly, 200 |
| quantity 0 | row removed |

## Strike Zone: the CSV import

Strike Zone buys and sells through one cart, whose Tools menu has a CSV
import that takes a whole list in one upload:

```
POST /TUser?MC=CUVC&MF=B   (multipart)
BUID=637  STORE_ID=637  CMD=Tools ...  TOOL_SELECT=CI  ACT=Do import  FILE=<csv>

#Usc Id,Inventory Name,Store Name,Buy #,Buy $,Sell #,Sell $
USCIDU-637-F-19290-285-OVN-RMS,x,Strike Zone Online,2,0,NC,0
```

- `Buy #` is the quantity sold to Strike Zone, `Sell #` the quantity bought
  from it; the other columns are ignored. The cart lists the first kind of
  row as `B-637-C-…` and the second as `S-637-C-…`.
- The import sets a card's quantity, trims it to the buylist's "Need" or to
  the stock, ignores a quantity of 0, and does nothing to a cart with no row
  yet, on either side. Uploads of 300, 1,000 and 3,000 rows took 2, 7 and
  44 s, and each loaded whole.
- The cart page lists only the first 800 rows, with no way to page on, so
  the bookmarklet reads the cart through "Export to CSV", which lists every
  row by its import id; a buylist row's name starts "Sell to us - ". An
  empty cart's export answers with the cart page instead.
- The cart is kept by Strike Zone's cookies, guests included, and the site
  is plain HTTP.

The `#Usc Id` is what the cart's "Export to CSV" writes, and no page
publishes it. go-mtgban's `strikezone` scraper computes it from the code
each row's "Sell to Us" or "Add to Cart" link carries,
`637-C-<item>-<variant>`, and stores it as `InstanceID`, one id for both
sides; its README has how. The bookmarklet only undoes the first step, a
shift of the item and variant digits by `8 9 7 2 9 1 8 9 7` (mod 10), to
find the row's plain code in the cart (`szCode`). A code of a shape
go-mtgban cannot compute the id for stays plain, and goes through its link.

The links add one copy of a card per `GET`, and the cart page's form sets
quantities, but cannot add a row:

```
http://shop.strikezoneonline.com/TUser?MC=CUVC&Buy=637-C-181059-106&MF=B&BUID=637
http://shop.strikezoneonline.com/TUser?MC=CUVC&Add=637-C-181059-106&MF=B&BUID=637

POST /TUser?MC=CUVC&MF=B
BUID=637&STORE_ID=637&0=B-637-C-181059-106&0Q=3&CMD=Update
```

The cart pages answer "Error: 8134 - too many requests", with a 200, once an
IP has made about 100 calls to them, at full speed and at one a second
alike, for 5 to 10 minutes. It applies only to the cart pages, not the
buylist pages the scraper reads.

| Sent | Result |
|---|---|
| the import, 40 buylist cards from an empty cart | 4 requests, 0.5 s, all 40 loaded |
| the import, 1,000 rows in one upload | 7 s, all 1,000 in the export, 800 on the page |
| the import, above what Strike Zone wants or has | trimmed to its "Need" or stock |
| the import, into a cart holding only the other side's rows | loaded |
| an id or code Strike Zone does not list | skipped quietly |
| one card per link | 100 calls in 11.7 s, until the limit |
| the form, quantity 0 | row removed |

## Hareruya: the forms

Hareruya keeps two carts on one site, a store cart and a buylist
("purchase") cart, both kept by its session cookie, guests included, and
both keyed by a `product_class_id`. A store lot sells each condition under
its own class (Lightning Bolt [4ED], product 3833: NM 27947, SP 27948, MP
27949, HP 27950), and the buylist buys a card under one class whatever its
grade. go-mtgban's `hareruya` scraper stores the class each row's cart
button adds as `InstanceID`.

| | Store | Buylist |
|---|---|---|
| Cart page | `/en/cart` | `/ja/purchase/cart` |
| Add one card | `POST /en/cart/add` | `POST /ja/purchase/add` |
| Set quantities | `POST /en/cart/update` | `POST /ja/purchase/update` |
| Most of one card | the stock | 20; more answers 400 `overlimit` |

```
POST /en/cart/add          product_class_id=27947&quantity=2
POST /en/cart/update       qty[27947]=1&qty[27948]=2&qty[436375]=1
```

- An add takes one class (two answer 500) and adds to the quantity
  already in the cart. A class the store does not sell or buy, or a
  quantity of 0, is skipped quietly. The store's add answers with the whole
  cart as JSON.
- The store's update form sets each quantity it names, trimmed to the
  stock, adds a class not yet in the cart, and removes one set to 0, so
  one request takes a whole list. The buylist's form sets and removes, but
  adds nothing, so new cards go through its add. Its page carries a CSRF
  token for the form, which the form does not need.

| Sent | Result |
|---|---|
| the store form, 600 classes from the published dump | 7.4 s, 596 loaded, 4 sold since |
| the store form, 200 classes | 2.9 s, 197 loaded, 3 sold since |
| the store form, above the stock | trimmed to the stock |
| the buylist add, 100 cards one after another | 30 s, all 100, no limit met |
| the buylist add, above 20 | 400 `overlimit` |

## Card Kingdom: the store cart

The site shows no button for this cart for now; see "What the site does".

Card Kingdom's buylist already takes a whole list through
`sellcart/partner_import`. Its store has no such import: its deck builder
(`/builder`, where the upload page's other CK button posts the names) is a
search, and the user picks each printing there. The store cart's own add
call takes one card, by product id and grade:

```
POST /api/cart/add   {"product_id": 10190, "style": "EX", "quantity": 2}
GET  /api/cart       {"lineitems": [{"product_id": 10190, "style": "EX", "qty": 2}, ...]}
```

- The product id is the printing's CK id, which go-mtgban's `cardkingdom`
  scraper stores as `OriginalID`. The style is CK's name for the grade: NM,
  EX, VG or G for our NM, SP, MP and HP. `ckCartID` builds a row as
  `<product id>-<style>`, for the `CK` split alone: sealed rows carry no CK
  id, and a graded slab's add was never measured, so `CKSealed` and
  `CKGraded` splits get no button.
- An add sets the quantity, and 0 removes the row. Above the stock it
  answers 400 `MaxQuantityExceeded` with how many there are, and the
  bookmarklet sends the card again at that. A product it does not have
  answers 200 with a message.
- The cart is kept by CK's cookies, guests included. No token is needed.

| Sent | Result |
|---|---|
| 30 cards from the published dump, across the four grades | 38 s, all 30 at the asked quantity |
| an add | 0.4 to 2.5 s |
| two cards in one body | 422 |

## SCG: the CSV import

SCG's sell site, `https://sellyourcards.starcitygames.com`, adds one card
per call (`POST /api/cartAddNamedItem`, keyed by `bc_variant_id`) and
answers 500 unless the call carries the card's prices. The CSV import its
uploads page offers takes the whole list and prices it itself:

- `POST /api/CSV2/upload`, multipart: the file, `fileFormatId=1` ("Star
  City Games Export"), and the defaults for rows it cannot read, the same
  fields the site's own form sends. The answer names a `fileId`.
- SCG matches a row on its SKU alone, so a file of `quantity,productid`
  is enough. The SKU names the condition, and is the `InstanceID`
  go-mtgban's `starcitygames` scraper stores on every buylist entry.
- `/mtg/uploads/<fileId>` is SCG's review of the file: the rows it matched,
  split into its sell list and bulk list, and the rows it could not match,
  for the user to fix. Its own "Add to Sell Cart" button fills the cart.
  An upload stays in the user's upload history for 5 days; nothing deletes
  it sooner.
- The site needs a login, and its calls carry the session cookie and the
  `XSRF-TOKEN` cookie back as an `X-XSRF-TOKEN` header. An upload without
  a login answers 401.

## What the site does

Each store split the upload optimizer lists gets a "Load at" button where
the store's cart can take it: ABU's, CSI's, Strike Zone's and Hareruya's
buylist and store splits, and SCG's and Mint's buylist splits. CSI's store
button sits beside its deck builder button, which posts only names. SCG's
store side and CK's buylist already have their own imports. Card Kingdom's
store split gets no button for now, though the bookmarklet still fills its
cart: a load logged a signed-in user out, and the cause is not known yet. The arbit, reverse and global pages give
each section the same buttons: "Load at" for the store it buys from and
"Load buylist at" for the store it sells to, each row in the condition the
store sells it in (`cartLoadForArbit`).

- `cartLoadFor` (`cartload.go`, the `cart_load` template function) builds
  the button, and `cartRows` turns the split into `item_id:quantity`
  pairs. Each id names one condition.
  - A buylist row always goes in as NM, and the store grades what
    arrives, so the cart quotes NM prices and reads higher than the
    split's total when the list has played cards; the panel says so.
    Sealed product carries no grade and goes in as listed. ABU lists an
    NM row for every card but prices a few at $0, which the scraper
    drops, so those cards are left out: on 2026-10-08, 24 of the 123,818
    cards ABU buys. 22 paid $0.01 to $0.03 played; the two Secret Lair
    1480 Swamps paid about $1, which looks like a pricing slip at ABU.
  - A store row uses the entry the optimizer priced it from: the one in
    the row's condition, or the store's first priced entry when the row
    names none.
  - A card the store has no entry for is left out, as `uuid2BuylistCSV`
    does for CK and SCG. Rows sharing an id are merged by adding their
    quantities, since ABU would keep only the first.
- The button opens the store's cart page, SCG's uploads page for SCG, with
  the pairs in the fragment,
  `https://abugames.com/cartview/buylist#ban=<id>:<qty>,...&v=<version>`,
  and `&side=retail` on a store split's link, since Strike Zone's two sides
  share one cart page. The fragment survives every store's page and never
  reaches their servers or ours. Where an affiliate code is configured for
  the store, the page is opened the way the store's own links from us are
  (`cartAffiliates`), so the cart it fills is credited the same way: Card
  Kingdom's `partner` and `utm_*` query, Mint's `utm_*` query, CSI's
  `utm_referrer`, and SCG's partner redirector,
  `goto.starcitygames.com/c/<code>/…?u=<page>`, which lands on the sell site
  with the fragment intact.
- Pressing the button first shows a panel (`js/cart-prompt.js`, from the
  `cart-prompt` partial both pages share), named for the store and side
  pressed, holding the loader to drag to the bookmarks bar:
  `js/ban-to-cart.js` as a `javascript:` link (`cart_bookmarklet`). It
  says to click the bookmark after the store's page loads, since nothing
  on that page can. Its Continue @ store button continues to the store, and
  "Don't show this again", kept in `localStorage`, lets later presses go
  straight there. The "?" beside the button always shows the panel, so
  the loader can be had again.

## The bookmarklet

Clicked on the page a button opened, `js/ban-to-cart.js` picks the store
from the page's host. It first checks it is the loader the site expects:
`cartLoader` stamps the start of the file's hash into the bookmarklet and
onto every link (`&v=`), so a bookmark saved before the file last changed
says it is out of date and asks to be dragged again, and touches no cart.
On SCG it then uploads the list as one CSV and opens SCG's review of it.
On ABU, CSI, Mint, Strike Zone, Hareruya and Card Kingdom it:

1. on ABU, stops unless ABU's own `isLoggedIn` flag is set, since a
   guest's buylist cart fails and a guest's store cart is lost at login;
   on Mint, stops while the page links to Mint's login page, which it
   does only for a guest, since a sell order needs an account;
2. reads the cart and stops at ABU's caps, 750 buylist lines or 1,000
   store lines, counting what is already there, and says what was left
   out; the other stores have no cap;
3. sends the rows in chunks with a progress banner: 300 for ABU's
   buylist, 50 for ABU's store so each request finishes in under a
   minute, 100 for CSI, and one at a time for Mint, about a second each;
   on Strike Zone, 300 per CSV import, under `Buy #` or, for a link that
   says `side=retail`, `Sell #`, after cards through their links until one
   stays when the cart is empty, since Strike Zone skips a card it no
   longer lists, with a plain code through its link and the cart form, and
   a "too many requests" answer waited out for 5 minutes before the call
   is made again; on Hareruya, 500 per store form, and on its buylist, one
   add per card the cart page does not list, at most 20 of it, then one
   form per 50 cards setting every quantity, so a card the page left out
   still ends at the list's; it stops before sending anything when the
   link's `side=retail` and the cart page disagree; on Card Kingdom, one
   add per card, 10 to a chunk, again at the stock where CK has fewer;
4. on ABU's 422, reads the cart back and tries each row missing from it
   alone until ABU refuses one, the id it does not know, then resends the
   rest; ABU's store also leaves out rows it has none of, so the first
   missing row is not always the unknown one;
5. reads the cart once more and reports what loaded, what the store left
   out, and what did not fit, then clears the fragment and reloads the
   page.

ABU's token, and the other stores' cookies, never leave the store's site.
Pasting an ABU token into mtgban would work too, since ABU's CORS is open,
but it would put a year-long credential in our page. Logging in to a
store through mtgban is not an option: we would be handling people's
passwords. Nor can mtgban post to SCG itself: SCG's session cookie is
`SameSite=Lax`, its CORS answers `*`, which a browser refuses to send
cookies to, and every call must echo SCG's `XSRF-TOKEN` cookie.

## Not tested

- What an expired ABU token returns, presumably the same 401.
- What ABU's buylist checkout does with rows above its buy limit or rows
  it stopped buying.
- ABU store lists above 1,000 lines, and bundles, which ABU's site sends
  to `/cart/group` and `/cart/set` instead.
- Whether a CSI guest's sell cart follows the user when they log in, and
  the same for Strike Zone.
- How long Strike Zone's call limit lasts, and whether calls made while it
  holds lengthen it.
- Strike Zone codes with an item of other than five or six digits, which
  go through their links.
- Whether Hareruya's guest carts follow the user at login, and whether its
  cart pages list every row past the 597 measured; the loader sets every
  quantity through the forms, so a row a page leaves out is not doubled.
