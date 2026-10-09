# Loading a list into a store's cart

Neither ABU Games nor Cool Stuff Inc has a decklist or CSV import for its
buylist, and neither has a partner import like Card Kingdom's
`sellcart/partner_import`. Both have the cart call their own pages make,
and both calls take a list. Star City Games has a CSV import on its sell
site, but no way to hand it a list from another site. The upload page
reaches all three through one bookmarklet, BAN-to-Cart, run on the store's
page. ABU was measured against a real account on 2026-10-07, CSI against a
guest cart and SCG against a real account on 2026-10-09.

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
the store's cart can take it: ABU's buylist and store splits, and CSI's
and SCG's buylist splits. CSI's and SCG's store sides already have their
own imports. The
arbit, reverse and global pages give each section the same buttons: "Load
at" for the store it buys from and "Load buylist at" for the store it sells
to, each row in the condition the store sells it in
(`cartLoadForArbit`).

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
  `https://abugames.com/cartview/buylist#ban=<id>:<qty>,...`. The
  fragment survives all three stores' pages and never reaches their
  servers or ours.
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
On ABU and CSI it:

1. on ABU, stops unless ABU's own `isLoggedIn` flag is set, since a
   guest's buylist cart fails and a guest's store cart is lost at login;
2. reads the cart and stops at ABU's caps, 750 buylist lines or 1,000
   store lines, counting what is already there, and says what was left
   out; CSI has no cap;
3. sends the rows in chunks with a progress banner: 300 for ABU's
   buylist, 50 for ABU's store so each request finishes in under a
   minute, 100 for CSI;
4. on ABU's 422, reads the cart back and tries each row missing from it
   alone until ABU refuses one, the id it does not know, then resends the
   rest; ABU's store also leaves out rows it has none of, so the first
   missing row is not always the unknown one;
5. reads the cart once more and reports what loaded, what the store left
   out, and what did not fit, then clears the fragment and reloads the
   page.

ABU's token, and CSI's and SCG's cookies, never leave the store's site.
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
- Whether a CSI guest's sell cart follows the user when they log in.
