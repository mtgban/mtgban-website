# Loading a list into ABU's carts

ABU Games has no decklist or CSV import, for its buylist or its store, and
no partner import like Card Kingdom's `sellcart/partner_import`. What it
does have is the cart API its own site calls, and both carts take a list.
This note is what the upload page needs to offer "Load at ABU" and "Load
buylist at ABU" next to the existing buttons, measured against a real
account on 2026-10-07.

## The calls

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
  `content-type`, so a browser can make these calls from any page.
- Both carts expire after 60 minutes of inactivity.

## What the server does with a list

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

Quantity limits are ABU's to enforce, so the site sends what the user
asked for. The store enforces them itself; the buylist leaves them to
checkout. Our scraper only lists buylist rows with a buy quantity and
price above 0, so a row ABU stopped buying only reaches the cart when it
filled up after the last scrape.

## What the site does

Each ABU split the upload optimizer lists, buylist or store, gets a "Load
at ABU" button.

- `abuCartRows` (`abucart.go`, the `abu_cart` template function) turns the
  split into `item_id:quantity` pairs. ABU gives each condition of a card
  its own id, so the id is the condition.
  - A buylist row always goes in as NM, and ABU grades what arrives. ABU's
    cart therefore quotes NM prices, and reads higher than the split's
    total when the list has played cards; the panel below says so.
    ABU lists an NM row for every card, but prices a few at $0, which the
    scraper drops, so those cards are left out: on 2026-10-08, 24 of the
    123,818 cards ABU buys. 22 paid $0.01 to $0.03 played; the two Secret
    Lair 1480 Swamps paid about $1, which looks like a pricing slip at ABU.
  - A store row uses the entry the optimizer priced it from: the one in
    the row's condition, or ABU's first priced entry when the row names
    none.
  - A card ABU has no entry for is left out, as `uuid2BuylistCSV` does for
    CK and SCG. Rows sharing an id are merged by adding their quantities,
    since the server would keep only the first. Sealed entries carry no
    id, so sealed product gets no button.
- The button opens the matching cart page with the pairs in the fragment,
  `https://abugames.com/cartview/buylist#mtgban=<id>:<qty>,...`, which
  html/template percent-encodes. The fragment survives ABU's router and
  never reaches ABU's or our servers.
- Pressing the button first shows a panel (`js/abu-prompt.js`) holding
  the loader to drag to the bookmarks bar: `js/abu-cart.js` as a
  `javascript:` link (`abu_bookmarklet`). It says to click the bookmark
  after the page on ABU loads, since nothing on ABU's page can. Its
  Open @ ABU button continues to ABU, and "Don't show this again", kept
  in `localStorage`, lets later presses go straight there. The "?" beside
  the button always shows the panel, so the loader can be had again.

## Getting the token

The token is the hard part. mtgban has no ABU token of its own and needs
none: each call carries the token ABU issued the user when they logged in
on abugames.com. ABU keeps it in `localStorage` under `accessToken-ABU`
there, where no mtgban page can read it. It lasts a year.

The bookmarklet keeps the token where it is. Clicked on the cart page the
button opened, `js/abu-cart.js` runs on abugames.com and:

1. stops unless ABU's own `isLoggedIn` flag is set, since a guest's
   buylist cart fails and a guest's store cart is lost at login;
2. reads the cart and stops at its cap, 750 buylist lines or 1,000 store
   lines, counting what is already there, and says what was left out;
3. sends the rows in chunks, 300 for the buylist and 50 for the store so
   each request finishes in under a minute, with a progress banner;
4. on a 422, reads the cart back and tries each row missing from it alone
   until ABU refuses one, the id it does not know, then resends the rest;
   the store also leaves out rows it has none of, so the first missing row
   is not always the unknown one;
5. reads the cart once more and reports what loaded, what ABU left out,
   and what did not fit, then clears the fragment and reloads the page.

**Pasting the token** into mtgban also works, since CORS is open, but the
user has to dig it out of the browser's developer tools, and a year-long
credential would then sit in our page. If it is ever offered, it stays in
the user's browser and is never sent to our server.

Logging in to ABU through mtgban is not an option: we would be handling
people's ABU passwords.

## Not tested

- What an expired token returns, presumably the same 401.
- What buylist checkout does with rows above ABU's buy limit or rows it
  stopped buying.
- Store lists above 1,000 lines, and bundles, which ABU's site sends to
  `/cart/group` and `/cart/set` instead.
