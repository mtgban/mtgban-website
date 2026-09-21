# MTGBAN Cardmarket Export

A browser extension that reads the offers listed on a Cardmarket page and
writes them out as a CSV the site's `/upload` page can read.

The parsing happens in the browser. Nothing is sent anywhere: the extension
produces a file, you look at it, and you upload it yourself if you want to.

## What it does

On any Cardmarket page that lists offers, a button appears in the bottom right
saying how many it can see. Clicking it downloads
`mkm-<game>-<date>.csv` and reports how many rows were exported and how many
were skipped.

It works on all seven games Cardmarket sells: Magic, Pokemon, YuGiOh, Lorcana,
One Piece, Flesh and Blood and Riftbound.

## The CSV

```
mcm_id,card_name,edition,condition,foil,quantity,article_id
265854,Mirri's Guile,Time Spiral,NM,,3,111111
300001,Sorcerous Spyglass,Zendikar,SP,foil,1,222222
,Charizard,Base Set,HP,,1,555555
```

`mcm_id` is the Cardmarket product id, which the site resolves straight to a
card. When a row carries none — as the third one above does — the upload falls
back to matching on `card_name` and `edition`, so the row still lands.

`article_id` is the offer's own id on Cardmarket. The site ignores it; it is
there so a row can be traced back to the listing it came from.

**There is no price column, deliberately.** The upload compares a price it is
given against mtgban's own, which are dollars, and every price on Cardmarket is
euros. A price column here would be read as the currency it is not, and a
valuation wrong by an exchange rate is worse than one the site works out for
itself.

Rows for cards the seller has marked Altered, Signed or Inked are skipped: they
are not the printing the catalog knows, and no id names them.

## Installing it

The same unpacked folder works in all three browsers.

**Chrome** — go to `chrome://extensions`, turn on Developer mode, click *Load
unpacked*, and pick this `extension/` folder.

**Firefox** — go to `about:debugging#/runtime/this-firefox`, click *Load
Temporary Add-on*, and pick `extension/manifest.json`. Firefox drops a
temporary add-on when it restarts, so this needs redoing each session.

**Safari** — Safari runs the same extension but wants an app around it, which
needs Xcode:

```
xcrun safari-web-extension-converter extension/
```

Run the generated project once, then enable the extension in Safari's settings.
For an unsigned build, Safari's Develop menu has to have *Allow Unsigned
Extensions* turned on, which Safari resets when it quits.

## Permissions

None beyond running on Cardmarket's own pages. There is no background script,
no storage, no network access, and no extension API call anywhere in the code —
the parse is a DOM read and the download is a blob and an anchor, both plain web
platform. That is also why one build runs unchanged on all three browsers.

## Limitations

It exports **the offers on the page you are looking at**. Cardmarket paginates,
so a large list needs exporting a page at a time and the files concatenating.

It reads Cardmarket's current markup. A redesign would break it, and the honest
failure is visible rather than silent: the button reports either "No offers on
this page" or "None of the N offers here could be read", and the second of those
means the markup moved.

## Tests

`test/run.html` checks the parser against a fixture standing in for a page.
Open it over HTTP — `file://` will not run the scripts:

```
python3 -m http.server 8731 --directory extension
```

then open `http://localhost:8731/test/run.html`. It prints a line per check and
`ALL CHECKS PASSED` at the end.

The other half of the contract — that the CSV above is read the way it is meant
to be — is pinned on the Go side, in `internal/docparse`.
