# direct-window

Measures which trailing window of Direct prices best stands in for a precon SYP card's missing Direct price, from the newspaper's rolling week of listings.
Flags (the script blank-imports `mtgmatcher/games`, as the site does, so the loader knows Magic): `-config` (the site config holding `new_newspaper_sql_config`), `-datastore` (`allprintings5.json`), `-syp` (one SYP card uuid per line).
Get `syp.txt` by loading the SYP vendor in a dev server (`-stores tcg_syplist`) and listing the uuids of its buylist, one per finish as the datastore keys them.
It needs the newspaper read-only account from the dev config; the output is the table `docs/direct-history.md` carries.
