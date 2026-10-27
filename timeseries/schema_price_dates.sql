-- price_dates holds every day each game has prices for under each provider.
-- The screener anchors its windows on a game's newest day, which in prices
-- means walking past every other game's rows; here it is one primary-key read.
--
-- category is the game: CategoryMagic (1) for the canonical Magic rows, the
-- TCGplayer category for any other game's. UpsertLongPrices files each day it
-- writes, in the same transaction; db_migration/price_dates fills the days
-- written before that. Applied idempotently at startup by
-- (*Client).EnsurePriceDatesSchema.
create table if not exists public.price_dates (
    provider smallint not null,
    category integer  not null,
    date     date     not null,
    primary key (provider, category, date)
);
