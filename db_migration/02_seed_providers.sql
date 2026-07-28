-- Provider seed (plan section 4 / 17.5). Idempotent.
-- Shared TCGplayer ids 3/4 across Magic (scraper) and non-Magic (tcgcsv) per D1.
-- Cardmarket is EUR; everything else USD.
INSERT INTO public.providers (id, shorthand, public_name, kind, currency) VALUES
    (1,  'CKRetail',     'Card Kingdom Retail',      'retail',  'USD'),
    (2,  'CKBuylist',    'Card Kingdom Buylist',     'buylist', 'USD'),
    (3,  'TCGLow',       'TCGplayer Low',            'retail',  'USD'),
    (4,  'TCGMarket',    'TCGplayer Market',         'retail',  'USD'),
    (5,  'TCGMid',       'TCGplayer Mid',            'retail',  'USD'),
    (6,  'TCGHigh',      'TCGplayer High',           'retail',  'USD'),
    (7,  'TCGDirectLow', 'TCGplayer Direct Low',     'retail',  'USD'),
    (8,  'MKMLow',       'Cardmarket Low',           'retail',  'EUR'),
    (9,  'MKMTrend',     'Cardmarket Trend',         'retail',  'EUR'),
    (10, 'SCGBuylist',   'Star City Games Buylist',  'buylist', 'USD'),
    (11, 'ABUBuylist',   'ABU Games Buylist',        'buylist', 'USD'),
    (12, 'CSIBuylist',   'Cool Stuff Inc Buylist',   'buylist', 'USD'),
    (13, 'SealedEV',     'Sealed EV (TCG Low)',      'derived', 'USD')
ON CONFLICT (id) DO UPDATE
    SET shorthand   = EXCLUDED.shorthand,
        public_name = EXCLUDED.public_name,
        kind        = EXCLUDED.kind,
        currency    = EXCLUDED.currency;
