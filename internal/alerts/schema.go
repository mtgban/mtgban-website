package alerts

const schemaSQL = `
CREATE TABLE IF NOT EXISTS alert_contacts (
    user_hash        TEXT PRIMARY KEY,
    discord_user_id  TEXT,
    tier             TEXT NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS alerts (
    id               BIGSERIAL PRIMARY KEY,
    user_hash        TEXT NOT NULL REFERENCES alert_contacts(user_hash) ON DELETE CASCADE,
    game             TEXT NOT NULL,
    card_id          TEXT NOT NULL,
    side             TEXT NOT NULL CHECK (side IN ('retail', 'buylist')),
    condition        TEXT NOT NULL DEFAULT 'NM' CHECK (condition IN ('NM', 'SP', 'MP', 'HP', 'PO')),
    stores           TEXT[] NOT NULL DEFAULT '{}',
    reference_price  NUMERIC(10,2) NOT NULL,
    above_kind       TEXT CHECK (above_kind IN ('abs', 'pct')),
    above_value      NUMERIC(10,2),
    below_kind       TEXT CHECK (below_kind IN ('abs', 'pct')),
    below_value      NUMERIC(10,2),
    delivery         TEXT NOT NULL DEFAULT 'discord' CHECK (delivery IN ('discord', 'email')),
    status           TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused', 'over_allowance', 'undeliverable', 'unresolvable')),
    above_armed      BOOLEAN NOT NULL DEFAULT true,
    below_armed      BOOLEAN NOT NULL DEFAULT true,
    last_fired_at    TIMESTAMPTZ,
    last_error       TEXT NOT NULL DEFAULT '',
    card_name        TEXT NOT NULL,
    card_set         TEXT NOT NULL,
    card_number      TEXT NOT NULL,
    card_finish      TEXT NOT NULL,
    created_price    NUMERIC(10,2),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (above_kind IS NOT NULL OR below_kind IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS alerts_game_active ON alerts (game) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS alerts_by_user ON alerts (user_hash, game, created_at DESC);

CREATE TABLE IF NOT EXISTS alert_events (
    id          BIGSERIAL PRIMARY KEY,
    alert_id    BIGINT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    fired_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    threshold   TEXT NOT NULL CHECK (threshold IN ('above', 'below')),
    store       TEXT NOT NULL,
    price       NUMERIC(10,2) NOT NULL,
    delivered   BOOLEAN NOT NULL,
    error       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS alert_events_by_alert ON alert_events (alert_id, fired_at DESC);
CREATE INDEX IF NOT EXISTS alert_events_fired_at_idx ON alert_events (fired_at);
`
