package userstate

const createTableSQL = `
CREATE TABLE IF NOT EXISTS user_state (
    email_hash   TEXT PRIMARY KEY,
    favorites    JSONB NOT NULL DEFAULT '[]',
    recents      JSONB NOT NULL DEFAULT '[]',
    preferences  JSONB NOT NULL DEFAULT '{}',
    version      BIGINT NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
)`

// createSharesSQL is the share-link table, additive like the alerts
// schema: a later start applies it to an existing database. The unique
// index holds one live share per owner and game.
const createSharesSQL = `
CREATE TABLE IF NOT EXISTS favorites_shares (
    share_id    TEXT PRIMARY KEY,
    email_hash  TEXT NOT NULL,
    game        TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS favorites_shares_by_owner_game ON favorites_shares (email_hash, game) WHERE revoked_at IS NULL`
