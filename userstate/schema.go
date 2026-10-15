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

// createUploadSharesSQL is the table a shared upload's rows wait in until
// their expiry; additive, so a later start applies it to an existing
// database.
const createUploadSharesSQL = `
CREATE TABLE IF NOT EXISTS upload_shares (
    share_key   TEXT PRIMARY KEY,
    email_hash  TEXT NOT NULL,
    rows        TEXT NOT NULL,
    buylist     BOOLEAN NOT NULL DEFAULT false,
    game        TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS upload_shares_expires ON upload_shares (expires_at)`
