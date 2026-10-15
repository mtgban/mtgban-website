package userstate

const createTableSQL = `
CREATE TABLE IF NOT EXISTS user_state (
    email_hash   TEXT PRIMARY KEY,
    favorites    JSONB NOT NULL DEFAULT '[]',
    recents      JSONB NOT NULL DEFAULT '[]',
    preferences  JSONB NOT NULL DEFAULT '{}',
    backpack     JSONB NOT NULL DEFAULT '[]',
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

// The table predates the backpack where this runs, so the column is added
// to an existing one too; ALTER needs the table owner, so NewClient runs it
// only when backpackColumnSQL finds no column.
const addBackpackSQL = `ALTER TABLE user_state ADD COLUMN IF NOT EXISTS backpack JSONB NOT NULL DEFAULT '[]'`

const backpackColumnSQL = `SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'user_state' AND column_name = 'backpack'`
