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

// The table predates the backpack where this runs, so the column is added
// to an existing one too; ALTER needs the table owner, so NewClient runs it
// only when backpackColumnSQL finds no column.
const addBackpackSQL = `ALTER TABLE user_state ADD COLUMN IF NOT EXISTS backpack JSONB NOT NULL DEFAULT '[]'`

const backpackColumnSQL = `SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'user_state' AND column_name = 'backpack'`
