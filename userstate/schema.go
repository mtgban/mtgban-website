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
