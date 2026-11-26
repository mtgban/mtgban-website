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

// createPatreonSessionsSQL is the table a Patreon login's refresh token
// lives in, one row per login; additive, so a later start applies it to an
// existing database. The token and the session id are stored as they are:
// a refresh token redeems only with the client secret, which lives in the
// infrastructure config, and a session id renews only beside its reader's
// signature, which the database never holds. patreon_user and client_id
// name the Patreon account and the client its token was issued to: Patreon
// keeps one token per pair, so the sessions of a pair renew together. lease
// names the holder of the current renewal, set on every session of the pair
// together, so a holder that outlived its lease cannot commit; it is null
// again once the renewal commits, so an empty fence matches nothing.
const createPatreonSessionsSQL = `
CREATE TABLE IF NOT EXISTS patreon_sessions (
    session_id    TEXT PRIMARY KEY,
    email_hash    TEXT NOT NULL,
    patreon_user  TEXT NOT NULL,
    client_id     TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    lease         TEXT,
    first_login   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_renewed  TIMESTAMPTZ NOT NULL DEFAULT now(),
    renew_after   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS patreon_sessions_email ON patreon_sessions (email_hash);
CREATE INDEX IF NOT EXISTS patreon_sessions_account ON patreon_sessions (patreon_user, client_id);
CREATE INDEX IF NOT EXISTS patreon_sessions_expires ON patreon_sessions (expires_at)`

// The table predates the backpack where this runs, so the column is added
// to an existing one too; ALTER needs the table owner, so NewClient runs it
// only when backpackColumnSQL finds no column.
const addBackpackSQL = `ALTER TABLE user_state ADD COLUMN IF NOT EXISTS backpack JSONB NOT NULL DEFAULT '[]'`

const backpackColumnSQL = `SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'user_state' AND column_name = 'backpack'`

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

// createInvitesSQL is the invite links an admin mints and each acceptance
// of them, additive like the tables above (docs/adr/0011-invite-links.md).
// A redemption's nonce is the accept form's, so a repeat of the same POST
// is answered from its row instead of spending a second use.
const createInvitesSQL = `
CREATE TABLE IF NOT EXISTS invites (
    code          TEXT PRIMARY KEY,
    game          TEXT NOT NULL,
    tier          TEXT NOT NULL,
    overrides     JSONB NOT NULL DEFAULT '{}',
    max_uses      INTEGER NOT NULL,
    uses          INTEGER NOT NULL DEFAULT 0,
    access_days   INTEGER NOT NULL,
    open_until    TIMESTAMPTZ NOT NULL,
    note          TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by    TEXT NOT NULL,
    created_ip    TEXT NOT NULL,
    created_ua    TEXT NOT NULL,
    created_site  TEXT NOT NULL,
    revoked_at    TIMESTAMPTZ,
    revoked_by    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS invites_created ON invites (created_at DESC);
CREATE TABLE IF NOT EXISTS invite_redemptions (
    id            BIGSERIAL PRIMARY KEY,
    code          TEXT NOT NULL REFERENCES invites (code) ON DELETE CASCADE,
    nonce         TEXT NOT NULL,
    redeemed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL,
    ip            TEXT NOT NULL,
    ua            TEXT NOT NULL,
    site          TEXT NOT NULL,
    signed_in     BOOLEAN NOT NULL DEFAULT false
);
CREATE UNIQUE INDEX IF NOT EXISTS invite_redemptions_nonce ON invite_redemptions (code, nonce)`
