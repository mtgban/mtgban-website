package userstate

import (
	"os"
	"strconv"
	"testing"
)

func TestHashEmail(t *testing.T) {
	// Lowercased before hashing, so case does not matter.
	a := HashEmail("User@Example.com")
	b := HashEmail("user@example.com")
	if a != b {
		t.Fatalf("expected case-insensitive hash, got %q vs %q", a, b)
	}
	// sha256 hex is 64 chars.
	if len(a) != 64 {
		t.Fatalf("expected 64-char hex hash, got %d chars", len(a))
	}
	if HashEmail("a@b.com") == HashEmail("c@d.com") {
		t.Fatal("distinct emails must hash differently")
	}
}

func testClient(t *testing.T) *Client {
	t.Helper()
	if os.Getenv("USERSTATE_TEST") == "" {
		t.Skip("USERSTATE_TEST not set; skipping DB integration test")
	}
	// USERSTATE_TEST_HOST, _PORT, _USER, _PASSWORD and _DB name the server,
	// each defaulting to the local one's.
	port, err := strconv.Atoi(testEnv("USERSTATE_TEST_PORT", "5432"))
	if err != nil {
		t.Fatalf("USERSTATE_TEST_PORT: %v", err)
	}
	cfg := SQLConfig{
		Host: testEnv("USERSTATE_TEST_HOST", "127.0.0.1"), Port: port, User: testEnv("USERSTATE_TEST_USER", "mtgban"),
		Password: testEnv("USERSTATE_TEST_PASSWORD", "mtgban"), DBName: testEnv("USERSTATE_TEST_DB", "user_state"), SSLMode: "disable",
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// testEnv is the named variable when it is set, empty included, else def.
func testEnv(name, def string) string {
	v, ok := os.LookupEnv(name)
	if !ok {
		return def
	}
	return v
}

func TestNewClientEnsuresSchema(t *testing.T) {
	c := testClient(t)
	// Schema is created on NewClient; a trivial query against the table must work.
	var n int
	if err := c.db.QueryRow(`SELECT count(*) FROM user_state WHERE email_hash = $1`, "nope").Scan(&n); err != nil {
		t.Fatalf("query user_state: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 rows, got %d", n)
	}
}
