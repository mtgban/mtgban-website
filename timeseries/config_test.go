package timeseries

import (
	"testing"

	"github.com/lib/pq"
)

// A key with an empty value stays out of the DSN: lib/pq would read the
// token after "password=" as the password, so "password= dbname=x" names no
// database and the server falls back to one named after the user. A value
// holding a space, quote or backslash is quoted, since a bare one ends at
// the space and reads the other two as quoting and escaping.
func TestDSN(t *testing.T) {
	tests := []struct {
		name string
		cfg  SQLConfig
		want string
	}{
		{
			name: "every value set",
			cfg:  SQLConfig{Host: "db", Port: 6432, User: "u", Password: "p", DBName: "prices", SSLMode: "require"},
			want: "host=db port=6432 user=u password=p dbname=prices sslmode=require binary_parameters=yes",
		},
		{
			name: "empty password",
			cfg:  SQLConfig{Host: "127.0.0.1", Port: 5432, User: "postgres", DBName: "postgres"},
			want: "host=127.0.0.1 port=5432 user=postgres dbname=postgres sslmode=disable binary_parameters=yes",
		},
		{
			name: "password the tokenizer would split",
			cfg:  SQLConfig{Host: "db", Port: 5432, User: "u", Password: `a b'c\d`, DBName: "x"},
			want: `host=db port=5432 user=u password='a b\'c\\d' dbname=x sslmode=disable binary_parameters=yes`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.DSN()
			if got != tt.want {
				t.Errorf("DSN() = %q, want %q", got, tt.want)
			}
		})
	}
}

// lib/pq's own parser reads a password and a database name back exactly,
// whatever spaces, quotes and backslashes they hold.
func TestDSNRoundTripsThroughLibPQ(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	for _, value := range []string{
		"plain",
		"two words",
		`it's`,
		`back\slash`,
		`a b'c\d`,
		`'quoted'`,
		`trailing\`,
		` padded `,
		`key=value`,
		`\'' \\`,
	} {
		t.Run(value, func(t *testing.T) {
			cfg := SQLConfig{Host: "db", Port: 6432, User: "u", Password: value, DBName: value}
			parsed, err := pq.NewConfig(cfg.DSN())
			if err != nil {
				t.Fatalf("NewConfig(%q): %v", cfg.DSN(), err)
			}
			if parsed.Password != value || parsed.Database != value {
				t.Errorf("NewConfig(%q) read password %q, dbname %q; want %q for both", cfg.DSN(), parsed.Password, parsed.Database, value)
			}
			if parsed.Host != "db" || parsed.Port != 6432 || parsed.User != "u" {
				t.Errorf("NewConfig(%q) read host %q, port %d, user %q", cfg.DSN(), parsed.Host, parsed.Port, parsed.User)
			}
		})
	}
}
