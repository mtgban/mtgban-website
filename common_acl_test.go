package main

import (
	"testing"

	"github.com/mtgban/mtgban-website/internal/access"
)

// The editor must not accept a table that locks the site out of fixing it.
func TestValidateACLTable(t *testing.T) {
	if err := validateACLTable(access.Table{}); err == nil {
		t.Error("empty table accepted")
	}
	noAdmin := access.Table{"Root": {"Search": {}}}
	if err := validateACLTable(noAdmin); err == nil {
		t.Error("table without any Admin tier accepted")
	}
	ok := access.Table{"Root": {"Search": {}, "Admin": {}}, "Mods": {"Search": {}}}
	if err := validateACLTable(ok); err != nil {
		t.Errorf("valid table refused: %v", err)
	}
}
