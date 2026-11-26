package invites

import (
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/internal/access"
)

var testRules = Rules{
	Table: access.Table{
		"Any":     {"Search": {}},
		"Pioneer": {"Search": {"SearchDownloadCSV": "false"}, "Upload": {"UploadOptimizer": "false"}},
		"Legacy":  {"Search": {"SearchDownloadCSV": "true"}, "Newspaper": {"NewsLarge": "true"}},
		"Root":    {"Search": {}, "Admin": {}},
	},
	Pages:   []string{"Search", "Newspaper", "Upload", "Arbit"},
	Options: []string{"SearchDownloadCSV", "NewsLarge", "UploadOptimizer"},
	Open:    "Any",
}

func TestNewCodeIsValid(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		code, err := NewCode()
		if err != nil {
			t.Fatal(err)
		}
		if !ValidCode(code) {
			t.Fatalf("NewCode drew %q", code)
		}
		seen[code] = true
	}
	if len(seen) < 200 {
		t.Errorf("200 draws gave %d codes", len(seen))
	}
	for _, bad := range []string{"", "abcdefg", "abcdefghj", "abcdefg0", "ABCDEFGH", "abcd efg"} {
		if ValidCode(bad) {
			t.Errorf("ValidCode(%q) = true", bad)
		}
	}
	if got := Normalize(" ABCDEFGH\n"); got != "abcdefgh" || !ValidCode(got) {
		t.Errorf("Normalize = %q", got)
	}
}

func TestNewNonceIsValid(t *testing.T) {
	nonce, err := NewNonce()
	if err != nil || !ValidNonce(nonce) {
		t.Fatalf("NewNonce = %q, %v", nonce, err)
	}
	for _, bad := range []string{"", "short", strings.Repeat("!", nonceLen)} {
		if ValidNonce(bad) {
			t.Errorf("ValidNonce(%q) = true", bad)
		}
	}
}

func TestAllowedTiersLeavesOutAdminAndAny(t *testing.T) {
	got := testRules.AllowedTiers()
	if want := []string{"Legacy", "Pioneer"}; !slices.Equal(got, want) {
		t.Errorf("AllowedTiers = %v, want %v", got, want)
	}
}

func TestFeaturesAreWhatTheTableSets(t *testing.T) {
	got := testRules.Features()
	want := []Feature{
		{Page: "Search", Options: []string{"SearchDownloadCSV"}},
		{Page: "Newspaper", Options: []string{"NewsLarge"}},
		{Page: "Upload", Options: []string{"UploadOptimizer"}},
	}
	if !slices.EqualFunc(got, want, func(a, b Feature) bool {
		return a.Page == b.Page && slices.Equal(a.Options, b.Options)
	}) {
		t.Errorf("Features = %+v, want %+v", got, want)
	}
}

func TestOverridesKeepOnlyWhatDiffers(t *testing.T) {
	cases := []struct {
		name   string
		posted map[string]map[string]string
		want   map[string]map[string]string
	}{
		{"unchanged", map[string]map[string]string{"Search": {"SearchDownloadCSV": "false"}, "Upload": {"UploadOptimizer": "false"}}, map[string]map[string]string{}},
		{"changed option", map[string]map[string]string{"Search": {"SearchDownloadCSV": "true"}}, map[string]map[string]string{"Search": {"SearchDownloadCSV": "true"}}},
		{"added page", map[string]map[string]string{"Newspaper": {"NewsLarge": "true"}}, map[string]map[string]string{"Newspaper": {"NewsLarge": "true"}}},
		{"added page, nothing set", map[string]map[string]string{"Newspaper": {"NewsLarge": ""}}, map[string]map[string]string{"Newspaper": {}}},
	}
	for _, c := range cases {
		got := testRules.Overrides("Pioneer", c.posted)
		if !maps.EqualFunc(got, c.want, maps.Equal) {
			t.Errorf("%s: Overrides = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestCheckRefuses(t *testing.T) {
	ok := Spec{Tier: "Pioneer", MaxUses: 1, OpenFor: DefaultOpenFor, AccessDays: 7}
	if err := testRules.Check(ok); err != nil {
		t.Fatalf("valid spec refused: %v", err)
	}
	cases := map[string]func(*Spec){
		"unknown tier":    func(s *Spec) { s.Tier = "Nope" },
		"admin tier":      func(s *Spec) { s.Tier = "Root" },
		"open entry":      func(s *Spec) { s.Tier = "Any" },
		"admin override":  func(s *Spec) { s.Overrides = map[string]map[string]string{"Admin": {}} },
		"identity option": func(s *Spec) { s.Overrides = map[string]map[string]string{"Search": {"UserEmail": "x@y"}} },
		"empty option":    func(s *Spec) { s.Overrides = map[string]map[string]string{"Search": {"SearchDownloadCSV": ""}} },
		"no uses":         func(s *Spec) { s.MaxUses = 0 },
		"too many uses":   func(s *Spec) { s.MaxUses = MaxUses + 1 },
		"open too short":  func(s *Spec) { s.OpenFor = time.Minute },
		"open too long":   func(s *Spec) { s.OpenFor = MaxOpenFor + time.Hour },
		"no access":       func(s *Spec) { s.AccessDays = 0 },
		"access too long": func(s *Spec) { s.AccessDays = MaxAccessDays + 1 },
		"long note":       func(s *Spec) { s.Note = strings.Repeat("é", MaxNote+1) },
	}
	for name, change := range cases {
		spec := ok
		change(&spec)
		if testRules.Check(spec) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLifeState(t *testing.T) {
	now := time.Now()
	allowed := []string{"Pioneer"}
	open := Life{Tier: "Pioneer", Uses: 0, MaxUses: 2, AccessDays: 7, OpenUntil: now.Add(time.Hour)}
	cases := map[string]struct {
		life Life
		want string
	}{
		"open":    {open, StateOpen},
		"used up": {Life{Tier: "Pioneer", Uses: 2, MaxUses: 2, OpenUntil: now.Add(time.Hour)}, StateUsedUp},
		"expired": {Life{Tier: "Pioneer", MaxUses: 2, OpenUntil: now}, StateExpired},
		"revoked": {Life{Tier: "Pioneer", MaxUses: 2, OpenUntil: now.Add(time.Hour), RevokedAt: now}, StateRevoked},
		"broken":  {Life{Tier: "Gone", MaxUses: 2, OpenUntil: now.Add(time.Hour)}, StateBroken},
	}
	for name, c := range cases {
		if got := c.life.State(now, allowed); got != c.want {
			t.Errorf("%s: State = %q, want %q", name, got, c.want)
		}
	}

	if got, want := open.LastAccessEnds(), open.OpenUntil.Add(7*24*time.Hour); !got.Equal(want) {
		t.Errorf("LastAccessEnds = %v, want %v", got, want)
	}
	revoked := open
	revoked.RevokedAt = now
	if got, want := revoked.LastAccessEnds(), now.Add(7*24*time.Hour); !got.Equal(want) {
		t.Errorf("revoked LastAccessEnds = %v, want %v", got, want)
	}
}
