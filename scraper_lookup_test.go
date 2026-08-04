package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

// installTestScrapers swaps in n synthetic sellers and vendors (plus a few
// special cases) and restores the previous snapshots on cleanup. Entry i is
// named "Bench Store %03d" with shorthand "BS%03d"; sellers and vendors share
// names and shorthands, mirroring production stores that run both sides.
func installTestScrapers(tb testing.TB, n int) {
	prevSellers := sellersPtr.Load()
	prevVendors := vendorsPtr.Load()
	tb.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})

	var sellers []mtgban.Seller
	var vendors []mtgban.Vendor
	for i := range n {
		info := mtgban.ScraperInfo{
			Name:      fmt.Sprintf("Bench Store %03d", i),
			Shorthand: fmt.Sprintf("BS%03d", i),
		}
		sellers = append(sellers, mtgban.NewSellerFromInventory(nil, info))
		vendors = append(vendors, mtgban.NewVendorFromBuylist(nil, info))
	}

	// A sealed seller sharing its name with a singles seller, to pin the
	// SealedMode discrimination of the ByName lookups.
	sellers = append(sellers, mtgban.NewSellerFromInventory(nil, mtgban.ScraperInfo{
		Name: "Bench Store 000", Shorthand: "BS000Sealed", SealedMode: true,
	}))
	// A vendor whose name collides with a seller of a different shorthand,
	// to pin the sellers-first precedence of store-code resolution.
	vendors = append(vendors, mtgban.NewVendorFromBuylist(nil, mtgban.ScraperInfo{
		Name: "Bench Store 001", Shorthand: "VENDONLY",
	}))

	sellersPtr.Store(&sellers)
	vendorsPtr.Store(&vendors)
}

func TestScraperNameLookup(t *testing.T) {
	installTestScrapers(t, 10)

	if got := scraperName("BS003"); got != "Bench Store 003" {
		t.Errorf("BS003 = %q, want Bench Store 003", got)
	}
	// scraperName matches the shorthand case-sensitively; a wrong-case query
	// falls through to the shorthand override map (empty here).
	if got := scraperName("bs003"); got != "" {
		t.Errorf("bs003 = %q, want empty (case-sensitive miss)", got)
	}
	if got := scraperName("NOPE"); got != "" {
		t.Errorf("NOPE = %q, want empty", got)
	}

	prev := Config.ScraperConfig.NameOverride
	Config.ScraperConfig.NameOverride = map[string]string{
		"Bench Store 004": "Renamed Store",
		"GHOST":           "Ghost Store",
	}
	t.Cleanup(func() { Config.ScraperConfig.NameOverride = prev })

	if got := scraperName("BS004"); got != "Renamed Store" {
		t.Errorf("BS004 with override = %q, want Renamed Store", got)
	}
	if got := scraperName("GHOST"); got != "Ghost Store" {
		t.Errorf("GHOST = %q, want Ghost Store (shorthand override fallback)", got)
	}
}

func TestFindScraperLookups(t *testing.T) {
	installTestScrapers(t, 10)

	// Shorthand lookups are case-insensitive.
	if _, err := findSellerInventory("bs005"); err != nil {
		t.Errorf("findSellerInventory(bs005): %v", err)
	}
	if _, err := findVendorBuylist("BS005"); err != nil {
		t.Errorf("findVendorBuylist(BS005): %v", err)
	}
	if _, err := findSellerInventory("NOPE"); err == nil {
		t.Error("findSellerInventory(NOPE): want error")
	}

	// Name lookups are case-insensitive and discriminate on SealedMode.
	if _, err := findSellerInventoryByName("bench store 000", false); err != nil {
		t.Errorf("ByName singles: %v", err)
	}
	if _, err := findSellerInventoryByName("bench store 000", true); err != nil {
		t.Errorf("ByName sealed: %v", err)
	}
	if _, err := findVendorBuylistByName("Bench Store 001", true); err == nil {
		t.Error("ByName sealed vendor: want error (only singles exists)")
	}
}

func TestFixupStoreCodeLookup(t *testing.T) {
	installTestScrapers(t, 10)

	// By shorthand, by name, unknown passthrough, quote stripping. Note only
	// the whole string is space-trimmed, not each comma-separated token.
	got := fixupStoreCodeNG(` BS002,"bench store 003",mystery `)
	want := []string{"bs002", "bs003", "mystery"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("fixup = %v, want %v", got, want)
	}

	// A name shared by a seller and a vendor-only entry resolves to the
	// seller's shorthand: sellers are consulted first.
	got = fixupStoreCodeNG("bench store 001")
	if len(got) != 1 || got[0] != "bs001" {
		t.Errorf("seller precedence = %v, want [bs001]", got)
	}

	// Overridden display names resolve too.
	prev := Config.ScraperConfig.NameOverride
	Config.ScraperConfig.NameOverride = map[string]string{"Bench Store 006": "Fancy Name"}
	t.Cleanup(func() { Config.ScraperConfig.NameOverride = prev })
	got = fixupStoreCodeNG("fancy name")
	if len(got) != 1 || got[0] != "bs006" {
		t.Errorf("override name = %v, want [bs006]", got)
	}
}

func BenchmarkFindSellerInventory(b *testing.B) {
	installTestScrapers(b, 100)
	b.ReportAllocs()
	for b.Loop() {
		findSellerInventory("BS050")
	}
}

func BenchmarkScraperName(b *testing.B) {
	installTestScrapers(b, 100)
	b.ReportAllocs()
	for b.Loop() {
		scraperName("BS050")
	}
}

func BenchmarkSortKeysByScraperName(b *testing.B) {
	installTestScrapers(b, 100)
	keys := make([]string, 100)
	for i := range keys {
		keys[i] = fmt.Sprintf("BS%03d", (i*37)%100)
	}
	b.ReportAllocs()
	for b.Loop() {
		sortKeysByScraperName(keys)
	}
}

func BenchmarkFixupStoreCode(b *testing.B) {
	installTestScrapers(b, 100)
	code := strings.ToLower("Bench Store 050,BS099,unknown")
	b.ReportAllocs()
	for b.Loop() {
		fixupStoreCodeNG(code)
	}
}
