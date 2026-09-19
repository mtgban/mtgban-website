// Package sessionstore turns an uploaded list into a scraper an admin can
// publish for the current process, and tracks which of the served scrapers
// were installed that way. It holds no opinion on how a host stores or
// serves its scrapers; a Registry reaches those through the Hooks it is
// built with, the way internal/access and internal/bucketstore reach their
// own host-owned state.
//
// A published store lives in memory only: it goes away with the process, or
// when the host's own admin surface calls Remove. It never shadows a real
// store - one the host's scraper config names, loaded or not, or one
// already serving under that shorthand that was not published this way.
package sessionstore

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"

	"github.com/mtgban/mtgban-website/internal/docparse"
)

// The two kinds a session store can be, spelled the way a scraper config
// spells its sections.
const (
	Retail  = "retail"
	Buylist = "buylist"
)

// A shorthand travels in cookies, query strings and a signature, where ","
// and "|" separate one store from the next, so it is kept to what those
// never split on.
var validShorthand = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Report says what became of the uploaded rows: how many the store holds,
// and how many were left out and why.
type Report struct {
	// Rows the store lists
	Entries int

	// Rows with no price, which a store cannot list
	Unpriced int

	// Sealed rows handed to a singles store, or cards handed to a sealed one
	OtherSide int

	// Rows graded with something the records do not accept
	UnknownGrade int
}

// String spells the report the way a host's admin page shows it.
func (report Report) String() string {
	msg := fmt.Sprintf("%d rows listed", report.Entries)
	if report.Unpriced > 0 {
		msg += fmt.Sprintf(", %d without a price left out", report.Unpriced)
	}
	if report.OtherSide > 0 {
		msg += fmt.Sprintf(", %d of the other kind left out", report.OtherSide)
	}
	if report.UnknownGrade > 0 {
		msg += fmt.Sprintf(", %d with an unknown condition left out", report.UnknownGrade)
	}
	return msg
}

// InfoFromForm reads a store's properties off a publish form: whatever
// ScraperInfo carries beside the timestamps, which are stamped at install,
// and the game, which is the host's own.
func InfoFromForm(r *http.Request) mtgban.ScraperInfo {
	credit, _ := strconv.ParseFloat(strings.TrimSpace(r.FormValue("store_credit")), 64)
	return mtgban.ScraperInfo{
		Name:                strings.TrimSpace(r.FormValue("store_name")),
		Shorthand:           strings.TrimSpace(r.FormValue("store_shorthand")),
		MetadataOnly:        r.FormValue("store_metadata") == "true",
		CreditMultiplier:    credit,
		NoQuantityInventory: r.FormValue("store_noqty") == "true",
		QuantityPriority:    r.FormValue("store_qtyprio") == "true",
		SealedMode:          r.FormValue("store_sealed") == "true",
		Family:              strings.TrimSpace(r.FormValue("store_family")),
	}
}

// FromEntries turns uploaded rows into a scraper of the given kind. Only
// what the store can list counts: a row without a price is not an offer, and
// a sealed store holds products where a singles store holds cards, the way
// the scrapers that come in pairs are split. An unmatched row has nothing to
// key on, and an opened product is not being traded as itself.
func FromEntries(kind string, info mtgban.ScraperInfo, entries []docparse.Entry, backends ...*mtgmatcher.Backend) (mtgban.Scraper, Report, error) {
	var backend *mtgmatcher.Backend
	if len(backends) > 0 {
		backend = backends[0]
	}
	if backend == nil {
		backend = &mtgmatcher.Backend{}
	}
	var report Report
	if kind != Retail && kind != Buylist {
		return nil, report, fmt.Errorf("unknown store kind %q", kind)
	}

	inventory := mtgban.InventoryRecord{}
	buylist := mtgban.BuylistRecord{}
	for _, entry := range entries {
		if entry.CardID == "" || entry.MismatchError != nil || entry.Unpacked {
			continue
		}

		co, err := backend.GetUUID(entry.CardID)
		isSealed := err == nil && co.Sealed
		if isSealed != info.SealedMode {
			report.OtherSide++
			continue
		}
		if entry.OriginalPrice <= 0 {
			report.Unpriced++
			continue
		}

		qty := 1
		if entry.HasQuantity {
			qty = entry.Quantity
		}

		// Relaxed, so a card listed twice at the same grade and price folds
		// into one line, as it would on any storefront. The one thing a
		// relaxed add refuses is a grade the records do not know, which is
		// a row left out like the others rather than a list refused.
		if kind == Retail {
			err = inventory.AddRelaxed(entry.CardID, &mtgban.InventoryEntry{
				Quantity:   qty,
				Conditions: entry.OriginalCondition,
				Price:      entry.OriginalPrice,
			})
		} else {
			err = buylist.AddRelaxed(entry.CardID, &mtgban.BuylistEntry{
				Quantity:   qty,
				Conditions: entry.OriginalCondition,
				BuyPrice:   entry.OriginalPrice,
			})
		}
		if err != nil {
			report.UnknownGrade++
			continue
		}
		report.Entries++
	}

	now := time.Now()
	if kind == Retail {
		info.InventoryTimestamp = &now
		return mtgban.NewSellerFromInventory(inventory, info), report, nil
	}
	info.BuylistTimestamp = &now
	return mtgban.NewVendorFromBuylist(buylist, info), report, nil
}

// Hooks is how a Registry reaches the host's own scraper state. Every field
// is required, the same as internal/access.Hooks. Publish and Remove call
// these while holding the Registry's own lock, so a hook must never call
// back into the Registry (Is/Publish/Remove) itself, directly or through
// another goroutine it waits on - and whatever lock a hook takes of the
// host's own (a snapshot-write mutex, say) must never be held by code that
// then calls into the Registry, or the two lock orders can deadlock.
type Hooks struct {
	// Backend returns the current card datastore used to classify uploaded rows.
	Backend func() *mtgmatcher.Backend
	// Sellers and Vendors return the currently served scrapers, of every
	// kind - session stores included, since Registry itself is what tells
	// the two apart.
	Sellers func() []mtgban.Seller
	Vendors func() []mtgban.Vendor

	// IsConfigured reports whether the host's own scraper config names the
	// shorthand, loaded or not: a session store may never shadow one.
	IsConfigured func(shorthand string) bool

	// Install publishes scraper as the host's served retail or buylist
	// scraper for its shorthand, refusing it the way the host's own
	// scraper-load path would (an older or much smaller dump, say).
	Install func(kind string, scraper mtgban.Scraper) error

	// Drop removes whatever currently serves under shorthand, on the given
	// side, from the host's snapshot.
	Drop func(kind, shorthand string)

	// Notify tells the host's own channel that a session store changed.
	Notify func(kind, message string)
}

// Registry tracks which of a host's served scrapers were published from an
// upload, which is what a host's admin surface offers to remove and what a
// publish may replace. The zero Registry is not usable; build one with New.
type Registry struct {
	hooks Hooks

	mu     sync.RWMutex
	stores map[registryKey]bool
}

// registryKey names a session store by side and shorthand: the same
// shorthand can be published on both sides, as a real store with a retail
// and a buylist section is. The shorthand is canonicalized (see key) so a
// lookup is case-insensitive the same way servingShorthand and a host's own
// IsConfigured are - a registry that only remembered one particular casing
// would refuse Is/Remove for a store that is plainly still live.
type registryKey struct {
	kind      string
	shorthand string
}

func key(kind, shorthand string) registryKey {
	return registryKey{kind, strings.ToUpper(shorthand)}
}

// New builds a Registry that reaches the host through hooks.
func New(hooks Hooks) *Registry {
	return &Registry{hooks: hooks, stores: map[registryKey]bool{}}
}

// Is reports whether the scraper serving shorthand on the given side was
// published from an upload.
func (reg *Registry) Is(kind, shorthand string) bool {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	return reg.stores[key(kind, shorthand)]
}

// Publish builds the store from entries and installs it beside the host's
// other scrapers. A shorthand the host's config claims, or one already
// serving that was not published this way, is refused: a session store may
// replace an earlier one of its own kind, never a real one. The lookups a
// host does are case-insensitive, so this is too.
func (reg *Registry) Publish(kind string, info mtgban.ScraperInfo, entries []docparse.Entry) (Report, error) {
	var report Report
	if info.Name == "" || info.Shorthand == "" {
		return report, errors.New("a store needs a name and a shorthand")
	}
	if !validShorthand.MatchString(info.Shorthand) {
		return report, fmt.Errorf("shorthand %q may only hold letters, digits, - and _", info.Shorthand)
	}

	var backend *mtgmatcher.Backend
	if reg.hooks.Backend != nil {
		backend = reg.hooks.Backend()
	}
	scraper, report, err := FromEntries(kind, info, entries, backend)
	if err != nil {
		return report, err
	}
	if report.Entries == 0 {
		return report, errors.New("no row can be listed: " + report.String())
	}

	reg.mu.Lock()
	defer reg.mu.Unlock()

	if reg.hooks.IsConfigured(info.Shorthand) {
		return report, fmt.Errorf("%s is a configured store", info.Shorthand)
	}
	existing := reg.servingShorthand(kind, info.Shorthand)
	if existing != "" && !reg.stores[key(kind, existing)] {
		return report, fmt.Errorf("%s is a real store", existing)
	}

	// A store replacing itself is dropped first: the checks an install runs
	// - newer than the current, not much smaller - are for a scraper
	// publishing its next dump, not for a different list under the same
	// name.
	if existing != "" {
		reg.hooks.Drop(kind, existing)
		delete(reg.stores, key(kind, existing))
	}

	if err := reg.hooks.Install(kind, scraper); err != nil {
		return report, err
	}
	reg.stores[key(kind, info.Shorthand)] = true

	return report, nil
}

// Remove takes a published store off the host. Only a session store can go
// this way: scrapers the host loaded on its own are not this registry's to
// drop, and a shorthand the config has since claimed is one of those
// whatever this registry remembers.
func (reg *Registry) Remove(kind, shorthand string) error {
	reg.mu.Lock()
	defer reg.mu.Unlock()

	k := key(kind, shorthand)
	if !reg.stores[k] || reg.hooks.IsConfigured(shorthand) {
		return fmt.Errorf("%s is not a session %s store", shorthand, kind)
	}

	// Drop by the spelling the scraper actually serves under, which the
	// caller's may not match - the registry's own bookkeeping is
	// case-insensitive, but a host's served-scraper lookup need not be, and
	// dropping the wrong spelling would clear this entry while leaving the
	// real one still serving.
	served := reg.servingShorthand(kind, shorthand)
	if served == "" {
		served = shorthand
	}
	reg.hooks.Drop(kind, served)
	delete(reg.stores, k)

	reg.hooks.Notify("refresh", fmt.Sprintf("session %s store %s removed", kind, shorthand))
	return nil
}

// servingShorthand returns the shorthand of the scraper answering to this
// one on the given side right now, spelled the way it serves, or "" when
// none does. Called with reg.mu already held.
func (reg *Registry) servingShorthand(kind, shorthand string) string {
	if kind == Retail {
		for _, seller := range reg.hooks.Sellers() {
			if strings.EqualFold(seller.Info().Shorthand, shorthand) {
				return seller.Info().Shorthand
			}
		}
		return ""
	}
	for _, vendor := range reg.hooks.Vendors() {
		if strings.EqualFold(vendor.Info().Shorthand, shorthand) {
			return vendor.Info().Shorthand
		}
	}
	return ""
}
