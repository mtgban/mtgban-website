package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mtgban/go-mtgban/cardtrader"
	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// The two tables the CardTrader inventory page offers, header first.
type ctExport struct {
	Raw [][]string `json:"raw"`
	Ban [][]string `json:"ban"`
}

// ctSummary counts a load for the page.
type ctSummary struct {
	Listings   int
	ThisGame   int
	Matched    int
	Unmatched  int
	OtherGames int
	NoCatalog  int
	// LeftOut are this game's altered and graded copies, raw CSV only.
	LeftOut int
	// Marked are the copies graded Poor for being signed or marked.
	Marked  int
	NoRates bool
}

// ctUnmatched is one listing of this game the matcher could not place.
type ctUnmatched struct {
	Name      string
	Expansion string
	Number    string
	Quantity  int
	Reason    string
}

// ctRawHeader names the columns as CardTrader's CSV import takes them.
var ctRawHeader = []string{
	"product_id", "blueprint_id", "game_id", "name", "expansion_code", "expansion_name",
	"quantity", "bundle", "price_cents", "price_currency", "condition", "language", "foil",
	"signed", "altered", "first_edition", "tcgplayer_id", "scryfall_id",
	"description", "user_data_field", "tag",
}

// ctBanHeader names the columns docparse reads.
var ctBanHeader = []string{"id", "name", "edition", "number", "finish", "condition", "quantity", "price"}

// ctLanguages are the codes a Magic listing carries, as the matcher names them.
var ctLanguages = map[string]string{
	"en": "", "fr": "French", "de": "German", "es": "Spanish", "it": "Italian",
	"jp": "Japanese", "kr": "Korean", "pt": "Portuguese", "ru": "Russian",
	"zh-cn": "Chinese", "zh-tw": "Chinese",
}

// ctListingProps reads the language and foil flag under the game's own
// property names, and whether the game names a foil at all.
func ctListingProps(gameID int, p cardtrader.ProductProperties) (language string, foil, hasFoil bool) {
	switch gameID {
	case cardtrader.GameMagic:
		return p.MTGLanguage, p.MTGFoil, true
	case cardtrader.GameLorcana:
		return p.LorcanaLanguage, p.LorcanaFoil, true
	case cardtrader.GameRiftbound:
		return p.RiftboundLanguage, p.RiftboundFoil, true
	case cardtrader.GameOnePiece:
		return p.OnePieceLanguage, p.OnePieceFoil, true
	case cardtrader.GameFleshAndBlood:
		return p.FabLanguage, p.FabFoilNew != "" && p.FabFoilNew != "Regular" && p.FabFoilNew != "false", true
	case cardtrader.GamePokemon:
		return p.PokemonLanguage, p.PokemonReverse, true
	case cardtrader.GameYuGiOh:
		return p.YuGiOhLanguage, false, false
	case cardtrader.GameGundam:
		return p.GundamLanguage, false, false
	case cardtrader.GamePalworld:
		return p.PalworldLanguage, false, false
	}
	return "", false, false
}

// ctFinish is the BAN finish column: foil or nonfoil, empty for a game
// whose listings carry no foil property.
func ctFinish(gameID int, p cardtrader.ProductProperties) string {
	_, foil, hasFoil := ctListingProps(gameID, p)
	switch {
	case !hasFoil:
		return ""
	case foil:
		return "foil"
	}
	return "nonfoil"
}

// ctFoilColumn is the raw CSV's foil flag, empty where the game has none.
func ctFoilColumn(gameID int, p cardtrader.ProductProperties) string {
	_, foil, hasFoil := ctListingProps(gameID, p)
	if !hasFoil {
		return ""
	}
	return strconv.FormatBool(foil)
}

// ctBanCondition writes CardTrader's grade as the code docparse reads.
// Played, CardTrader's grade between MP and HP, folds into HP as the
// scraper folds it.
func ctBanCondition(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.EqualFold(s, "Played") {
		return string(mtgban.HP)
	}
	cond, err := mtgban.ParseCondition(s)
	if err != nil {
		return ""
	}
	return string(cond)
}

// ctMarked reads a copy as the scraper does: signed, or described as
// signed, inked, stamped, poor or water damaged, it grades Poor.
func ctMarked(p cardtrader.Product) bool {
	if p.Properties.Signed {
		return true
	}
	for _, word := range []string{"signed", "inked", "stamp", "poor", "water"} {
		if mtgmatcher.Contains(p.Description, word) {
			return true
		}
	}
	return false
}

// ctPriceUSD converts a listing's price to dollars with two decimals, or
// reports that the currency has no rate.
func ctPriceUSD(cents int, currency string, rates map[string]float64) (string, bool) {
	price := float64(cents) / 100
	if !strings.EqualFold(currency, "USD") {
		rate, found := rates[strings.ToLower(currency)]
		if !found {
			return "", false
		}
		price *= rate
	}
	return strconv.FormatFloat(price, 'f', 2, 64), true
}

// ctMatch resolves one listing of this game to a uuid, or says why not.
func ctMatch(b *mtgmatcher.Backend, gameID int, bp *cardtrader.Blueprint, p cardtrader.Product) (uuid, reason string) {
	language, foil, _ := ctListingProps(gameID, p.Properties)

	if gameID == cardtrader.GameMagic {
		card, err := cardtrader.Preprocess(b, bp)
		if err != nil {
			return "", "not a card we price"
		}
		card.Foil = foil
		if language != "" {
			lang, ok := ctLanguages[strings.ToLower(language)]
			if !ok {
				return "", "unsupported language"
			}
			card.Language = lang
		}
		uuid, err := b.Match(card)
		if err != nil {
			return "", "no match"
		}
		return uuid, ""
	}

	var ids []string
	if tcgID := bp.TCGplayerProductID(); tcgID != 0 {
		ids = append(ids, fmt.Sprint(tcgID))
	}
	for _, mkmID := range bp.CardMarketIDs {
		if uuid := b.ConvertID(mtgmatcher.IDSpaceCardmarket, fmt.Sprint(mkmID)); uuid != "" {
			ids = append(ids, uuid)
		}
	}
	if len(ids) == 0 {
		return "", "no id to match by"
	}
	for _, id := range ids {
		if uuid, err := b.MatchID(id, foil); err == nil && uuid != "" {
			return uuid, ""
		}
	}
	return "", "no match"
}

// buildCTExport turns a seller's inventory into the two tables and the
// page's counts. Every listing goes to the raw table; this game's go to
// the BAN table too, matched where the catalog and the matcher allow.
func buildCTExport(b *mtgmatcher.Backend, game mtgmatcher.Game, inv *cardtrader.Inventory, rates map[string]float64) (ctExport, ctSummary, []ctUnmatched) {
	gameID, known := cardtrader.GameID(game)
	export := ctExport{
		Raw: [][]string{ctRawHeader},
		Ban: [][]string{ctBanHeader},
	}
	summary := ctSummary{Listings: len(inv.Products), NoRates: rates == nil}
	var unmatched []ctUnmatched

	for _, p := range inv.Products {
		bp := inv.Blueprints[p.BlueprintID]
		pGame := p.GameID
		if pGame == 0 && bp != nil {
			pGame = bp.GameID
		}
		language, _, _ := ctListingProps(pGame, p.Properties)

		raw := make([]string, 0, len(ctRawHeader))
		raw = append(raw, strconv.Itoa(p.ID), strconv.Itoa(p.BlueprintID), strconv.Itoa(pGame))
		name, code, expName, tcgID, scryfallID := p.Name, "", "", "", ""
		if bp != nil {
			if name == "" {
				name = bp.Name
			}
			code, expName, scryfallID = bp.Expansion.Code, bp.Expansion.Name, bp.ScryfallID
			if bp.TCGplayerID != 0 {
				tcgID = strconv.Itoa(bp.TCGplayerID)
			}
		}
		raw = append(raw, name, code, expName,
			strconv.Itoa(p.Quantity), strconv.FormatBool(p.Bundle), strconv.Itoa(p.PriceCents), p.PriceCurrency,
			p.Properties.Condition, language, ctFoilColumn(pGame, p.Properties),
			strconv.FormatBool(p.Properties.Signed), strconv.FormatBool(p.Properties.Altered),
			strconv.FormatBool(p.Properties.FirstEdition), tcgID, scryfallID,
			p.Description, p.UserDataField, p.Tag)
		export.Raw = append(export.Raw, raw)

		if !known || pGame != gameID {
			summary.OtherGames++
			continue
		}
		summary.ThisGame++

		// An altered or graded copy is priced as that copy, not as the
		// card: the scraper skips both, and so does the BAN table.
		if p.Properties.Altered || p.Graded {
			summary.LeftOut++
			continue
		}
		condition := p.Properties.Condition
		if ctMarked(p) {
			condition = "Poor"
			summary.Marked++
		}

		banName, edition, number := p.Name, "", p.Properties.Number
		if bp != nil {
			banName, edition = bp.Name, bp.Expansion.Name
			if bp.Properties.Number != "" {
				number = bp.Properties.Number
			}
		}

		// A bundle is a playset: the scraper counts it as four copies.
		copies := p.Quantity
		if p.Bundle {
			copies *= 4
		}

		var uuid, reason string
		switch {
		case bp == nil && len(inv.Unavailable) > 0:
			reason = "catalog unavailable"
			summary.NoCatalog++
		case bp == nil:
			reason = "unknown blueprint"
		default:
			uuid, reason = ctMatch(b, gameID, bp, p)
		}
		if uuid == "" {
			summary.Unmatched++
			unmatched = append(unmatched, ctUnmatched{Name: banName, Expansion: edition, Number: number, Quantity: copies, Reason: reason})
		} else {
			summary.Matched++
		}

		price, _ := ctPriceUSD(p.PriceCents, p.PriceCurrency, rates)
		export.Ban = append(export.Ban, []string{
			uuid, banName, edition, number, ctFinish(gameID, p.Properties),
			ctBanCondition(condition), strconv.Itoa(copies), price,
		})
	}

	return export, summary, unmatched
}

// CardTraderVars is what the CardTrader inventory page fills and reads.
type CardTraderVars struct {
	CTLoaded    bool
	CTSummary   ctSummary
	CTUnmatched []ctUnmatched
	// CTUnmatchedTotal counts every unmatched listing, past the rows shown.
	CTUnmatchedTotal int
	CTExport         *ctExport
	CTError          string
}

// ctUnmatchedShown caps the unmatched rows the page draws; the BAN CSV has all.
const ctUnmatchedShown = 500

// ctExportInventory fetches a seller's stock with their token. Tests swap it.
var ctExportInventory = func(ctx context.Context, token string) (*cardtrader.Inventory, error) {
	return cardtrader.NewCTAuthClient(token).ExportInventory(ctx)
}

// ctExchangeRates prices the BAN table in dollars. Tests swap it.
var ctExchangeRates = mtgban.GetExchangeRates

// ctExportTimeout bounds one load: a seller in two hundred expansions is
// about a minute of catalog fetches.
const ctExportTimeout = 3 * time.Minute

// What the page says when an export cannot start.
const (
	ctErrTooMany     = "Too many exports are running. Try again in a minute."
	ctErrAccountBusy = "An export is already running for your account. Wait for it to finish."
)

// ctExportGate caps the exports in flight: a few per process, and one per
// account, so one seller's tabs cannot hold every slot.
type ctExportGate struct {
	slots chan struct{}
	mu    sync.Mutex
	busy  map[string]bool
}

func newCTExportGate(n int) *ctExportGate {
	return &ctExportGate{slots: make(chan struct{}, n), busy: map[string]bool{}}
}

// acquire takes the account's slot, then a process slot, or says which is
// full. The release it returns gives both back. An empty email, a reader
// with no signature, is capped by the process alone.
func (g *ctExportGate) acquire(email string) (release func(), refused string) {
	if email != "" {
		g.mu.Lock()
		taken := g.busy[email]
		g.busy[email] = true
		g.mu.Unlock()
		if taken {
			return nil, ctErrAccountBusy
		}
	}
	select {
	case g.slots <- struct{}{}:
	default:
		g.free(email)
		return nil, ctErrTooMany
	}
	return func() {
		<-g.slots
		g.free(email)
	}, ""
}

func (g *ctExportGate) free(email string) {
	if email == "" {
		return
	}
	g.mu.Lock()
	delete(g.busy, email)
	g.mu.Unlock()
}

// ctExports caps the exports one process runs at once. Tests swap it.
var ctExports = newCTExportGate(4)

// CardTraderInventory renders the page a seller loads their stock on. A GET
// is the form; a POST with a token runs the export and renders the result
// above the form. The token lives in the request body and nowhere else.
func (s *site) CardTraderInventory(w http.ResponseWriter, r *http.Request) {
	sig := verifiedSignature(r)
	pageVars := genPageNav(s, r, "CardTrader", sig)
	pageVars.Title = "CardTrader inventory"

	// Upload keeps the desktop layout on a phone; this page does not.
	pageVars.IsMobile = isMobileRequest(r)
	if pageVars.IsMobile {
		pageVars.Nav = filterNavForMobile(pageVars.Nav)
	}

	// The middleware gates sections by their own path, not their sub-pages,
	// so this page checks its section's grant and visibility itself.
	canUpload, _ := strconv.ParseBool(GetParamFromSig(sig, "Upload"))
	if DevMode && !SigCheck {
		canUpload = true
	}
	if !canUpload {
		pageVars.Title = "This feature is BANned"
		pageVars.ErrorMessage = ErrMsgPlus
		render(w, "cardtrader_inventory.html", pageVars)
		return
	}
	if _, found := cardtrader.GameID(Config().Game); !found {
		pageVars = genPageNav(s, r, "Error", sig)
		pageVars.Title = "Unauthorized"
		render(w, "home.html", pageVars)
		return
	}

	if r.Method == http.MethodPost {
		s.loadCardTraderInventory(r, sig, &pageVars)
	}

	render(w, "cardtrader_inventory.html", pageVars)
}

// ctTokenRefused tells a token CardTrader turned away from the catalog
// being unreachable: a 401 or 403 answered to one of the export's calls.
func ctTokenRefused(err error) bool {
	var se *cardtrader.StatusError
	return errors.As(err, &se) && (se.Code == http.StatusUnauthorized || se.Code == http.StatusForbidden)
}

func (s *site) loadCardTraderInventory(r *http.Request, sig string, pageVars *PageVars) {
	token := strings.TrimSpace(r.PostFormValue("token"))
	if len(token) > 7 && strings.EqualFold(token[:7], "bearer ") {
		token = strings.TrimSpace(token[7:])
	}
	if token == "" {
		pageVars.CTError = "Paste your CardTrader API token first."
		return
	}

	// Released on every return, a cancelled or timed-out export included.
	release, refused := ctExports.acquire(GetParamFromSig(sig, "UserEmail"))
	if refused != "" {
		pageVars.CTError = refused
		return
	}
	defer release()

	ctx, cancel := context.WithTimeout(r.Context(), ctExportTimeout)
	defer cancel()

	inv, err := ctExportInventory(ctx, token)
	if err != nil {
		pageVars.CTError = "CardTrader did not answer. Try again in a minute."
		if ctTokenRefused(err) {
			pageVars.CTError = "CardTrader did not accept that token."
		}
		return
	}
	if len(inv.Products) == 0 {
		pageVars.CTError = "CardTrader returned no listings for that token."
		return
	}

	// Its own deadline: a long export may have spent the one above.
	ratesCtx, cancelRates := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancelRates()
	rates, err := ctExchangeRates(ratesCtx)
	if err != nil {
		rates = nil
	}

	export, summary, unmatched := buildCTExport(s.datastore().backend, Config().Game, inv, rates)
	pageVars.CTLoaded = true
	pageVars.CTSummary = summary
	pageVars.CTUnmatchedTotal = len(unmatched)
	pageVars.CTUnmatched = unmatched[:min(len(unmatched), ctUnmatchedShown)]
	pageVars.CTExport = &export

	if logger := LogPages["Upload"]; logger != nil {
		logger.Printf("cardtrader inventory: %d listings, %d matched, %d unmatched by %q",
			summary.Listings, summary.Matched, summary.Unmatched, GetParamFromSig(sig, "UserEmail"))
	}
}
