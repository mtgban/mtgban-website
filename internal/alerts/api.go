package alerts

import (
	"context"
	"encoding/json"
	"log"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/mtgban/mtgban-website/ratelimit"
)

// APIStore is what the API and page need from the store.
type APIStore interface {
	Contact(ctx context.Context, userHash string) (Contact, bool, error)
	EnsureContact(ctx context.Context, userHash, tier string) error
	Create(ctx context.Context, a Alert) (Alert, error)
	ListByUser(ctx context.Context, userHash, game string) ([]Alert, error)
	Get(ctx context.Context, id int64, userHash string) (Alert, bool, error)
	Update(ctx context.Context, a Alert) (bool, error)
	SetStatus(ctx context.Context, id int64, userHash string, status Status) (bool, error)
	Delete(ctx context.Context, id int64, userHash string) (bool, error)
	LastEvents(ctx context.Context, ids []int64) (map[int64]Event, error)
}

// Caller is who a request is from: the user, their tier, and the
// ACL values their signature carries.
type Caller struct {
	UserHash string
	Tier     string
	Values   url.Values
	// Origin is the site the request came to, empty when its host is not
	// one the site trusts.
	Origin string
}

// APIDeps is what the API reads; Prices and Resolve read the live data
// at call time. A nil Store answers 503 to every signed-in request.
type APIDeps struct {
	Store APIStore
	// Identity reads the caller; a status other than 200 is the refusal.
	Identity   func(r *http.Request) (Caller, int, string)
	Allowance  func(v url.Values) int
	Prices     func(cardID string, side Side, v url.Values) []StorePrice
	Resolve    func(cardID string) (Card, bool, bool)
	StoreLabel func(shorthand string) string
	// Game is the site's game, read at call time.
	Game    func() string
	Limiter *ratelimit.Limiter
}

// API serves /api/alerts/ and backs the page.
type API struct{ deps APIDeps }

// NewAPI constructs an API on deps; a nil StoreLabel labels by shorthand.
func NewAPI(deps APIDeps) *API {
	if deps.StoreLabel == nil {
		deps.StoreLabel = func(shorthand string) string { return shorthand }
	}
	return &API{deps: deps}
}

// Store is the API's store, nil when alerts are unavailable.
func (a *API) Store() APIStore {
	if a == nil {
		return nil
	}
	return a.deps.Store
}

// game is the site's game, empty when Game is unset.
func (a *API) game() string {
	if a.deps.Game == nil {
		return ""
	}
	return a.deps.Game()
}

// View is an alert with its current best price and last event.
type View struct {
	Alert
	Current      *float64 `json:"current,omitempty"`
	CurrentStore string   `json:"current_store,omitempty"`
	LastEvent    *Event   `json:"last_event,omitempty"`
}

// Options is what the create or edit form needs for a card and side.
type Options struct {
	Card          Card         `json:"card"`
	Sealed        bool         `json:"sealed"`
	Stores        []StorePrice `json:"stores"`
	Conditions    []string     `json:"conditions"`
	DiscordLinked bool         `json:"discord_linked"`
}

type request struct {
	CardID         string     `json:"card_id"`
	Side           Side       `json:"side"`
	Condition      string     `json:"condition"`
	Stores         []string   `json:"stores"`
	ReferencePrice *float64   `json:"reference_price"`
	Above          *Threshold `json:"above"`
	Below          *Threshold `json:"below"`
	Delivery       Delivery   `json:"delivery"`
	Status         Status     `json:"status"`
}

const maxBody = 16 * 1024

// hasJSONContentType reports whether the request declares an
// application/json body, ignoring any charset or other parameter.
func hasJSONContentType(r *http.Request) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/json"
}

// jsonError writes a status code and an {"error": msg} body.
func jsonError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, struct {
		Error string `json:"error"`
	}{Error: msg})
}

// writeJSON writes a status code and a JSON body.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ServeHTTP answers /api/alerts/: list, create, options, edit and delete.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if a == nil || a.deps.Identity == nil {
		jsonError(w, http.StatusServiceUnavailable, "alerts unavailable")
		return
	}
	c, status, msg := a.deps.Identity(r)
	if status != http.StatusOK {
		jsonError(w, status, msg)
		return
	}
	userHash := c.UserHash
	if a.deps.Limiter != nil && !a.deps.Limiter.Allow(userHash) {
		jsonError(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	if a.deps.Store == nil {
		jsonError(w, http.StatusServiceUnavailable, "alerts unavailable")
		return
	}
	switch r.Method {
	case http.MethodPost, http.MethodPatch, http.MethodDelete:
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			jsonError(w, http.StatusForbidden, "cross-site request refused")
			return
		}
	}
	switch r.Method {
	case http.MethodPost, http.MethodPatch:
		if !hasJSONContentType(r) {
			jsonError(w, http.StatusUnsupportedMediaType, "expected application/json")
			return
		}
	}
	w.Header().Set("Cache-Control", "private, no-store")
	ctx := r.Context()
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/alerts/"), "/")

	switch {
	case rest == "" && r.Method == http.MethodGet:
		views, err := a.ListFor(ctx, c)
		if err != nil {
			a.fail(w, "list", err)
			return
		}
		if views == nil {
			views = []View{}
		}
		writeJSON(w, http.StatusOK, views)
	case rest == "" && r.Method == http.MethodPost:
		a.create(w, r, c)
	case rest == "options" && r.Method == http.MethodGet:
		// keep lists an alert's own stores so the edit form shows them unpriced.
		var keep []string
		k := strings.TrimSpace(r.FormValue("keep"))
		if k != "" {
			keep = strings.Split(k, ",")
		}
		opts, status, msg := a.OptionsFor(ctx, c, r.FormValue("card"), Side(r.FormValue("side")), keep)
		if status != http.StatusOK {
			jsonError(w, status, msg)
			return
		}
		writeJSON(w, http.StatusOK, opts)
	default:
		id, err := strconv.ParseInt(rest, 10, 64)
		if err != nil {
			jsonError(w, http.StatusNotFound, "not found")
			return
		}
		switch r.Method {
		case http.MethodPatch:
			a.patch(w, r, c, id)
		case http.MethodDelete:
			ok, err := a.deps.Store.Delete(ctx, id, userHash)
			if err != nil {
				a.fail(w, "delete", err)
				return
			}
			if !ok {
				jsonError(w, http.StatusNotFound, "not found")
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func (a *API) fail(w http.ResponseWriter, what string, err error) {
	log.Printf("alerts: %s failed: %v", what, err)
	jsonError(w, http.StatusInternalServerError, what+" failed")
}

// ListFor is the user's alerts with their current best price and last event.
// Call only when Store() is non-nil.
func (a *API) ListFor(ctx context.Context, c Caller) ([]View, error) {
	rows, err := a.deps.Store.ListByUser(ctx, c.UserHash, a.game())
	if err != nil {
		return nil, err
	}
	ids := make([]int64, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID)
	}
	last, err := a.deps.Store.LastEvents(ctx, ids)
	if err != nil {
		return nil, err
	}
	views := make([]View, 0, len(rows))
	for _, row := range rows {
		v := View{Alert: row}
		prices := a.deps.Prices(row.CardID, row.Side, c.Values)
		best, store, ok := bestStorePrice(prices, row.Side, row.Condition, row.Stores)
		if ok {
			v.Current, v.CurrentStore = &best, store
		}
		e, ok := last[row.ID]
		if ok {
			v.LastEvent = &e
		}
		views = append(views, v)
	}
	return views, nil
}

// OptionsFor is the create or edit form's needs for a card and side; call
// only when Store() is non-nil. keep is the alert's stores, so an edit still
// lists one the user scoped to after it stops offering the card; nil on create.
func (a *API) OptionsFor(ctx context.Context, c Caller, cardID string, side Side, keep []string) (Options, int, string) {
	userHash := c.UserHash
	if a.deps.Allowance(c.Values) <= 0 {
		return Options{}, http.StatusForbidden, "alerts are not part of your tier"
	}
	if side != SideRetail && side != SideBuylist {
		return Options{}, http.StatusUnprocessableEntity, "side must be retail or buylist"
	}
	card, sealed, found := a.deps.Resolve(cardID)
	if !found {
		return Options{}, http.StatusNotFound, "unknown card"
	}
	contact, _, err := a.deps.Store.Contact(ctx, userHash)
	if err != nil {
		log.Printf("alerts: contact lookup failed: %v", err)
		return Options{}, http.StatusInternalServerError, "contact lookup failed"
	}
	opts := Options{
		Card: card, Sealed: sealed, Conditions: Conditions,
		Stores: a.deps.Prices(cardID, side, c.Values), DiscordLinked: contact.DiscordUserID != "",
	}
	if sealed {
		opts.Conditions = []string{"NM"}
	}
	opts.Stores = withKeptStores(opts.Stores, keep, a.deps.StoreLabel)
	if opts.Stores == nil {
		opts.Stores = []StorePrice{}
	}
	return opts, http.StatusOK, ""
}

func decodeRequest(w http.ResponseWriter, r *http.Request) (request, bool) {
	var req request
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&req)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid json")
		return req, false
	}
	return req, true
}

func (a *API) create(w http.ResponseWriter, r *http.Request, c Caller) {
	ctx := r.Context()
	userHash, tier := c.UserHash, c.Tier
	if a.deps.Allowance(c.Values) <= 0 {
		jsonError(w, http.StatusForbidden, "alerts are not part of your tier")
		return
	}
	req, ok := decodeRequest(w, r)
	if !ok {
		return
	}
	if req.Delivery == DeliveryEmail {
		jsonError(w, http.StatusUnprocessableEntity, "email delivery is not available yet")
		return
	}
	card, sealed, found := a.deps.Resolve(req.CardID)
	if !found {
		jsonError(w, http.StatusUnprocessableEntity, "unknown card")
		return
	}
	err := a.deps.Store.EnsureContact(ctx, userHash, tier)
	if err != nil {
		a.fail(w, "contact", err)
		return
	}
	contact, _, err := a.deps.Store.Contact(ctx, userHash)
	if err != nil {
		a.fail(w, "contact", err)
		return
	}
	if req.Delivery == DeliveryDiscord && contact.DiscordUserID == "" {
		jsonError(w, http.StatusUnprocessableEntity, "link Discord on Patreon and sign in again")
		return
	}
	existing, err := a.deps.Store.ListByUser(ctx, userHash, a.game())
	if err != nil {
		a.fail(w, "list", err)
		return
	}
	if len(existing) >= a.deps.Allowance(c.Values) {
		jsonError(w, http.StatusConflict, "alert allowance reached; delete one first")
		return
	}
	visible := a.deps.Prices(req.CardID, req.Side, c.Values)
	stores, err := scopeStores(req.Stores, visible)
	if err != nil {
		jsonError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	condition := req.Condition
	if sealed {
		condition = "NM"
	}
	best, _, hasPrice := bestStorePrice(visible, req.Side, condition, stores)
	var above, below Threshold
	if req.Above != nil {
		above = *req.Above
	}
	if req.Below != nil {
		below = *req.Below
	}
	alert := Alert{
		UserHash: userHash, Game: a.game(), CardID: req.CardID, Side: req.Side, Condition: condition,
		Stores: stores, Above: above, Below: below, Delivery: req.Delivery, Card: card, Origin: c.Origin,
	}
	if req.ReferencePrice != nil {
		alert.ReferencePrice = *req.ReferencePrice
	} else if hasPrice {
		alert.ReferencePrice = best
	}
	if hasPrice {
		alert.CreatedPrice = &best
	}
	// Validate rounds the thresholds and tidies the stores first, so a
	// duplicate compares as it would be saved.
	err = alert.Validate()
	if err != nil {
		jsonError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	for _, e := range existing {
		if sameAlert(e, alert) {
			writeJSON(w, http.StatusConflict, struct {
				Error   string `json:"error"`
				AlertID int64  `json:"alert_id"`
			}{"you already have this alert", e.ID})
			return
		}
	}
	alert.AboveArmed, alert.BelowArmed = startArmed(alert, best, hasPrice)
	created, err := a.deps.Store.Create(ctx, alert)
	if err != nil {
		a.fail(w, "create", err)
		return
	}
	v := View{Alert: created}
	if hasPrice {
		v.Current = &best
	}
	writeJSON(w, http.StatusCreated, v)
}

// sameAlert reports whether two alerts watch the same thing: card, side,
// condition, stores and thresholds.
func sameAlert(a, b Alert) bool {
	if a.CardID != b.CardID || a.Side != b.Side || a.Condition != b.Condition || a.Above != b.Above || a.Below != b.Below {
		return false
	}
	as, bs := slices.Clone(a.Stores), slices.Clone(b.Stores)
	slices.Sort(as)
	slices.Sort(bs)
	return slices.Equal(as, bs)
}

func (a *API) patch(w http.ResponseWriter, r *http.Request, c Caller, id int64) {
	ctx := r.Context()
	userHash := c.UserHash
	req, ok := decodeRequest(w, r)
	if !ok {
		return
	}
	cur, found, err := a.deps.Store.Get(ctx, id, userHash)
	if err != nil {
		a.fail(w, "get", err)
		return
	}
	if !found {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	// A lapsed tier may still pause or delete; resuming or editing needs the allowance.
	if (req.Status == StatusActive || req.Status == "") && a.deps.Allowance(c.Values) <= 0 {
		jsonError(w, http.StatusForbidden, "alerts are not part of your tier")
		return
	}
	// A status-only patch is pause or resume; anything else is an edit,
	// and the two must not be mixed in one request.
	if req.Status != "" {
		if req.CardID != "" || req.Side != "" || req.Condition != "" || req.Stores != nil ||
			req.ReferencePrice != nil || req.Above != nil || req.Below != nil || req.Delivery != "" {
			jsonError(w, http.StatusUnprocessableEntity, "status must be sent alone")
			return
		}
		if req.Status != StatusActive && req.Status != StatusPaused {
			jsonError(w, http.StatusUnprocessableEntity, "status must be active or paused")
			return
		}
		ok, err := a.deps.Store.SetStatus(ctx, id, userHash, req.Status)
		if err != nil {
			a.fail(w, "status", err)
			return
		}
		if !ok {
			jsonError(w, http.StatusNotFound, "not found")
			return
		}
		cur.Status = req.Status
		writeJSON(w, http.StatusOK, View{Alert: cur})
		return
	}
	if req.Delivery == DeliveryEmail {
		jsonError(w, http.StatusUnprocessableEntity, "email delivery is not available yet")
		return
	}
	next := cur
	if req.Condition != "" {
		next.Condition = req.Condition
	}
	prices := a.deps.Prices(cur.CardID, cur.Side, c.Values)
	if req.Stores != nil {
		visible := withKeptStores(prices, cur.Stores, a.deps.StoreLabel)
		stores, err := scopeStores(req.Stores, visible)
		if err != nil {
			jsonError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		next.Stores = stores
	}
	if req.ReferencePrice != nil {
		next.ReferencePrice = *req.ReferencePrice
	}
	if req.Above != nil {
		next.Above = *req.Above
	}
	if req.Below != nil {
		next.Below = *req.Below
	}
	if req.Delivery != "" {
		next.Delivery = req.Delivery
	}
	if c.Origin != "" {
		next.Origin = c.Origin
	}
	_, sealed, resolved := a.deps.Resolve(cur.CardID)
	if resolved && sealed {
		next.Condition = "NM"
	}
	err = next.Validate()
	if err != nil {
		jsonError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	best, _, hasPrice := bestStorePrice(prices, next.Side, next.Condition, next.Stores)
	next.AboveArmed, next.BelowArmed = startArmed(next, best, hasPrice)
	ok, err = a.deps.Store.Update(ctx, next)
	if err != nil {
		a.fail(w, "update", err)
		return
	}
	if !ok {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, View{Alert: next})
}
