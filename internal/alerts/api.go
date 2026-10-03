package alerts

import (
	"context"
	"encoding/json"
	"log"
	"mime"
	"net/http"
	"net/mail"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"

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
	Channels(ctx context.Context, userHash string) ([]Channel, error)
	ChannelFor(ctx context.Context, userHash string, kind ChannelKind) (Channel, bool, error)
	UpsertChannel(ctx context.Context, c Channel) error
	DeleteChannel(ctx context.Context, userHash string, kind ChannelKind, source ChannelSource) error
	EnableChannel(ctx context.Context, userHash string, kind ChannelKind, source ChannelSource) error
	ChannelByAddress(ctx context.Context, kind ChannelKind, address string) ([]Channel, error)
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
	// Channels is the delivery channels the ACL values allow.
	Channels func(v url.Values) []ChannelKind
	// Mint signs a confirm token; SendConfirm mails its link.
	Mint        func(t Token) string
	SendConfirm func(ctx context.Context, to, link string) error
	ConfirmTTL  time.Duration
	// ConfirmLimiter caps confirmation mails per user.
	ConfirmLimiter *ratelimit.Limiter
}

const (
	defaultConfirmTTL = 24 * time.Hour
	confirmBurst      = 3
	maxEmailLen       = 254
)

// confirmRate refills one confirmation mail every 20 minutes.
var confirmRate = rate.Every(20 * time.Minute)

// API serves /api/alerts/ and backs the page.
type API struct{ deps APIDeps }

// NewAPI constructs an API on deps; a nil StoreLabel labels by shorthand,
// a nil Channels allows Discord alone. The default ConfirmLimiter, like
// the Service's default Limiter, is built only when a store is present:
// an unavailable API answers 503 before either is reached.
func NewAPI(deps APIDeps) *API {
	if deps.StoreLabel == nil {
		deps.StoreLabel = func(shorthand string) string { return shorthand }
	}
	if deps.Channels == nil {
		deps.Channels = func(url.Values) []ChannelKind { return []ChannelKind{ChannelDiscord} }
	}
	if deps.ConfirmTTL == 0 {
		deps.ConfirmTTL = defaultConfirmTTL
	}
	if deps.ConfirmLimiter == nil && deps.Store != nil {
		deps.ConfirmLimiter = ratelimit.NewLimiter(confirmRate, confirmBurst)
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
	CardID         string          `json:"card_id"`
	Side           Side            `json:"side"`
	Condition      string          `json:"condition"`
	Stores         []string        `json:"stores"`
	ReferencePrice *float64        `json:"reference_price"`
	Above          *Threshold      `json:"above"`
	Below          *Threshold      `json:"below"`
	Delivery       DeliveryChannel `json:"delivery"`
	Status         Status          `json:"status"`
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

// ServeHTTP answers /api/alerts/: list, create, options, edit, delete and channels.
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
	case rest == "channels" && r.Method == http.MethodGet:
		views, err := a.channelViews(ctx, userHash)
		if err != nil {
			a.fail(w, "channels", err)
			return
		}
		writeJSON(w, http.StatusOK, views)
	case rest == "channels/email" && r.Method == http.MethodPost:
		a.setEmail(w, r, c)
	case rest == "channels/email" && r.Method == http.MethodDelete:
		a.deleteEmail(w, r, c)
	case rest == "channels/email/resend" && r.Method == http.MethodPost:
		a.resendEmail(w, r, c)
	case rest == "channels/enable" && r.Method == http.MethodPost:
		a.enableChannel(w, r, c)
	case rest == "channels" || rest == "channels/email" || rest == "channels/email/resend" || rest == "channels/enable":
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
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
	return req, decodeBody(w, r, &req)
}

// decodeBody reads a JSON body into v, answering 400 when it cannot.
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(v)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid json")
		return false
	}
	return true
}

// deliveryRefusal is why alerts cannot go out on d, status 200 when they can.
func (a *API) deliveryRefusal(ctx context.Context, c Caller, d DeliveryChannel) (int, string) {
	kind := ChannelKind(d)
	if kind != ChannelDiscord && kind != ChannelEmail {
		// Validate names an unknown delivery.
		return http.StatusOK, ""
	}
	if !slices.Contains(a.deps.Channels(c.Values), kind) {
		return http.StatusUnprocessableEntity, "channel not available on your tier"
	}
	_, ok, err := a.deps.Store.ChannelFor(ctx, c.UserHash, kind)
	if err != nil {
		log.Printf("alerts: channel lookup failed: %v", err)
		return http.StatusInternalServerError, "channel lookup failed"
	}
	if ok {
		return http.StatusOK, ""
	}
	if kind == ChannelEmail {
		return http.StatusUnprocessableEntity, "confirm an email address first"
	}
	return http.StatusUnprocessableEntity, "link Discord on Patreon and sign in again"
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
	if req.Delivery == "" {
		req.Delivery = DeliveryDiscord
	}
	card, sealed, found := a.deps.Resolve(req.CardID)
	if !found {
		jsonError(w, http.StatusUnprocessableEntity, "unknown card")
		return
	}
	status, msg := a.deliveryRefusal(ctx, c, req.Delivery)
	if status != http.StatusOK {
		jsonError(w, status, msg)
		return
	}
	err := a.deps.Store.EnsureContact(ctx, userHash, tier)
	if err != nil {
		a.fail(w, "contact", err)
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
	for _, e := range existing {
		if sameAlert(e, alert) {
			writeJSON(w, http.StatusConflict, struct {
				Error   string `json:"error"`
				AlertID int64  `json:"alert_id"`
			}{"you already have this alert", e.ID})
			return
		}
	}
	err = alert.Validate()
	if err != nil {
		jsonError(w, http.StatusUnprocessableEntity, err.Error())
		return
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
	// An unchanged delivery is not re-checked, so edits survive a lapsed channel.
	if req.Delivery != "" && req.Delivery != cur.Delivery {
		status, msg := a.deliveryRefusal(ctx, c, req.Delivery)
		if status != http.StatusOK {
			jsonError(w, status, msg)
			return
		}
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

// Channel states the page shows.
const (
	stateVerified = "verified"
	statePending  = "pending"
	stateDisabled = "disabled"
)

// channelView is one channel as GET channels lists it.
type channelView struct {
	Kind       ChannelKind   `json:"kind"`
	Address    string        `json:"address"`
	Source     ChannelSource `json:"source"`
	State      string        `json:"state"`
	Reason     string        `json:"reason"`
	VerifiedAt *time.Time    `json:"verified_at"`
	DisabledAt *time.Time    `json:"disabled_at"`
}

// channelState is verified, pending or disabled, disabled winning.
func channelState(c Channel) string {
	switch {
	case c.DisabledAt != nil:
		return stateDisabled
	case c.VerifiedAt != nil:
		return stateVerified
	default:
		return statePending
	}
}

func viewChannel(c Channel) channelView {
	return channelView{
		Kind: c.Kind, Address: c.Address, Source: c.Source, State: channelState(c),
		Reason: c.DisabledReason, VerifiedAt: c.VerifiedAt, DisabledAt: c.DisabledAt,
	}
}

// channelViews is the user's channels, with the contact's Discord id
// standing in when no Discord row exists.
func (a *API) channelViews(ctx context.Context, userHash string) ([]channelView, error) {
	rows, err := a.deps.Store.Channels(ctx, userHash)
	if err != nil {
		return nil, err
	}
	views := make([]channelView, 0, len(rows)+1)
	if !slices.ContainsFunc(rows, func(c Channel) bool { return c.Kind == ChannelDiscord }) {
		c, ok, err := a.deps.Store.ChannelFor(ctx, userHash, ChannelDiscord)
		if err != nil {
			return nil, err
		}
		if ok {
			views = append(views, viewChannel(c))
		}
	}
	for _, c := range rows {
		views = append(views, viewChannel(c))
	}
	return views, nil
}

// channelRow is the stored channel of a kind and source, if any.
func (a *API) channelRow(ctx context.Context, userHash string, kind ChannelKind, source ChannelSource) (Channel, bool, error) {
	rows, err := a.deps.Store.Channels(ctx, userHash)
	if err != nil {
		return Channel{}, false, err
	}
	i := slices.IndexFunc(rows, func(c Channel) bool { return c.Kind == kind && c.Source == source })
	if i < 0 {
		return Channel{}, false, nil
	}
	return rows[i], true, nil
}

// parseEmail is a bare address, trimmed and lowercased; false when invalid.
func parseEmail(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxEmailLen {
		return "", false
	}
	addr, err := mail.ParseAddress(s)
	// A | would break the confirm token, which joins its fields on it.
	if err != nil || addr.Name != "" || addr.Address != s || strings.Contains(s, "|") {
		return "", false
	}
	return strings.ToLower(s), true
}

// emailState is the answer to setting or resending an address.
type emailState struct {
	State   string `json:"state"`
	Address string `json:"address"`
}

// confirmRefusal is why a confirmation mail cannot go out, status 200 when it can.
func (a *API) confirmRefusal(c Caller) (int, string) {
	if a.deps.Mint == nil || a.deps.SendConfirm == nil {
		return http.StatusServiceUnavailable, "email confirmation not configured"
	}
	if !slices.Contains(a.deps.Channels(c.Values), ChannelEmail) {
		return http.StatusUnprocessableEntity, "channel not available on your tier"
	}
	if c.Origin == "" {
		return http.StatusBadRequest, "cannot build a confirmation link for this host"
	}
	return http.StatusOK, ""
}

// mailConfirm mints a confirm link for address and mails it, answering 202.
func (a *API) mailConfirm(ctx context.Context, w http.ResponseWriter, c Caller, address string) {
	token := a.deps.Mint(Token{Kind: TokenConfirm, UserHash: c.UserHash, Address: address, Expires: time.Now().Add(a.deps.ConfirmTTL)})
	link := c.Origin + "/alerts/confirm?token=" + url.QueryEscape(token)
	err := a.deps.SendConfirm(ctx, address, link)
	if err != nil {
		log.Printf("alerts: confirm mail failed: %v", err)
		jsonError(w, http.StatusBadGateway, "could not send the confirmation mail")
		return
	}
	writeJSON(w, http.StatusAccepted, emailState{State: statePending, Address: address})
}

func (a *API) setEmail(w http.ResponseWriter, r *http.Request, c Caller) {
	ctx := r.Context()
	status, msg := a.confirmRefusal(c)
	if status != http.StatusOK {
		jsonError(w, status, msg)
		return
	}
	var body struct {
		Address string `json:"address"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	address, ok := parseEmail(body.Address)
	if !ok {
		jsonError(w, http.StatusUnprocessableEntity, "enter a valid email address")
		return
	}
	cur, found, err := a.channelRow(ctx, c.UserHash, ChannelEmail, SourceUser)
	if err != nil {
		a.fail(w, "channels", err)
		return
	}
	if found && strings.EqualFold(cur.Address, address) {
		// The address already confirmed and working needs no mail.
		if channelState(cur) == stateVerified {
			writeJSON(w, http.StatusOK, emailState{State: stateVerified, Address: cur.Address})
			return
		}
		msg := reverifyRefusal(cur)
		if msg != "" {
			jsonError(w, http.StatusUnprocessableEntity, msg)
			return
		}
	}
	if !a.confirmAllowed(ctx, w, c, address) {
		return
	}
	// The channel row needs its contact, which a failed login write may not have left.
	err = a.deps.Store.EnsureContact(ctx, c.UserHash, c.Tier)
	if err != nil {
		a.fail(w, "contact", err)
		return
	}
	err = a.deps.Store.UpsertChannel(ctx, Channel{UserHash: c.UserHash, Kind: ChannelEmail, Address: address, Source: SourceUser})
	if err != nil {
		a.fail(w, "channel", err)
		return
	}
	a.mailConfirm(ctx, w, c, address)
}

func (a *API) resendEmail(w http.ResponseWriter, r *http.Request, c Caller) {
	ctx := r.Context()
	status, msg := a.confirmRefusal(c)
	if status != http.StatusOK {
		jsonError(w, status, msg)
		return
	}
	cur, found, err := a.channelRow(ctx, c.UserHash, ChannelEmail, SourceUser)
	if err != nil {
		a.fail(w, "channels", err)
		return
	}
	// A verified address needs no mail unless a bounce disabled it.
	if !found || channelState(cur) == stateVerified {
		jsonError(w, http.StatusNotFound, "no address to confirm")
		return
	}
	msg = reverifyRefusal(cur)
	if msg != "" {
		jsonError(w, http.StatusUnprocessableEntity, msg)
		return
	}
	address := strings.ToLower(cur.Address)
	if !a.confirmAllowed(ctx, w, c, address) {
		return
	}
	a.mailConfirm(ctx, w, c, address)
}

// reverifyRefusal is why the user's own disabled row may not get a new
// confirm mail, empty when it may; confirmAllowed refuses a complaint.
func reverifyRefusal(cur Channel) string {
	switch {
	case cur.DisabledAt == nil, cur.DisabledReason == ReasonBounced, cur.DisabledReason == ReasonComplained:
		return ""
	case cur.DisabledReason == ReasonUnsubscribed:
		return "this address unsubscribed; use Enable to turn it back on"
	default:
		return "this address cannot receive mail from us"
	}
}

// confirmAllowed charges the confirm limiter, then refuses an address
// anyone's recipient marked as spam; false means it answered.
func (a *API) confirmAllowed(ctx context.Context, w http.ResponseWriter, c Caller, address string) bool {
	if !a.deps.ConfirmLimiter.Allow(c.UserHash) {
		jsonError(w, http.StatusTooManyRequests, "too many confirmation mails; try again later")
		return false
	}
	rows, err := a.deps.Store.ChannelByAddress(ctx, ChannelEmail, address)
	if err != nil {
		a.fail(w, "channels", err)
		return false
	}
	if slices.ContainsFunc(rows, func(ch Channel) bool { return ch.DisabledAt != nil && ch.DisabledReason == ReasonComplained }) {
		jsonError(w, http.StatusUnprocessableEntity, "this address cannot receive mail from us")
		return false
	}
	return true
}

func (a *API) deleteEmail(w http.ResponseWriter, r *http.Request, c Caller) {
	ctx := r.Context()
	_, found, err := a.channelRow(ctx, c.UserHash, ChannelEmail, SourceUser)
	if err != nil {
		a.fail(w, "channels", err)
		return
	}
	if !found {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	err = a.deps.Store.DeleteChannel(ctx, c.UserHash, ChannelEmail, SourceUser)
	if err != nil {
		a.fail(w, "channel", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) enableChannel(w http.ResponseWriter, r *http.Request, c Caller) {
	ctx := r.Context()
	var body struct {
		Kind ChannelKind `json:"kind"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.Kind != ChannelDiscord && body.Kind != ChannelEmail {
		jsonError(w, http.StatusUnprocessableEntity, "unknown channel")
		return
	}
	cur, found, err := a.channelRow(ctx, c.UserHash, body.Kind, SourcePatreon)
	if err != nil {
		a.fail(w, "channels", err)
		return
	}
	if !found {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	if cur.DisabledAt != nil && cur.DisabledReason == ReasonComplained {
		jsonError(w, http.StatusUnprocessableEntity, "this address cannot receive mail from us")
		return
	}
	err = a.deps.Store.EnableChannel(ctx, c.UserHash, body.Kind, SourcePatreon)
	if err != nil {
		a.fail(w, "channel", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
