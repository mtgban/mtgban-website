package main

import (
	"context"
	"net/http"
	"net/url"
	"sync"

	"github.com/mtgban/mtgban-website/internal/siteorigin"
	"github.com/mtgban/mtgban-website/observability"
)

// FeatureCounter counts feature use by minute; nil when feature counts are off.
var FeatureCounter *observability.Counter

// dimsKey is the context key of a request's dimsHolder.
type dimsKey struct{}

// dimsHolder keeps a request's dimensions once the first fact works them out.
type dimsHolder struct {
	mu  sync.Mutex
	set bool
	d   observability.Dims
}

func holderOf(r *http.Request) *dimsHolder {
	h, ok := r.Context().Value(dimsKey{}).(*dimsHolder)
	if !ok {
		return nil
	}
	return h
}

// withDimsHolder returns r carrying an empty holder for its dimensions.
func withDimsHolder(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), dimsKey{}, &dimsHolder{}))
}

// withMetricDims fills the holder already in r's context with d, or installs
// a filled one when there is none, so a route's http.status row and its own
// facts carry the same dimensions.
func withMetricDims(r *http.Request, d observability.Dims) *http.Request {
	if h := holderOf(r); h != nil {
		h.mu.Lock()
		h.d, h.set = d, true
		h.mu.Unlock()
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), dimsKey{}, &dimsHolder{set: true, d: d}))
}

// metricDims is r's dimensions, worked out once a request where r carries a holder.
func metricDims(r *http.Request) observability.Dims {
	h := holderOf(r)
	if h == nil {
		return requestDims(r)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.set {
		h.d, h.set = requestDims(r), true
	}
	return h.d
}

// dimsSignature is verifiedRequestSignature without parsing the body: a sig
// only an unparsed body carries is ignored, and one in both it and the URL is
// read from the URL.
func dimsSignature(r *http.Request) string {
	sig, _ := dimsValues(r)
	return sig
}

// dimsValues is dimsSignature and the values it carries, nil for none.
func dimsValues(r *http.Request) (string, url.Values) {
	formSig := r.URL.Query().Get("sig")
	if r.Form != nil {
		formSig = r.Form.Get("sig")
	}
	sig := cookieSignature(r)
	if sig == "" {
		sig = formSig
	}
	if !signatureUnexpired(sig) {
		sig = ""
	}
	if formSig != "" {
		sig = formSig
	}
	v, ok := signatureIsValid(sig)
	if !ok {
		return "", nil
	}
	return sig, v
}

// requestDims reads r's dimensions off its checked signature, for a route with no signing wrapper.
func requestDims(r *http.Request) observability.Dims {
	_, v := dimsValues(r)
	return signatureDims(r, v)
}

// withSignedDims fills r's holder from v, a checked signature's values or nil, when counting is on.
func withSignedDims(r *http.Request, v url.Values) *http.Request {
	if FeatureCounter == nil {
		return r
	}
	return withMetricDims(r, signatureDims(r, v))
}

// signatureDims is r's dimensions read off v, a checked signature's values or nil, and its user agent.
func signatureDims(r *http.Request, v url.Values) observability.Dims {
	device := "desktop"
	if isMobileRequest(r) {
		device = "mobile"
	}
	return observability.Dims{
		Instance: observabilityInstance,
		Tier:     storedTier(v.Get("UserTier")),
		Device:   device,
		Signed:   v.Get("UserEmail") != "",
		Bot:      observability.IsBot(r.UserAgent()),
	}
}

// storedTier is tier as stored: "Any" when empty, "other" unless the ACL names it.
func storedTier(tier string) string {
	if tier == "" || tier == "Any" {
		return "Any"
	}
	if _, ok := ACL()[tier]; !ok {
		return "other"
	}
	return tier
}

// pageLabelSet is pageLabels as a set, built on first use.
var pageLabelSet = sync.OnceValue(func() map[string]bool {
	set := map[string]bool{}
	for _, label := range pageLabels() {
		set[label] = true
	}
	return set
})

// metricValidators answers the registry's checks; p may be nil, and then no store is known.
func metricValidators(p *prices) observability.Validators {
	return observability.Validators{
		Store: func(shorthand string) bool {
			if p == nil {
				return false
			}
			_, seller := p.index.seller[shorthand]
			_, vendor := p.index.vendor[shorthand]
			return seller || vendor
		},
		Page:   func(label string) bool { return pageLabelSet()[label] },
		Route:  func(label string) bool { return routeLabelSet()[label] },
		Origin: func(host string) bool { return handoffOriginHosts()[host] },
	}
}

// count stores one fact the registry allows, or counts it as rejected.
func count(d observability.Dims, p *prices, scope, name, value string) {
	if FeatureCounter == nil {
		return
	}
	n, ok := observability.Lookup(name)
	if ok {
		scope, value, ok = n.Check(scope, value, metricValidators(p))
	}
	if !ok {
		FeatureCounter.Reject()
		return
	}
	FeatureCounter.Add(d, scope, name, value, 1)
}

// addChecked adds n to a fact the caller already ran through the registry's Check.
func addChecked(d observability.Dims, scope, name, value string, n int64) {
	if FeatureCounter == nil {
		return
	}
	FeatureCounter.Add(d, scope, name, value, n)
}

// rejectChecked counts a fact the caller's registry check refused.
func rejectChecked() {
	if FeatureCounter == nil {
		return
	}
	FeatureCounter.Reject()
}

// observe counts a fact about r for a name with no scope.
func observe(r *http.Request, name, value string) {
	if FeatureCounter == nil {
		return
	}
	count(metricDims(r), nil, "", name, value)
}

// observeScoped counts a fact about r under scope.
func observeScoped(r *http.Request, scope, name, value string) {
	if FeatureCounter == nil {
		return
	}
	count(metricDims(r), nil, scope, name, value)
}

// observeStore is observeScoped with a prices snapshot, for a name whose
// scope or value is a store. observe and observeScoped validate with no
// snapshot, so a store there folds to "other".
func observeStore(r *http.Request, p *prices, scope, name, value string) {
	if FeatureCounter == nil {
		return
	}
	count(metricDims(r), p, scope, name, value)
}

// observeJob counts a fact with no request; device is "job" or "discord".
func observeJob(device, scope, name, value string) {
	if FeatureCounter == nil {
		return
	}
	count(observability.Dims{Instance: observabilityInstance, Device: device}, nil, scope, name, value)
}

// requestObserver fills another package's hook that serves a request.
func requestObserver(r *http.Request, scope, name, value string) {
	if FeatureCounter == nil {
		return
	}
	count(metricDims(r), nil, scope, name, value)
}

// jobObserver fills another package's hook with no request; device is "job" or "discord".
func jobObserver(device string) func(scope, name, value string) {
	return func(scope, name, value string) {
		if FeatureCounter == nil {
			return
		}
		count(observability.Dims{Instance: observabilityInstance, Device: device}, nil, scope, name, value)
	}
}

// refererPage is the page label of r's Referer on r's own host, else "other".
func refererPage(r *http.Request) string {
	u, err := url.Parse(r.Referer())
	if err != nil || !ownSiteHost(u.Host) || u.Host != siteorigin.Host(r) {
		return "other"
	}
	return pageLabel(u.Path, u.Query().Get("page"))
}

// fact is one fact held as data, for a handler that emits many at once.
type fact struct{ scope, name, value string }

// newFact is the one place a fact is built; name is a string literal.
func newFact(scope, name, value string) fact {
	return fact{scope: scope, name: name, value: value}
}

// observeFacts counts each fact about r; p may be nil.
func observeFacts(r *http.Request, p *prices, facts []fact) {
	if FeatureCounter == nil {
		return
	}
	for _, f := range facts {
		observeStore(r, p, f.scope, f.name, f.value)
	}
}

// countEdges are smallCount's and pageBucket's bucket edges.
var countEdges = []int64{1, 2, 3, 6}

// smallCount buckets n as "0", "1", "2", "3-5" or "6+".
func smallCount(n int) string {
	return observability.Bucket(countEdges, int64(n))
}

// pageBucket buckets n as "1", "2", "3-5" or "6+"; below 1 is "1".
func pageBucket(n int) string {
	return observability.Bucket(countEdges, int64(max(n, 1)))
}

// refusalReason is auth.refuse's value for a refusal signing wrote with status.
func refusalReason(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "unauthenticated"
	case http.StatusTooManyRequests:
		return "rate_limited"
	}
	return "other"
}
