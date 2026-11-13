package observability

import (
	"cmp"
	"context"
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"
	"time"
)

// MaxErrorLine is the highest line an error row may name.
const MaxErrorLine = 1_000_000

// scripts are the basenames of every file under js/; a drift test in the root package keeps them in step.
var scripts = []string{
	"admin-metrics.js", "admin-people.js", "alerts.js", "api-plans.js", "arbit-filters.js", "arbit-presets.js",
	"arbit-rows.js", "autocomplete.js", "backpack.js", "ban-to-cart.js", "card-art-fallback.js", "card-row.js",
	"cart-prompt.js", "chart-range.js", "chartopts.js", "command-palette.js", "confirm-dialog.js", "cookies.js",
	"copy2clip.js", "edition-combobox.js", "editions-picker.js", "favorites-shared.js", "favorites.js",
	"fetchnames.js", "fflate.min.js", "filtering.js", "followmouse.js", "guide-data.js", "guide.js", "icons.js",
	"list-storage.js", "load-lists.js", "metrics.js", "mobile-chart.js", "navbar.js", "news-filters.js",
	"nightmode.js", "offline-age.js", "offline-banner.js", "offline-db.js", "offline-format.js",
	"offline-images-ui.js", "offline-images.js", "offline-live.js", "offline-mode.js", "offline-page-desktop.js",
	"offline-page-mobile.js", "offline-page.js", "offline-prefer.js", "offline-query.js",
	"offline-render-mobile.js", "offline-render-shared.js", "offline-render.js", "offline-search.js",
	"offline-settings-mobile.js", "offline-sync.js", "offline-util.js", "offline-watch.js", "palette-chips.js",
	"palette-loader.js", "palette-providers.js", "printings-panel.js", "recent-searches.js", "scope.js",
	"screener.js", "sealed.js", "search-chart.js", "search-modal.js", "search-quick-icons.js",
	"search-result-nav.js", "search-sidebar.js", "search-track.js", "search-type-focus.js", "section-fold.js",
	"settings-changes.js", "settings-loader.js", "settings-shell.js", "settings.js", "store-factors.js",
	"store-picker.js", "tooltips.js", "upload-exports.js", "upload-form.js", "upload-handoff.js",
	"upload-optimizer.js", "upload-options.js", "upload-presets.js", "upload-printings.js",
	"upload-processing.js", "upload-share.js", "upload-sort.js", "upload-store-prompt.js", "upload-tabs.js",
	"user-state.js", "utils.js",
}

// errorScopes are where an error may be placed: a script under js/, a page's own inline code, or anywhere else.
var errorScopes = append(slices.Clone(scripts), "inline", "other")

// errorClasses are the error names a report keeps; ScriptError is a muted cross-origin error.
var errorClasses = []string{
	"Error", "TypeError", "ReferenceError", "RangeError", "SyntaxError", "URIError", "EvalError",
	"AggregateError", "AbortError", "NetworkError", "QuotaExceededError", "NotAllowedError",
	"SecurityError", "InvalidStateError", "NotFoundError", "TimeoutError", "ScriptError", "other",
}

// Scripts returns the basenames of every file under js/, sorted.
func Scripts() []string {
	return slices.Clone(scripts)
}

// ErrorClasses returns the error classes an error row may name.
func ErrorClasses() []string {
	return slices.Clone(errorClasses)
}

// NormalizeBuild keeps the 40-hex commit and drops dev's "-<nanos>" suffix.
func NormalizeBuild(s string) (string, bool) {
	sha, suffix, cut := strings.Cut(s, "-")
	if len(sha) != 40 || !allBytes(sha, isLowerHex) {
		return "", false
	}
	if cut && (suffix == "" || !allBytes(suffix, isDigit)) {
		return "", false
	}
	return sha, true
}

func allBytes(s string, f func(byte) bool) bool {
	for i := 0; i < len(s); i++ {
		if !f(s[i]) {
			return false
		}
	}
	return true
}

func isLowerHex(c byte) bool { return isDigit(c) || c >= 'a' && c <= 'f' }

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// maxPendingErrors is the most distinct rows the buffer holds between flushes.
const maxPendingErrors = 400

// ErrorStore writes error rows for one instance and says how many it refused.
type ErrorStore interface {
	UpsertErrors(ctx context.Context, instance string, rows []ErrorRow) (refused int, err error)
}

type errorKey struct {
	day                          time.Time
	device, build, script, class string
	line                         int
}

// ErrorBuffer sums script error rows in memory and writes them off the request path.
type ErrorBuffer struct {
	store      ErrorStore
	instance   string
	now        func() time.Time
	reject     func()
	maxPending int
	sem        chan struct{} // serialises flushes

	mu      sync.Mutex
	pending map[errorKey]int64
	closed  bool
}

// NewErrorBuffer returns a buffer; reject is called once for each row the store refused or the buffer dropped.
func NewErrorBuffer(store ErrorStore, instance string, now func() time.Time, reject func()) *ErrorBuffer {
	if reject == nil {
		reject = func() {}
	}
	return &ErrorBuffer{
		store:      store,
		instance:   instance,
		now:        now,
		reject:     reject,
		maxPending: maxPendingErrors,
		sem:        make(chan struct{}, 1),
		pending:    map[errorKey]int64{},
	}
}

// Add reports false, having stored nothing, when the buffer is full or closed.
func (b *ErrorBuffer) Add(device, build, script, class string, line int, n int64) bool {
	if b == nil {
		return false
	}
	k := errorKey{day: wholeDay(b.now()), device: device, build: build, script: script, class: class, line: line}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false
	}
	if _, ok := b.pending[k]; !ok && len(b.pending) >= b.maxPending {
		return false
	}
	b.pending[k] += n
	return true
}

// Flush writes every pending row in one call; on a failure the rows wait for the next flush.
func (b *ErrorBuffer) Flush(ctx context.Context) (err error) {
	if b == nil {
		return nil
	}
	select {
	case b.sem <- struct{}{}:
		defer func() { <-b.sem }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	taken := b.pending
	b.pending = map[errorKey]int64{}
	b.mu.Unlock()
	if len(taken) == 0 {
		return nil
	}
	rows := make([]ErrorRow, 0, len(taken))
	for k, n := range taken {
		rows = append(rows, ErrorRow{Day: k.day, Device: k.device, Build: k.build, Script: k.script, Class: k.class, Line: k.line, N: n})
	}
	slices.SortFunc(rows, compareErrorRows)

	defer func() {
		if p := recover(); p != nil {
			b.rejectN(len(rows)) // a store that panicked may have written some; never retried
			err = fmt.Errorf("observability: error flush panic: %v", p)
		}
	}()
	refused, err := b.store.UpsertErrors(ctx, b.instance, rows)
	if err != nil {
		b.putBack(rows)
		return err
	}
	b.rejectN(refused)
	return nil
}

// Run flushes every interval until ctx is done.
func (b *ErrorBuffer) Run(ctx context.Context, every time.Duration) {
	if b == nil {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			b.runOnce(ctx, every)
		}
	}
}

func (b *ErrorBuffer) runOnce(ctx context.Context, every time.Duration) {
	defer func() {
		if p := recover(); p != nil {
			log.Println("observability: error buffer panic:", p)
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, every)
	defer cancel()
	if err := b.Flush(ctx); err != nil {
		log.Println("observability: error flush:", err)
	}
}

// Close flushes once, bounded by ctx; Add refuses afterwards.
func (b *ErrorBuffer) Close(ctx context.Context) error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				done <- fmt.Errorf("observability: error close panic: %v", p)
			}
		}()
		done <- b.Flush(ctx)
	}()
	select {
	case err := <-done:
		if err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// putBack merges unsent rows into pending, rejecting those past the cap or after Close.
func (b *ErrorBuffer) putBack(rows []ErrorRow) {
	dropped := 0
	b.mu.Lock()
	for _, r := range rows {
		k := errorKey{day: r.Day, device: r.Device, build: r.Build, script: r.Script, class: r.Class, line: r.Line}
		_, ok := b.pending[k]
		if b.closed || !ok && len(b.pending) >= b.maxPending {
			dropped++
			continue
		}
		b.pending[k] += r.N
	}
	b.mu.Unlock()
	b.rejectN(dropped)
}

func (b *ErrorBuffer) rejectN(n int) {
	for range n {
		b.reject()
	}
}

// compareErrorRows orders rows by day, device, build, script, line and class.
func compareErrorRows(a, b ErrorRow) int {
	return cmp.Or(
		a.Day.Compare(b.Day),
		cmp.Compare(a.Device, b.Device),
		cmp.Compare(a.Build, b.Build),
		cmp.Compare(a.Script, b.Script),
		cmp.Compare(a.Line, b.Line),
		cmp.Compare(a.Class, b.Class),
	)
}
