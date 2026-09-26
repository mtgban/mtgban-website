// chart-range.js - keeps a chart's loaded history in step with the range asked
// for. The page renders only what it first draws, so a wider range has to be
// fetched from /api/chart. See docs/chart-page-loading.md.

// ChartRangeLoader fetches wider windows on demand. opts:
//   ids         the roster, spelled as the ?chart= url spells it
//   maxDays     the ceiling the viewer's tier allows
//   loadedDays  what the page already rendered
//   onData      installs a fetched payload into the chart
//   onBusy      optional; called with true/false around a fetch
function ChartRangeLoader(opts) {
    this.ids = opts.ids;
    this.maxDays = opts.maxDays;
    this.loadedDays = opts.loadedDays;
    this.onData = opts.onData;
    this.onBusy = opts.onBusy || function() {};
    this.inflight = null;
    this.waiting = [];
}

// want resolves a range selection to a number of days. Zero means "all", which
// is the whole entitlement rather than an unbounded ask.
ChartRangeLoader.prototype.want = function(rangeDays) {
    if (!rangeDays || rangeDays > this.maxDays) return this.maxDays;
    return rangeDays;
};

// ensure calls cb once the chart holds at least rangeDays of history. When that
// is already true it calls back synchronously, so the common case - narrowing,
// or picking a range inside what was rendered - does no work at all.
//
// A failed fetch still calls back: the chart keeps the window it has and draws
// that, which is a shorter chart rather than a broken one.
ChartRangeLoader.prototype.ensure = function(rangeDays, cb) {
    var want = this.want(rangeDays);
    if (want <= this.loadedDays) {
        cb();
        return;
    }
    var self = this;
    // Ask for the ceiling rather than for exactly what was wanted: widening
    // twice costs two round trips and two cache entries, and the viewer who
    // widens once usually widens again.
    var ask = this.maxDays;
    // A second ask while the first is in flight waits on it rather than being
    // dropped: the callback is what applies the new range window, so returning
    // here would leave the select and localStorage saying one thing and the
    // chart drawing another.
    this.waiting.push(cb);
    if (this.inflight === ask) return;
    this.inflight = ask;
    this.onBusy(true);

    fetch('/api/chart/' + encodeURIComponent(this.ids) + '?range=' + ask)
        .then(function(r) {
            if (!r.ok) throw new Error('chart range ' + r.status);
            return r.json();
        })
        .then(function(data) {
            // A wider window holds the one drawn, so an empty answer is never a
            // widening: it is how the legacy read still reports an archive error.
            if (!data || !data.datasets || !data.datasets.length) throw new Error('chart range: empty payload');
            var got = data.loadedDays || ask;
            // A response narrower than what is already drawn is not a widening:
            // installing it would shrink the chart. Keep what the page has and
            // let the next attempt try again.
            if (got < self.loadedDays) throw new Error('chart range: narrower than loaded');
            self.loadedDays = got;
            self.onData(data);
        })
        .catch(function(err) {
            // Leave loadedDays alone so a later attempt can retry.
            if (typeof console !== 'undefined') console.warn(err);
        })
        .then(function() {
            self.inflight = null;
            self.onBusy(false);
            var pending = self.waiting;
            self.waiting = [];
            pending.forEach(function(fn) { fn(); });
        });
};

// chartNumbers normalises a fetched series to numbers and nulls. Usually a
// copy, but responses cache for an hour, so one sent before gaps became null
// can still arrive with quoted prices and "Number.NaN" gaps.
function chartNumbers(data) {
    return (data || []).map(function(v) {
        if (v === null || v === undefined) return null;
        var n = typeof v === 'number' ? v : parseFloat(v);
        return isNaN(n) ? null : n;
    });
}

// chartDatasetConfig turns one API dataset into the Chart.js dataset the page
// builds inline, so a widened chart is shaped exactly like the rendered one.
function chartDatasetConfig(ds, color) {
    return {
        label: ds.name,
        cardId: ds.cardId || '',
        data: chartNumbers(ds.data),
        borderColor: color || ds.color,
        referenceKey: ds.reference || ds.name,
        fill: 'origin',
    };
}
