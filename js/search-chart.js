// Set a per-chart-style key
var legendStorageKey = 'BANChart' + (window.BAN_SEARCH_CHART.sealed ? 'Sealed' : '');

// Prepare options
var allLabels = window.BAN_SEARCH_CHART.axisLabels;
var opts = getChartOpts(allLabels, localStorage.getItem("chartSpanGaps"));

// Checkpoint annotations (bans/releases/reprints).
// clip: false lets badges render above the plot area in the
// top padding band reserved by buildCheckpointAnnotations.
var chartCheckpoints = window.BAN_SEARCH_CHART.checkpoints;
var checkpointChartRef = { chart: null };
if (chartCheckpoints && chartCheckpoints.length) {
    restoreCheckpointTypes();
    opts.plugins.annotation = {
        clip: false,
        annotations: buildCheckpointAnnotations(chartCheckpoints, checkpointChartRef, opts),
    };
}

// Apply saved or default date range before chart creation.
// Multi-card charts remember their range under a separate key and
// default to the full union of every card's history, so the longest
// timeline is visible at once; shorter-history cards just begin
// partway along the shared axis instead of clamping the whole chart.
var rangeKey = window.BAN_SEARCH_CHART.multi ? 'chartMultiDateRange' : 'chartDateRange';
// The same choice, mirrored into a cookie. localStorage is the
// front-end's own copy, but the server cannot read it, and a
// server that does not know the range renders the one the select
// starts on and then watches the viewer widen it - which draws
// the chart twice on every load, for anyone who ever widened once.
var rangeCookie = window.BAN_SEARCH_CHART.multi ? 'SearchChartMultiRange' : 'SearchChartRange';
function rememberRange(rangeDays) {
    localStorage.setItem(rangeKey, rangeDays.toString());
    setCookie(rangeCookie, rangeDays.toString(), 365);
}
var savedRange = localStorage.getItem(rangeKey);
if (window.BAN_SEARCH_CHART.multi && savedRange === null) {
    savedRange = '0';
}
if (savedRange !== null) {
    document.getElementById('dateRange').value = savedRange;
}
var initialRange = parseInt(document.getElementById('dateRange').value);
// Write it back even when nothing changed, so the cookie exists
// from the first load rather than only once the select is touched.
rememberRange(initialRange);
if (initialRange > 0 && initialRange < allLabels.length) {
    opts.scales.x.min = allLabels[initialRange - 1];
}
setReleasesSuppressedByRange(initialRange);

// Create the chart
var ctx = document.getElementById('cardChart').getContext('2d');
var cardChart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: allLabels,
        datasets: window.BAN_SEARCH_CHART.datasets
    },
    options: opts,
});

// Expose chart so checkpoint toggle handlers can reach it
window.cardChart = cardChart;
checkpointChartRef.chart = cardChart;

// How much history the page actually rendered, and how much the
// viewer is entitled to. They differ because the page inlines the
// window the chart first draws and fetches the rest only if asked
// for it; installChartPayload is what a fetched wider window
// replaces the chart's contents with, and is assigned below by
// whichever of the two chart shapes this page is.
var chartLoadedDays = window.BAN_SEARCH_CHART.loadedDays;
var chartMaxDays = window.BAN_SEARCH_CHART.maxDays;
var chartRosterIDs = window.BAN_SEARCH_CHART.ids;
var installChartPayload;

// The axis a widened payload brings, installed everywhere it is
// held. x-top is a transparent spacer scale, but it is a category
// axis built from the labels the chart was constructed with, so
// leaving it alone keeps the old window's labels on a chart that
// no longer has them.
function installLabels(labels) {
    cardChart.data.labels = labels;
    var top = cardChart.options.scales['x-top'];
    if (top) top.labels = labels;
}

// Checkpoint annotations are keyed to the axis, so a widened
// chart needs the ones its new span crosses, not the ones the
// rendered window did.
function installCheckpoints(list) {
    chartCheckpoints = list || [];
    var toggles = document.querySelector('.chart-checkpoint-toggles');
    if (toggles) toggles.style.display = chartCheckpoints.length ? '' : 'none';
    if (!chartCheckpoints.length) {
        if (cardChart.options.plugins.annotation) {
            cardChart.options.plugins.annotation.annotations = {};
        }
        return;
    }
    restoreCheckpointTypes();
    // Built against the same options object the first pass used,
    // not against the chart's resolved copy of it.
    // buildCheckpointAnnotations reserves the top padding band
    // the badges are positioned into by mutating what it is
    // handed, so handing it a different object reserves the band
    // somewhere the layout never reads and the icons land off the
    // top of the canvas.
    var annotations = buildCheckpointAnnotations(chartCheckpoints, checkpointChartRef, opts);
    opts.plugins.annotation = { clip: false, annotations: annotations };
    cardChart.options.plugins.annotation = opts.plugins.annotation;
    cardChart.options.layout = opts.layout;
}

if (window.BAN_SEARCH_CHART.multi) {
    // Multi-card mode: keep one persistent line per card and swap its
    // data array when the reference changes. Chart.js then animates the
    // value transition (TCG Low → TCG Market morphs in place) instead
    // of fading datasets in/out, which feels choppy and makes the Y
    // axis snap.
    var chartReferences = window.BAN_SEARCH_CHART.references;
    var savedRef = localStorage.getItem('chartMultiRef');
    var currentReference = (savedRef && chartReferences.indexOf(savedRef) >= 0)
        ? savedRef : chartReferences[0];

    // Reshape the server-rendered (card × reference) datasets into a
    // cardId -> { label, color, references: { ref: data } } lookup, then
    // collapse the chart down to one dataset per card. Keyed by cardId
    // (the UUID), not the display label, so two printings that share a
    // "Name (SET)" label stay distinct lines instead of merging.
    var cardLines = {};
    var cardOrder = [];
    cardChart.data.datasets.forEach(function(ds) {
        if (!cardLines[ds.cardId]) {
            cardLines[ds.cardId] = { label: ds.label, color: ds.borderColor, references: {} };
            cardOrder.push(ds.cardId);
        }
        cardLines[ds.cardId].references[ds.referenceKey] = ds.data;
    });
    cardChart.data.datasets = cardOrder.map(function(id) {
        var cl = cardLines[id];
        return {
            cardId: id,
            label: cl.label,
            data: cl.references[currentReference] || [],
            borderColor: cl.color,
            fill: 'origin',
        };
    });
    cardChart.update('none');

    function selectReference(ref) {
        currentReference = ref;

        var newById = {};
        cardChart.data.datasets.forEach(function(ds) {
            var cl = cardLines[ds.cardId];
            newById[ds.cardId] = cl ? (cl.references[ref] || []) : [];
        });

        // Pre-bridge: for positions that are NaN in current data but
        // have a value in the new reference, plant the nearest valid
        // neighbor's value as the starting point. update('none') commits
        // that state instantly, then the second update() animates from
        // it to the real new data — newly-appearing points slide out of
        // the existing line instead of popping in at their final spot.
        cardChart.data.datasets.forEach(function(ds) {
            var newData = newById[ds.cardId];
            var oldData = ds.data;
            var bridged = oldData.map(function(v, i) {
                var oldNum = parseFloat(v);
                if (!isNaN(oldNum)) return oldNum;
                var newNum = parseFloat(newData[i]);
                if (isNaN(newNum)) return NaN;
                for (var k = 1; k < oldData.length; k++) {
                    if (i - k >= 0) {
                        var leftVal = parseFloat(oldData[i - k]);
                        if (!isNaN(leftVal)) return leftVal;
                    }
                    if (i + k < oldData.length) {
                        var rightVal = parseFloat(oldData[i + k]);
                        if (!isNaN(rightVal)) return rightVal;
                    }
                }
                return newNum;
            });
            ds.data = bridged;
        });
        cardChart.update('none');

        cardChart.data.datasets.forEach(function(ds) {
            ds.data = newById[ds.cardId];
        });
        cardChart.update();

        renderChartLegend(cardChart, 'chartLegend');
        document.querySelectorAll('.ref-picker-btn').forEach(function(btn) {
            btn.classList.toggle('active', btn.getAttribute('data-ref') === ref);
        });
        localStorage.setItem('chartMultiRef', ref);
    }
    // Draws the picker from chartReferences, which the server renders
    // for the window the page drew and a widened payload can extend.
    // Listeners rather than inline onclick, since these buttons are
    // rebuilt rather than parsed from the template.
    function renderReferencePicker() {
        var host = document.querySelector('.chart-ref-picker');
        if (!host) return;
        host.textContent = '';
        chartReferences.forEach(function(ref) {
            var btn = document.createElement('a');
            btn.className = 'btn default ref-picker-btn' +
                (ref === currentReference ? ' active' : '');
            btn.setAttribute('data-ref', ref);
            btn.href = 'javascript:void(0)';
            btn.textContent = ref;
            btn.addEventListener('click', function() { selectReference(ref); });
            host.appendChild(btn);
        });
    }
    renderReferencePicker();

    // A widened roster arrives as the same (card × reference) list the
    // page rendered, so it rebuilds the same lookup and re-collapses to
    // one line per card on whichever reference is showing.
    installChartPayload = function(data) {
        installLabels(data.axisLabels);
        cardLines = {};
        cardOrder = [];
        data.datasets.forEach(function(ds) {
            if (!cardLines[ds.cardId]) {
                cardLines[ds.cardId] = { label: ds.name, color: ds.color, references: {} };
                cardOrder.push(ds.cardId);
            }
            cardLines[ds.cardId].references[ds.reference || ds.name] = chartNumbers(ds.data);
        });
        if (data.references && data.references.length) {
            chartReferences = data.references;
            if (chartReferences.indexOf(currentReference) < 0) {
                currentReference = chartReferences[0];
            }
            // The picker was rendered from the window the page drew,
            // so a wider one can carry a price source that window had
            // no button for. Re-render it rather than only re-marking
            // what is already there, or that source is charted with
            // no way to select it.
            renderReferencePicker();
        }
        cardChart.data.datasets = cardOrder.map(function(id) {
            var cl = cardLines[id];
            return {
                cardId: id,
                label: cl.label,
                data: cl.references[currentReference] || [],
                borderColor: cl.color,
                fill: 'origin',
            };
        });
        installCheckpoints(data.checkpoints);
        renderChartLegend(cardChart, 'chartLegend');
    };

    // Hovering a legend entry drives the sidebar preview to that
    // card by replaying its result row's hover, so the image,
    // printings and products all update together (setting just the
    // image left the printings list mismatched). Delegated on the
    // container so it keeps working after the legend re-renders.
    (function() {
        var legendEl = document.getElementById('chartLegend');
        if (!legendEl) return;
        var lastHoverId = null;
        legendEl.addEventListener('mouseover', function(e) {
            var item = e.target.closest('.chart-legend-item[data-card-id]');
            if (!item) return;
            var cardId = item.getAttribute('data-card-id');
            if (cardId === lastHoverId) return;
            lastHoverId = cardId;
            // Legend entries carry the chart id (ban:<id> when long-form reads
            // are on); match them to the row's data-chart-id, not data-card-id.
            var row = document.querySelector('.result-header[data-chart-id="' + cardId + '"]');
            if (row && typeof row.onmouseenter === 'function') row.onmouseenter();
        });
        legendEl.addEventListener('mouseleave', function() { lastHoverId = null; });
    })();
} else {
    // Load state from local storage
    applySavedLegendState(cardChart, legendStorageKey);

    // A widened single-card chart is rebuilt rather than patched in
    // place: a longer window can hold a provider that has no data at
    // all in the rendered one, which would otherwise be left out.
    installChartPayload = function(data) {
        installLabels(data.axisLabels);
        cardChart.data.datasets = data.datasets.map(function(ds) {
            return chartDatasetConfig(ds);
        });
        installCheckpoints(data.checkpoints);
        applySavedLegendState(cardChart, legendStorageKey);
        renderChartLegend(cardChart, 'chartLegend', legendStorageKey);
    };
}

// Build custom HTML legend (single-card clicks persist via
// legendStorageKey). Multi mode passes no key: its legend is a
// per-card index, and writing that into the per-price-source
// BANChart key would corrupt every single-card chart's saved state.
renderChartLegend(cardChart, 'chartLegend', window.BAN_SEARCH_CHART.multi ? undefined : legendStorageKey);

// Apply theme (light/dark)
rethemeFirstAxes(cardChart);

// Re-run on theme flips (class changes on <body>/<html>)
const rerun = () => cardChart && rethemeFirstAxes(cardChart);
const mo = new MutationObserver(rerun);
mo.observe(document.body, {
    attributes: true,
    attributeFilter: ['class'],
});
mo.observe(document.documentElement, {
    attributes: true,
    attributeFilter: ['class'],
});

// The loader owns everything about history the chart does not yet
// hold. Narrowing, or picking a range inside the rendered window,
// never reaches the network.
var chartRange = new ChartRangeLoader({
    ids: chartRosterIDs,
    maxDays: chartMaxDays,
    loadedDays: chartLoadedDays,
    onData: function(data) { installChartPayload(data); },
    onBusy: function(busy) {
        var sel = document.getElementById('dateRange');
        if (sel) sel.disabled = busy;
    },
});

function applyRangeWindow(rangeDays) {
    var allLabels = cardChart.data.labels;
    if (rangeDays === 0 || rangeDays >= allLabels.length) {
        cardChart.options.scales.x.min = undefined;
    } else {
        // Labels are newest-first; element at rangeDays-1 is the cutoff
        cardChart.options.scales.x.min = allLabels[rangeDays - 1];
    }
    setReleasesSuppressedByRange(rangeDays);
    cardChart.update();
}

// drawRange draws a range once the loader holds it. A widening that
// failed leaves the chart what it had, so it draws all of that, sets
// the select to it, where picking the range again retries, and says so.
function drawRange(rangeDays) {
    return function(err) {
        document.getElementById('chartRangeFailed').hidden = !err;
        if (err) {
            rangeDays = chartRange.loadedDays;
            document.getElementById('dateRange').value = String(rangeDays);
        }
        applyRangeWindow(rangeDays);
    };
}

function changeRange(rangeDays) {
    rememberRange(rangeDays);
    chartRange.ensure(rangeDays, drawRange(rangeDays));
}

// The select can start on a range wider than the page rendered -
// a saved preference, or a roster, which defaults to the whole
// span. Fill it in now so the chart matches what the control says.
if (chartRange.want(initialRange) > chartLoadedDays) {
    chartRange.ensure(initialRange, drawRange(initialRange));
}
function toggleGaps() {
    cardChart.options.spanGaps = !cardChart.options.spanGaps;
    cardChart.update();
    localStorage.setItem("chartSpanGaps", cardChart.options.spanGaps);
}
function downloadAsImg() {
    var chartImg = document.createElement('a');
    chartImg.download = window.BAN_SEARCH_CHART.downloadName;

    var scaleFactor = 2;
    var border = 10;
    var chartW = cardChart.width * scaleFactor;
    var chartH = cardChart.height * scaleFactor;

    // Lay out a legend strip mirroring the on-screen legend (same
    // labels, colours, and hidden state) so the exported PNG is
    // self-describing. Read it from the datasets — the HTML legend
    // is a sibling div, not part of the canvas.
    var datasets = cardChart.data.datasets || [];
    var fontSize = 13 * scaleFactor;
    var dotR = 5 * scaleFactor;
    var swatchGap = 7 * scaleFactor;
    var itemGap = 22 * scaleFactor;
    var rowH = fontSize + 12 * scaleFactor;
    var pad = border * scaleFactor;
    var textColor = readVar('--normal') || '#000000';

    var measureCtx = document.createElement('canvas').getContext('2d');
    measureCtx.font = fontSize + 'px sans-serif';
    var items = datasets.map(function (ds, i) {
        var label = ds.label || '';
        var textW = measureCtx.measureText(label).width;
        return {
            label: label,
            color: ds.borderColor || ds.backgroundColor || '#888888',
            hidden: !cardChart.isDatasetVisible(i),
            width: dotR * 2 + swatchGap + textW,
            textW: textW,
        };
    });

    // Wrap items into rows no wider than the chart.
    var rows = [];
    var row = [];
    var rowW = 0;
    items.forEach(function (it) {
        var w = it.width + itemGap;
        if (row.length && rowW + w > chartW) {
            rows.push(row);
            row = [];
            rowW = 0;
        }
        row.push(it);
        rowW += w;
    });
    if (row.length) rows.push(row);
    var legendH = items.length ? rows.length * rowH + pad : 0;

    var exportCanvas = document.createElement('canvas');
    exportCanvas.width = chartW;
    exportCanvas.height = chartH + legendH;

    var exportCtx = exportCanvas.getContext('2d');
    exportCtx.fillStyle = readVar('--background');
    exportCtx.fillRect(0, 0, exportCanvas.width, exportCanvas.height);
    exportCtx.drawImage(cardChart.canvas, border, border, chartW - border * 3, chartH - border * 2);

    // Draw the legend strip under the chart, rows centred.
    exportCtx.font = fontSize + 'px sans-serif';
    exportCtx.textBaseline = 'middle';
    var y = chartH + rowH / 2;
    rows.forEach(function (r) {
        var totalW = r.reduce(function (s, it) { return s + it.width + itemGap; }, 0) - itemGap;
        var x = Math.max(pad, (chartW - totalW) / 2);
        r.forEach(function (it) {
            exportCtx.globalAlpha = it.hidden ? 0.4 : 1;
            exportCtx.fillStyle = it.color;
            exportCtx.beginPath();
            exportCtx.arc(x + dotR, y, dotR, 0, Math.PI * 2);
            exportCtx.fill();
            var labelX = x + dotR * 2 + swatchGap;
            exportCtx.fillStyle = textColor;
            exportCtx.fillText(it.label, labelX, y);
            if (it.hidden) {
                exportCtx.strokeStyle = textColor;
                exportCtx.lineWidth = Math.max(1, scaleFactor);
                exportCtx.beginPath();
                exportCtx.moveTo(labelX, y);
                exportCtx.lineTo(labelX + it.textW, y);
                exportCtx.stroke();
            }
            x += it.width + itemGap;
        });
        y += rowH;
    });
    exportCtx.globalAlpha = 1;

    chartImg.href = exportCanvas.toDataURL("image/png");
    chartImg.click();
}

// The pending roster (the chart plus everything batched but not yet
// committed) lives in localStorage so it survives the iframe
// navigating between the search box and result pages, and is shared
// with the iframe (same origin).
function chartPending() {
    return (localStorage.getItem('chartAddPending') || '').split(',').filter(Boolean);
}
function refreshBatchButton() {
    var btn = document.getElementById('chartBatchCommit');
    if (!btn) return;
    var orig = window.BAN_SEARCH_CHART.ids.split(',').filter(Boolean);
    var pend = chartPending();
    var os = {}; orig.forEach(function(x){ os[x] = 1; });
    var ps = {}; pend.forEach(function(x){ ps[x] = 1; });
    var changed = pend.filter(function(x){ return !os[x]; }).length +
                  orig.filter(function(x){ return !ps[x]; }).length;
    btn.disabled = changed === 0;
    btn.style.opacity = changed ? '1' : '0.5';
    btn.style.cursor = changed ? 'pointer' : 'default';
    btn.textContent = changed ? ('Update chart (' + changed + ')') : 'Update chart';
}
function openChartAddModal() {
    var overlay = document.getElementById('chartAddOverlay');
    var frame = document.getElementById('chartAddFrame');
    if (!overlay || !frame) return;
    // Hoist the overlay to <body> so no ancestor's transform/filter/
    // backdrop-filter traps its position:fixed inside a containing
    // block. Done here (not at script-parse time) because the overlay
    // element is rendered further down the page than this script.
    if (overlay.parentNode !== document.body) {
        document.body.appendChild(overlay);
    }
    // Seed the batch with the chart's current roster.
    localStorage.setItem('chartAddPending', window.BAN_SEARCH_CHART.ids);
    refreshBatchButton();
    // Reuse the homepage (it owns the search box now) as the picker;
    // it carries the roster + modal flag so a search from it returns
    // to the results page still in modal context.
    frame.src = '/?chart=' + window.BAN_SEARCH_CHART.ids + '&modal=1';
    // Styling lives entirely in .chart-add-overlay / .open
    // (css/search.css) so the three copies can't drift; just
    // toggle the classes here.
    overlay.classList.add('open');
    document.body.classList.add('chart-add-open');
}
// Send the iframe back to the search box, carrying whatever's been
// batched so far so already-added cards render as added.
function newChartSearch() {
    var frame = document.getElementById('chartAddFrame');
    if (frame) frame.src = '/?chart=' + encodeURIComponent(chartPending().join(',')) + '&modal=1';
}
// Commit the batch: reload the chart with the pending roster.
function commitChartBatch() {
    var pend = chartPending();
    var url = new URL(window.location.href);
    if (pend.length) url.searchParams.set('chart', pend.join(','));
    else url.searchParams.delete('chart');
    url.searchParams.delete('q');
    window.location = url.toString();
}
function closeChartAddModal() {
    var overlay = document.getElementById('chartAddOverlay');
    if (!overlay) return;
    overlay.classList.remove('open');
    document.body.classList.remove('chart-add-open');
}
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        var overlay = document.getElementById('chartAddOverlay');
        if (overlay && overlay.classList.contains('open')) {
            closeChartAddModal();
        }
    }
});
window.addEventListener('message', function(e) {
    if (e.origin !== window.location.origin) return;
    if (!e.data) return;
    // A second Escape inside the iframe asks us to close the modal.
    if (e.data.type === 'chart-modal-close') {
        closeChartAddModal();
        return;
    }
    if (e.data.type !== 'chart-batch-changed') return;
    // The iframe already updated the pending roster in localStorage;
    // just refresh the commit button's count.
    refreshBatchButton();
});
