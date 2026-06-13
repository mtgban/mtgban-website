/* ── Plugins ── */

// Dashed vertical crosshair on hover
const crosshairPlugin = {
    id: 'crosshair',
    afterDatasetsDraw(chart) {
        const active = chart.tooltip?.getActiveElements();
        if (!active?.length) return;

        const x = active[0].element.x;
        const { top, bottom } = chart.chartArea;
        const ctx = chart.ctx;

        ctx.save();
        ctx.beginPath();
        ctx.setLineDash([4, 3]);
        ctx.moveTo(x, top);
        ctx.lineTo(x, bottom);
        ctx.lineWidth = 1;
        ctx.strokeStyle = readVar('--chartjs-crosshair');
        ctx.stroke();
        ctx.restore();
    }
};

// Build per-dataset gradient fills once layout dimensions are known
const gradientFillPlugin = {
    id: 'gradientFill',
    afterLayout(chart) {
        const area = chart.chartArea;
        if (!area) return;

        chart.data.datasets.forEach(function (ds) {
            var color = ds.borderColor;
            if (!color || typeof color !== 'string') return;

            var match = color.match(/(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/);
            if (!match) return;
            var r = match[1], g = match[2], b = match[3];

            var grad = chart.ctx.createLinearGradient(0, area.top, 0, area.bottom);
            grad.addColorStop(0,   'rgba(' + r + ',' + g + ',' + b + ',0.10)');
            grad.addColorStop(0.5, 'rgba(' + r + ',' + g + ',' + b + ',0.03)');
            grad.addColorStop(1,   'rgba(' + r + ',' + g + ',' + b + ',0)');
            ds.backgroundColor = grad;
        });
    }
};

Chart.register(crosshairPlugin, gradientFillPlugin);


/* ── External HTML tooltip ── */

function externalTooltipHandler(context) {
    var chart   = context.chart;
    var tooltip = context.tooltip;
    var container = chart.canvas.parentNode;

    var el = container.querySelector('.chart-tooltip');
    if (!el) {
        el = document.createElement('div');
        el.className = 'chart-tooltip';
        container.appendChild(el);
    }

    if (tooltip.opacity === 0) {
        el.style.opacity = '0';
        return;
    }

    // Build HTML
    var html = '';
    if (tooltip.title && tooltip.title.length) {
        html += '<div class="chart-tooltip-title">' + tooltip.title[0] + '</div>';
    }

    var body = tooltip.body || [];
    body.forEach(function (bodyItem, i) {
        var line = bodyItem.lines[0];
        if (!line) return;
        var colors = tooltip.labelColors[i];
        html += '<div class="chart-tooltip-row">' +
            '<span class="chart-tooltip-swatch" style="background:' + colors.borderColor + '"></span>' +
            '<span>' + line + '</span>' +
            '</div>';
    });

    // Append any checkpoints landing on the hovered date so the user sees
    // price values and event context (bans/releases/reprints) in one popup.
    var hoveredDate = '';
    if (tooltip.dataPoints && tooltip.dataPoints.length) {
        var ms = tooltip.dataPoints[0].parsed.x;
        if (typeof ms === 'number') {
            var d = new Date(ms);
            var pad = function (n) { return (n < 10 ? '0' : '') + n; };
            hoveredDate = d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
        }
    }
    if (hoveredDate && currentCheckpoints.length) {
        var matching = currentCheckpoints.filter(function (cp) {
            return cp.date === hoveredDate &&
                   visibleCheckpointTypes.has(checkpointToggleKey(cp.type));
        });
        if (matching.length) {
            html += '<div class="chart-tooltip-checkpoints">';
            matching.forEach(function (cp) {
                var dotColor = (checkpointColors[cp.type] || {}).line || '#888';
                // Drive the row's left bar (and a row separator border) from
                // a CSS custom property so per-row styling stays in CSS.
                html += '<div class="chart-tooltip-row chart-tooltip-cp" style="--cp-color:' + dotColor + '">' +
                    '<span class="chart-tooltip-swatch" style="background:' + dotColor + '"></span>' +
                    '<span><strong>' + escapeHtml(cp.title) + '</strong>' +
                    (cp.detail ? '<br><span style="opacity:.75">' + escapeHtml(cp.detail) + '</span>' : '') +
                    '</span>' +
                    '</div>';
            });
            html += '</div>';
        }
    }

    el.innerHTML = html;
    el.style.opacity = '1';

    // Position to whichever side of the crosshair has more room
    var cx = chart.canvas.offsetLeft + tooltip.caretX;
    var cy = chart.canvas.offsetTop  + tooltip.caretY;

    el.style.top = cy + 'px';
    el.style.transform = 'translateY(-50%)';

    if (tooltip.caretX > chart.width / 2) {
        el.style.right = (container.clientWidth - cx + 14) + 'px';
        el.style.left  = 'auto';
    } else {
        el.style.left  = (cx + 14) + 'px';
        el.style.right = 'auto';
    }
}


/* ── Chart options ── */

function getChartOpts(xAxisLabels, gaps) {
    if (gaps === null) {
        gaps = true;
    } else {
        gaps = (gaps === 'true');
    }

    var textColor = readVar('--chartjs-text') || '#000000';
    var gridColor = readVar('--chartjs-grid') || 'rgba(150,150,150,0.06)';

    return {
        responsive: true,
        maintainAspectRatio: true,
        spanGaps: gaps,

        interaction: {
            mode: 'index',
            intersect: false,
        },

        animation: {
            duration: 800,
            easing: 'easeOutQuart',
        },

        elements: {
            line: {
                tension: 0.15,
                borderWidth: 2,
            },
            point: {
                radius: 0,
                hoverRadius: 5,
                hoverBorderWidth: 2,
                hoverBorderColor: 'rgba(255,255,255,0.9)',
                hitRadius: 6,
            },
        },

        plugins: {
            legend: {
                display: false,
            },
            tooltip: {
                enabled: false,
                external: externalTooltipHandler,
                mode: 'index',
                intersect: false,
                callbacks: {
                    title: function (items) {
                        if (!items.length) return '';
                        var d = new Date(items[0].parsed.x);
                        return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
                    },
                    label: function (ctx) {
                        var val = parseFloat(ctx.raw);
                        if (isNaN(val)) return null;
                        return ctx.dataset.label + ': $' + val.toFixed(2);
                    },
                },
            },
        },

        scales: {
            x: {
                type: 'time',
                time: {
                    unit: 'day',
                    stepSize: 7,
                    displayFormats: { day: 'MMM d' },
                },
                grid: {
                    color: gridColor,
                    drawTicks: false,
                },
                ticks: {
                    color: textColor,
                    padding: 8,
                    maxRotation: 45,
                    font: { size: 10 },
                    // Append the year to each tick when the visible range
                    // crosses a calendar-year boundary (e.g. "Jan 5 '26").
                    // For ranges that sit inside a single year, the year
                    // would be redundant on every tick, so we keep the
                    // shorter "MMM d" form.
                    callback: xAxisTickFormatter,
                },
                border: { display: false },
            },
            'x-top': {
                type: 'category',
                position: 'top',
                display: true,
                labels: xAxisLabels,
                reverse: true,
                grid: { display: false },
                ticks: {
                    color: 'transparent',
                    font: { size: 4 },
                },
                border: { display: false },
            },
            y: {
                beginAtZero: true,
                grid: {
                    color: gridColor,
                    drawTicks: false,
                },
                ticks: {
                    color: textColor,
                    padding: 8,
                    font: { size: 10 },
                    callback: function (value) {
                        return '$' + value.toFixed(2);
                    },
                },
                border: { display: false },
                afterDataLimits: function (axis) {
                    axis.max *= 1.1;
                },
            },
        },
    };
}


/* ── Theme helpers ── */

function readVar(name) {
    var el = document.documentElement;
    if (document.body.classList.contains('light-theme') || document.body.classList.contains('dark-theme')) {
        el = document.body;
    }
    return window.getComputedStyle(el).getPropertyValue(name).trim();
}

function renderChartLegend(chart, containerId) {
    var container = document.getElementById(containerId);
    if (!container) return;
    var html = '';
    chart.data.datasets.forEach(function(ds, i) {
        var visible = chart.isDatasetVisible(i);
        var color = ds.borderColor || ds.backgroundColor || '#888';
        html += '<button class="chart-legend-item' + (visible ? '' : ' hidden') + '" data-index="' + i + '" style="border-color:' + color + '">';
        html += '<span class="chart-legend-dot" style="background:' + color + '"></span>';
        html += ds.label;
        html += '</button>';
    });
    container.innerHTML = html;

    container.querySelectorAll('.chart-legend-item').forEach(function(btn) {
        btn.addEventListener('click', function() {
            var idx = parseInt(this.getAttribute('data-index'));
            var visible = chart.isDatasetVisible(idx);
            chart.setDatasetVisibility(idx, !visible);
            chart.update();
            this.classList.toggle('hidden');
        });
    });
}

function rethemeFirstAxes(chart) {
    if (!chart || !chart.config) return;

    var isDark = document.body.classList.contains('dark-theme');
    var grid = isDark ? 'rgba(140,140,140,0.2)' : 'rgba(0,0,0,0.1)';
    var text = isDark ? '#dddddd' : '#000000';

    // Build a plain options overlay — avoids triggering Chart.js
    // reactive proxy setters that cause infinite recursion in Firefox
    var opts = chart.config.options;

    if (opts.plugins && opts.plugins.legend && opts.plugins.legend.labels) {
        opts.plugins.legend.labels.color = text;
    }
    if (opts.scales) {
        if (opts.scales.x) {
            opts.scales.x.ticks.color = text;
            opts.scales.x.grid.color = grid;
        }
        if (opts.scales.y) {
            opts.scales.y.ticks.color = text;
            opts.scales.y.grid.color = grid;
        }
    }

    chart.update('none');
}


/* ── Legend persistence ── */

function withLegendPersistence(legendStorageKey, opts) {
    var defaultClick = Chart.defaults.plugins.legend.onClick;

    opts.plugins.legend.onClick = function (e, legendItem, legend) {
        defaultClick.call(this, e, legendItem, legend);

        var chart = legend.chart;
        var hidden = chart.data.datasets.map(function (_, i) {
            return !chart.isDatasetVisible(i);
        });
        localStorage.setItem(legendStorageKey, JSON.stringify(hidden));
    };

    return opts;
}

/* ── Checkpoint annotations ── */

// Line and label-background colors per checkpoint type. Release labels are
// black with a white icon (the Scryfall set glyphs are monochrome and would
// otherwise render black-on-grey, which disappears).
const checkpointColors = {
    ban:     { line: 'rgba(217, 83, 79, 0.9)',  label: 'rgba(217, 83, 79, 0.9)'  },
    unban:   { line: 'rgba(92, 184, 92, 0.9)',  label: 'rgba(92, 184, 92, 0.9)'  },
    release: { line: 'rgba(108, 117, 125, 0.9)', label: 'rgba(0, 0, 0, 0.9)'    },
    reprint: { line: 'rgba(240, 173, 78, 0.9)', label: 'rgba(240, 173, 78, 0.9)' },
    format:  { line: 'rgba(102, 16, 242, 0.9)', label: 'rgba(102, 16, 242, 0.9)' },
};

// Line z-order priority for same-date overlaps. Higher z draws later, so
// the more important line wins the pixel: red ban > green unban > orange
// reprint > black release. Format isn't called out in the priority but
// sits below release as a soft default.
const checkpointZ = {
    ban: 4,
    unban: 3,
    reprint: 2,
    release: 1,
    format: 0,
};

// Bans + unbans share the "Bans" checkbox; releases + formats share the
// "Releases" checkbox (both are set/format-launch context).
function checkpointToggleKey(type) {
    if (type === 'unban') return 'ban';
    if (type === 'format') return 'release';
    return type;
}

var TICK_MONTH_NAMES = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];

// X-axis tick formatter. `this` is the scale instance. Re-runs on every chart
// update, so changing the date-range dropdown reformats labels automatically.
function xAxisTickFormatter(value) {
    var d = new Date(value);
    var label = TICK_MONTH_NAMES[d.getMonth()] + ' ' + d.getDate();
    if (typeof this.min === 'number' && typeof this.max === 'number') {
        var startYear = new Date(this.min).getFullYear();
        var endYear = new Date(this.max).getFullYear();
        if (startYear !== endYear) {
            label += " '" + String(d.getFullYear()).slice(-2);
        }
    }
    return label;
}

// Returns true when the chart's visible x-axis spans at least `days` days.
// Reads from the laid-out scale, so it works whether the user selected an
// explicit range (x.min set) or "All" (auto-bounded from data).
//
// The +1 makes the range match the dropdown values: "2 Years" sets x.min to
// the label 730 days back, so (max - min) is 729 days of gap but represents
// 730 days of inclusive coverage. Without the +1, the 2-year selection
// would just miss the threshold.
function chartSpansAtLeastDays(chart, days) {
    var xScale = chart && chart.scales && chart.scales.x;
    if (!xScale || typeof xScale.min !== 'number' || typeof xScale.max !== 'number') return false;
    var rangeDays = (xScale.max - xScale.min) / 86400000 + 1;
    return rangeDays >= days;
}

// Note: no 'format' entry — formats share the 'release' toggle via
// checkpointToggleKey, so the visibility set only needs the canonical keys.
const visibleCheckpointTypes = new Set(['ban', 'release', 'reprint']);

// Legacy flag — kept false so the older `if (key === 'release' &&
// releasesSuppressedByRange) continue;` checks elsewhere never trip.
// Release visibility at long ranges is now driven by a separate pref.
var releasesSuppressedByRange = false;

// Long-range release auto-hide: at 5y/10y the release lines are noisy and
// laggy, so we default release markers off. The user can opt back in via
// the Releases checkbox; that choice is stored separately from the short-
// range preference so flipping ranges doesn't clobber either setting.
var RELEASE_LONG_RANGE_DAYS = 1825;
var RELEASES_LONG_RANGE_KEY = 'chartReleasesLongRange';
var currentRangeDays = 0;

function isLongChartRange(rangeDays) {
    return typeof rangeDays === 'number' && rangeDays >= RELEASE_LONG_RANGE_DAYS;
}

function getReleasesLongRangePref() {
    try {
        return localStorage.getItem(RELEASES_LONG_RANGE_KEY) === 'true';
    } catch (e) {
        return false;
    }
}

function setReleasesLongRangePref(on) {
    try {
        localStorage.setItem(RELEASES_LONG_RANGE_KEY, String(on));
    } catch (e) {}
}

function getReleasesShortRangePref() {
    try {
        var raw = localStorage.getItem(CHECKPOINT_TYPES_KEY);
        if (!raw) return true;
        var saved = JSON.parse(raw);
        if (!Array.isArray(saved)) return true;
        return saved.indexOf('release') !== -1;
    } catch (e) {
        return true;
    }
}

// Updates in-memory state and the checkbox DOM only. Callers are responsible
// for triggering a chart redraw — folding the redraw in here would commit any
// pending axis changes (e.g. an x.min set just before this call) without
// animation, killing the transition on range changes that also flip release
// visibility.
function setReleasesSuppressedByRange(rangeDays) {
    currentRangeDays = rangeDays;
    var longRange = isLongChartRange(rangeDays);
    var shouldShow = longRange ? getReleasesLongRangePref() : getReleasesShortRangePref();

    if (shouldShow) visibleCheckpointTypes.add('release');
    else visibleCheckpointTypes.delete('release');

    var el = document.getElementById('cpToggleRelease');
    if (el) el.checked = shouldShow;
}

// Snapshot of the checkpoints currently rendered on the chart. Used by the
// external tooltip handler so price + event context render in one popup.
var currentCheckpoints = [];

// Cluster threshold for vertical stacking — checkpoints whose pixel
// positions fall within this many px of each other stack vertically.
// The full label box is KEYRUNE_CANVAS_SIZE (22) + 2 * label padding (1) =
// 24, so anything under 24 lets adjacent icons touch or slightly overlap.
// Keyrune glyphs leave transparent margin inside the canvas, so a few
// pixels of canvas overlap reads as zero visible overlap. We pick 14 to
// keep more reprints on row 0 next to nearby releases instead of dropping
// them to row 1 every time they sit within a label-box of each other.
var CHECKPOINT_CLUSTER_PX = 14;
var checkpointYLayoutCache = { signature: null, clusters: {} };

function getCheckpointYRow(chart, idx) {
    var xScale = chart && chart.scales && chart.scales.x;
    if (!xScale) return 0;
    // Visibility is part of the signature: when the user toggles a type
    // off, hidden icons drop out of the row-assignment sweep entirely, so
    // remaining icons may move from bottom to top.
    var visKey = Array.from(visibleCheckpointTypes).sort().join(',');
    var sig = xScale.min + '|' + xScale.max + '|' + (xScale.width || 0) + '|' + visKey;
    if (checkpointYLayoutCache.signature !== sig) {
        checkpointYLayoutCache.signature = sig;
        checkpointYLayoutCache.clusters = computeCheckpointYLayout(xScale);
    }
    var row = checkpointYLayoutCache.clusters[idx];
    return typeof row === 'number' ? row : 0;
}

function computeCheckpointYLayout(xScale) {
    // Two-pass priority placement. Reprints are demoted relative to
    // releases/bans/formats so they don't push the main events to the
    // bottom row when they happen to sit slightly left of one.
    //
    // Pass 1: non-reprints in px order — each goes top unless it would
    // overlap an already-placed top item, in which case it goes bottom.
    // Pass 2: reprints — same rule, but they check against the full
    // top-row set populated by pass 1 (and by earlier pass-2 reprints).
    var items = [];
    for (var i = 0; i < currentCheckpoints.length; i++) {
        var cp = currentCheckpoints[i];
        if (!cp || !cp.date) continue;
        var key = checkpointToggleKey(cp.type);
        if (key === 'release' && releasesSuppressedByRange) continue;
        if (!visibleCheckpointTypes.has(key)) continue;
        var px = xScale.getPixelForValue(new Date(cp.date).getTime());
        if (!isFinite(px)) continue;
        items.push({ idx: i, px: px, type: cp.type });
    }
    items.sort(function (a, b) {
        var pa = a.type === 'reprint' ? 1 : 0;
        var pb = b.type === 'reprint' ? 1 : 0;
        if (pa !== pb) return pa - pb;
        return a.px - b.px;
    });

    var rows = {};
    // Tried in order: row 0 first (above plot), then row 1, 2, 3, 4 going
    // progressively deeper into the plot. Rows 3 and 4 are spillover and
    // typically only used at very dense zoom levels.
    var ROW_COUNT = 5;
    var rowPxs = [];
    for (var rInit = 0; rInit < ROW_COUNT; rInit++) rowPxs.push([]);
    function minDist(pxs, px) {
        var min = Infinity;
        for (var k = 0; k < pxs.length; k++) {
            var d = Math.abs(pxs[k] - px);
            if (d < min) min = d;
        }
        return min;
    }
    for (var j = 0; j < items.length; j++) {
        var it = items[j];
        var dists = [];
        for (var rDist = 0; rDist < ROW_COUNT; rDist++) {
            dists.push(minDist(rowPxs[rDist], it.px));
        }
        var chosen = -1;
        // First clear row wins.
        for (var r = 0; r < ROW_COUNT; r++) {
            if (dists[r] >= CHECKPOINT_CLUSTER_PX) { chosen = r; break; }
        }
        // All rows blocked — fall back to whichever has the most
        // clearance so the inevitable overlap is minimised.
        if (chosen < 0) {
            var bestDist = -Infinity;
            for (var r2 = 0; r2 < ROW_COUNT; r2++) {
                if (dists[r2] > bestDist) { bestDist = dists[r2]; chosen = r2; }
            }
        }
        rows[it.idx] = chosen;
        rowPxs[chosen].push(it.px);
    }
    return rows;
}

// When the user hovers a checkpoint icon, snap the tooltip/crosshair to the
// closest data-point index for that date. The existing crosshair plugin reads
// from chart.tooltip's active elements, so once those are set the vertical
// line and price tooltip appear at the picked date automatically.
function activateCheckpointDate(chart, dateStr) {
    if (!chart || !chart.data || !chart.data.labels || !chart.tooltip) return;
    var labels = chart.data.labels;
    if (labels.length === 0) return;

    var target = new Date(dateStr).getTime();
    if (!isFinite(target)) return;

    var closestIdx = 0;
    var minDist = Math.abs(new Date(labels[0]).getTime() - target);
    for (var k = 1; k < labels.length; k++) {
        var d = Math.abs(new Date(labels[k]).getTime() - target);
        if (d < minDist) { minDist = d; closestIdx = k; }
    }

    var elements = [];
    chart.data.datasets.forEach(function (_, dsIdx) {
        if (chart.isDatasetVisible(dsIdx)) {
            elements.push({ datasetIndex: dsIdx, index: closestIdx });
        }
    });
    if (elements.length === 0) return;

    var xScale = chart.scales && chart.scales.x;
    var area = chart.chartArea;
    var caretX = xScale ? xScale.getPixelForValue(target) : (area ? (area.left + area.right) / 2 : 0);
    var caretY = area ? (area.top + area.bottom) / 2 : 0;
    chart.tooltip.setActiveElements(elements, { x: caretX, y: caretY });
    chart.setActiveElements(elements);
    chart.update('none');
}

function clearCheckpointActivation(chart) {
    if (!chart || !chart.tooltip) return;
    chart.tooltip.setActiveElements([], { x: 0, y: 0 });
    chart.setActiveElements([]);
    chart.update('none');
}

function isCheckpointDarkMode() {
    return document.body && document.body.classList.contains('dark-theme');
}

// Cache <img> loads and the colorized canvases we generate from them. The
// raw image is shared across themes (one fetch per URL), but each color
// variant gets its own canvas under a separate key.
//
// Canvas dimension matches KEYRUNE_CANVAS_SIZE and the actual draw size
// matches KEYRUNE_FONT_PX (declared later in the file), so hammer/unlock
// icons render at the same visible size as the keyrune glyphs (centered
// in the same-sized box). Kept as numeric literals here to dodge the TDZ
// since this `const` is declared before the keyrune ones.
const CHECKPOINT_ICON_SIZE = 22;
const CHECKPOINT_ICON_GLYPH_PX = 18;
const CHECKPOINT_ICON_INSET = (CHECKPOINT_ICON_SIZE - CHECKPOINT_ICON_GLYPH_PX) / 2;
const checkpointIconRawCache = new Map();   // url -> Image
const checkpointIconCanvasCache = new Map(); // url|color -> canvas

// HiDPI: chart.js's main canvas is allocated at device pixels (cssW * DPR)
// with the context scaled by DPR. When the annotation plugin draws our
// source canvas, it uses our canvas.width as the source bitmap size and
// the label's `width`/`height` as the CSS destination size. So we allocate
// the source canvas at SIZE * DPR pixels and pin the label box to SIZE in
// CSS — that gives a 1:1 source-to-device-pixel mapping and a sharp icon.
function getDevicePixelRatio() {
    return (typeof window !== 'undefined' && window.devicePixelRatio) || 1;
}

function getCheckpointIcon(url, glyphColor, onLoad) {
    var key = url + '|' + glyphColor;
    if (checkpointIconCanvasCache.has(key)) return checkpointIconCanvasCache.get(key);

    var dpr = getDevicePixelRatio();
    var canvas = document.createElement('canvas');
    canvas.width = CHECKPOINT_ICON_SIZE * dpr;
    canvas.height = CHECKPOINT_ICON_SIZE * dpr;
    checkpointIconCanvasCache.set(key, canvas);

    function paint(img) {
        var ctx = canvas.getContext('2d');
        // setTransform (not scale) so repeat paints don't compound the
        // DPR factor on the same context.
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, CHECKPOINT_ICON_SIZE, CHECKPOINT_ICON_SIZE);
        ctx.drawImage(img, CHECKPOINT_ICON_INSET, CHECKPOINT_ICON_INSET, CHECKPOINT_ICON_GLYPH_PX, CHECKPOINT_ICON_GLYPH_PX);
        // Replace the image's color with glyphColor, preserving its alpha
        // mask. source-in keeps only the parts that overlap existing pixels.
        ctx.globalCompositeOperation = 'source-in';
        ctx.fillStyle = glyphColor;
        ctx.fillRect(0, 0, CHECKPOINT_ICON_SIZE, CHECKPOINT_ICON_SIZE);
        ctx.globalCompositeOperation = 'source-over';
    }

    var img = checkpointIconRawCache.get(url);
    if (img && img.complete && img.naturalWidth > 0) {
        paint(img);
        return canvas;
    }
    if (!img) {
        img = new Image();
        img.referrerPolicy = 'no-referrer';
        img.src = url;
        checkpointIconRawCache.set(url, img);
    }
    img.addEventListener('load', function () {
        paint(img);
        if (typeof onLoad === 'function') onLoad();
    });
    img.addEventListener('error', function () {
        checkpointIconRawCache.delete(url);
        checkpointIconCanvasCache.delete(key);
    });
    return canvas;
}

// Keyrune glyphs vary in intrinsic width/height (some sets have a tall skinny
// icon, others wide squat ones). If we hand the raw character to the
// annotation plugin it auto-sizes the label box to whatever the glyph
// measures, so the colored circles around different icons end up noticeably
// different sizes. Render each glyph centered into a fixed-size off-screen
// canvas instead — the plugin sizes the label box from canvas.width /
// canvas.height, so every label box (and therefore every circle) is uniform.
const KEYRUNE_CANVAS_SIZE = 22;
const KEYRUNE_FONT_PX = 18;
const keyruneCanvasCache = new Map();
function getKeyruneCanvas(code, glyphColor) {
    if (!code) return null;
    var key = code + '|' + glyphColor;
    if (keyruneCanvasCache.has(key)) return keyruneCanvasCache.get(key);

    var ch = getKeyruneChar(code);
    if (!ch) return null;

    var dpr = getDevicePixelRatio();
    var canvas = document.createElement('canvas');
    canvas.width = KEYRUNE_CANVAS_SIZE * dpr;
    canvas.height = KEYRUNE_CANVAS_SIZE * dpr;
    var ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    ctx.font = KEYRUNE_FONT_PX + 'px Keyrune';
    ctx.fillStyle = glyphColor;
    // Bottom-align each glyph in its canvas so the row sits on a common
    // floor. Keyrune icons vary in how they sit inside the em-box; the
    // 'middle' textBaseline centers each on its own middle, which lets
    // them drift up and down across the row. Aligning bottoms (using
    // each glyph's actualBoundingBoxDescent) gives a consistent baseline.
    // X stays centered on the glyph's *visible* horizontal box.
    ctx.textAlign = 'center';
    ctx.textBaseline = 'alphabetic';
    var m = ctx.measureText(ch);
    var descent = m.actualBoundingBoxDescent || 0;
    var leftExt = m.actualBoundingBoxLeft || 0;
    var rightExt = m.actualBoundingBoxRight || 0;
    var drawX = KEYRUNE_CANVAS_SIZE / 2 + (leftExt - rightExt) / 2;
    var drawY = KEYRUNE_CANVAS_SIZE - descent;
    ctx.fillText(ch, drawX, drawY);

    keyruneCanvasCache.set(key, canvas);
    return canvas;
}

// Resolve a Keyrune CSS class ("ss-dsk") to its rendered glyph character. The
// Keyrune stylesheet is already loaded on the search page (see
// templates/search.html "extra-css"). We read the ::before content of a hidden
// element to extract the codepoint, then drop the element. The character is
// drawn into an off-screen canvas via `font: '... Keyrune'`.
const keyruneCharCache = new Map();
function getKeyruneChar(code) {
    if (!code) return '';
    if (keyruneCharCache.has(code)) return keyruneCharCache.get(code);

    var el = document.createElement('i');
    el.className = 'ss ss-' + code;
    el.style.position = 'absolute';
    el.style.left = '-9999px';
    el.style.visibility = 'hidden';
    document.body.appendChild(el);
    var content = window.getComputedStyle(el, '::before').content || '';
    document.body.removeChild(el);

    // Computed content is wrapped in quotes (and may be escaped as
    // "\eXXX"). Strip the wrapper; the codepoint itself renders fine
    // through the Keyrune font.
    content = content.replace(/^['"](.*)['"]$/, '$1');
    if (content === 'none') content = '';
    keyruneCharCache.set(code, content);
    return content;
}

function buildCheckpointAnnotations(checkpoints, chartRef, opts) {
    currentCheckpoints = Array.isArray(checkpoints) ? checkpoints : [];
    // New dataset → previous layout cache is stale.
    checkpointYLayoutCache = { signature: null, clusters: {} };
    var annotations = {};
    if (currentCheckpoints.length === 0) return annotations;

    var redraw = function () {
        // Once an icon finishes loading, ask the chart to redraw so it
        // appears without requiring user interaction.
        var c = chartRef && chartRef.chart;
        if (c) c.update('none');
    };

    // Force the Keyrune webfont binary to load. The CSS @font-face is
    // declared in keyrune.css, but browsers defer the fetch until something
    // visibly uses the font. Without this nudge, Chart.js draws the glyph's
    // codepoint with a fallback font (no matching glyph → tofu) and we end up
    // showing the set name as a text fallback.
    var anyKeyrune = checkpoints.some(function (cp) { return cp.keyruneCode; });
    if (anyKeyrune && document.fonts && document.fonts.load) {
        document.fonts.load(KEYRUNE_FONT_PX + 'px Keyrune').then(function () {
            keyruneCharCache.clear();
            keyruneCanvasCache.clear();
            redraw();
        }).catch(function () {});
    }

    // Group same-date checkpoints so we can stack them. Stack position is
    // computed at draw time (not build time) — when the user toggles a type
    // off, the remaining visible labels reflow back to the top of the chart
    // instead of leaving holes where hidden items used to sit.
    var sameDateGroups = {};
    checkpoints.forEach(function (cp, i) {
        if (!sameDateGroups[cp.date]) sameDateGroups[cp.date] = [];
        sameDateGroups[cp.date].push(i);
    });
    // Step between stacked same-date badges. The label box is the icon canvas
    // (max 22px for keyrunes, 20px for iconUrl) plus 4px padding on each side,
    // Padding matches the label config below (1px). Step is below the font
    // size, so the visible glyphs slightly overlap each other — keyrune icons
    // are mostly symmetric/centered, so a 2-3px overlap still reads cleanly.
    var LABEL_PADDING_PX = 1;
    var LABEL_HALF_PX = KEYRUNE_CANVAS_SIZE / 2 + LABEL_PADDING_PX;
    var STACK_STEP_PX = KEYRUNE_FONT_PX - 6;

    // Reserve a band above the plot for the single above-plot row. Only one
    // step up is ever used, so ABOVE_CAPACITY = 2 is enough.
    var ABOVE_CAPACITY = 2;
    var topPad = 2 * LABEL_HALF_PX + (ABOVE_CAPACITY - 1) * STACK_STEP_PX + 4;
    if (opts) {
        opts.layout = opts.layout || {};
        var pad = opts.layout.padding;
        if (pad == null) {
            opts.layout.padding = { top: topPad };
        } else if (typeof pad === 'number') {
            opts.layout.padding = { top: Math.max(pad, topPad), right: pad, bottom: pad, left: pad };
        } else {
            pad.top = Math.max(pad.top || 0, topPad);
        }
    }

    checkpoints.forEach(function (cp, i) {
        var palette = checkpointColors[cp.type] || { line: 'rgba(120,120,120,0.9)', label: 'rgba(120,120,120,0.9)' };

        // Stack position within the horizontal cluster (checkpoints whose
        // pixel positions fall within CHECKPOINT_CLUSTER_PX of each other).
        // At wide zoom levels, dates a few days apart still collapse to the
        // same x-cluster and stack vertically instead of overlapping. Hidden
        // siblings collapse their slot so the stack reflows to the top.
        // Falls back to the build-time same-date group on first draw before
        // the chart's x-scale is laid out.
        //
        // Five-row placement: row 0 sits one step above the plot, rows
        // 1–4 step progressively deeper into the plot (each 2 *
        // STACK_STEP_PX below the previous). Rows 3 and 4 are spillover
        // used only when the upper rows are all blocked. The placement
        // sweep runs at draw time so it adapts to zoom and visibility.
        var yAdjustFn = function (ctx) {
            var row = getCheckpointYRow(ctx && ctx.chart, i);
            var dirs = [-1, 1, 3, 5, 7];
            return -LABEL_HALF_PX + dirs[row] * STACK_STEP_PX;
        };

        // Scriptable so each draw re-evaluates: the first draw may fire
        // before the Keyrune font is ready; subsequent draws (after font
        // load triggers redraw above) pick up the real glyph character.
        //
        // The glyph itself carries the type's color (release = monochrome
        // theme-text, reprint = orange, ban = red, unban = green). Release
        // is the only monochrome type, so it flips between black and white
        // to stay legible against the chart background.
        var glyphColorFn = function () {
            if (cp.type === 'release') {
                return isCheckpointDarkMode() ? '#ffffff' : '#000000';
            }
            return palette.label;
        };
        var contentFn = function () {
            var glyphColor = glyphColorFn();
            if (cp.keyruneCode) {
                var canvas = getKeyruneCanvas(cp.keyruneCode, glyphColor);
                if (canvas) return canvas;
            }
            if (cp.iconUrl) return getCheckpointIcon(cp.iconUrl, glyphColor, redraw);
            // Short text label (format name, etc.). The annotation plugin
            // renders strings inline using the label font, so the badge sizes
            // to fit the text rather than to the uniform icon canvas.
            if (cp.iconText) return cp.iconText;
            return cp.title;
        };
        // Font only affects the text-fallback path now — canvas content is
        // pre-rendered and the plugin ignores the font option for it.
        var fontFn = function () {
            return { size: 10, weight: 'bold' };
        };

        annotations['cp_' + i] = {
            type: 'line',
            xMin: cp.date,
            xMax: cp.date,
            xScaleID: 'x',
            // z controls draw order within the same drawTime: when two
            // lines share a date the higher-z line paints last and wins
            // the pixel. See checkpointZ for the type priority.
            z: checkpointZ[cp.type] || 0,
            borderColor: palette.line,
            // Release lines get noisy at multi-year zooms — drop the dashed
            // line once the visible range exceeds 2 years (i.e. 5y/10y),
            // keeping only the keyrune icon at the top. Bans/unbans/
            // reprints/formats stay dashed regardless.
            borderWidth: function (ctx) {
                if (cp.type !== 'release') return 1.5;
                return chartSpansAtLeastDays(ctx.chart, 731) ? 0 : 1.5;
            },
            borderDash: [4, 4],
            display: function (ctx) {
                var key = checkpointToggleKey(cp.type);
                if (key === 'release' && releasesSuppressedByRange) return false;
                if (!visibleCheckpointTypes.has(key)) return false;
                // clip: false (set so badges can spill above the plot) also
                // disables left/right clipping, so out-of-range lines leak
                // into the axis margin. Filter them out by date here.
                var xScale = ctx.chart && ctx.chart.scales && ctx.chart.scales.x;
                if (xScale && typeof xScale.min === 'number' && typeof xScale.max === 'number') {
                    var t = new Date(cp.date).getTime();
                    if (t < xScale.min || t > xScale.max) return false;
                }
                return true;
            },
            label: {
                display: true,
                // Render labels in a later draw phase than the lines so every
                // line is painted first and the opaque labels cover the line
                // segments behind them. This is what prevents lines from
                // visually crossing through icons of same-date siblings.
                drawTime: 'afterDraw',
                content: contentFn,
                position: 'end',
                // No bubble — the glyph itself carries the type color. The
                // `color` field only affects the iconText/title text-fallback
                // path, which we keep tinted to match.
                backgroundColor: 'transparent',
                color: glyphColorFn,
                borderRadius: 0,
                padding: 1,
                font: fontFn,
                yAdjust: yAdjustFn,
                xAdjust: 0,
                // Pin the label box to CSS pixels. The source canvases are
                // allocated at SIZE * DPR pixels for sharpness on HiDPI
                // displays; without these overrides the plugin would draw
                // the icon at SIZE * DPR CSS pixels (i.e. too big).
                width: KEYRUNE_CANVAS_SIZE,
                height: KEYRUNE_CANVAS_SIZE,
            },
            enter: function (ctx) {
                var chart = ctx.chart;
                chart.canvas.style.cursor = cp.url ? 'pointer' : 'default';
                activateCheckpointDate(chart, cp.date);
                return true;
            },
            leave: function (ctx) {
                var chart = ctx.chart;
                chart.canvas.style.cursor = 'default';
                clearCheckpointActivation(chart);
                return true;
            },
            click: function () {
                if (cp.url) window.open(cp.url, '_blank', 'noopener');
            },
        };
    });

    return annotations;
}


// Coalesce rapid toggles into a single update per frame. Without this, rapid
// clicks racing with Chart.js's responsive ResizeObserver can compound layout
// changes and grow the canvas continuously until the next idle moment.
var pendingCheckpointUpdate = false;
function toggleCheckpointType(type, on) {
    if (on) visibleCheckpointTypes.add(type);
    else visibleCheckpointTypes.delete(type);
    if (type === 'release' && isLongChartRange(currentRangeDays)) {
        // Long-range release toggle stores the user's override separately
        // from the short-range preference, so navigating ranges respects
        // both choices independently.
        setReleasesLongRangePref(on);
    } else {
        persistCheckpointTypes();
    }
    if (pendingCheckpointUpdate) return;
    pendingCheckpointUpdate = true;
    requestAnimationFrame(function () {
        pendingCheckpointUpdate = false;
        if (window.cardChart) window.cardChart.update('none');
    });
}

var CHECKPOINT_TYPES_KEY = 'chartCheckpointTypes';

function persistCheckpointTypes() {
    try {
        var savedSet = new Set(visibleCheckpointTypes);
        // At long range, the live `release` membership is the auto-hide
        // state, not the user's short-range preference. Re-apply the saved
        // short-range value so toggling ban/reprint at long range doesn't
        // clobber what the user picked for short-range views.
        if (isLongChartRange(currentRangeDays)) {
            if (getReleasesShortRangePref()) savedSet.add('release');
            else savedSet.delete('release');
        }
        localStorage.setItem(
            CHECKPOINT_TYPES_KEY,
            JSON.stringify(Array.from(savedSet))
        );
    } catch (e) { /* localStorage unavailable; non-fatal */ }
}

// Restore previously-saved checkbox state and apply it to both the in-memory
// set and the rendered DOM checkboxes. Safe to call before the chart exists
// or on pages without the toggle UI. Call before buildCheckpointAnnotations so
// the first draw reflects the saved state.
function restoreCheckpointTypes() {
    var raw;
    try { raw = localStorage.getItem(CHECKPOINT_TYPES_KEY); }
    catch (e) { return; }
    if (!raw) return;

    var saved;
    try { saved = JSON.parse(raw); }
    catch (e) { return; }
    if (!Array.isArray(saved)) return;

    visibleCheckpointTypes.clear();
    saved.forEach(function (t) { visibleCheckpointTypes.add(t); });

    [['ban', 'cpToggleBan'], ['release', 'cpToggleRelease'], ['reprint', 'cpToggleReprint']]
        .forEach(function (pair) {
            var el = document.getElementById(pair[1]);
            if (el) el.checked = visibleCheckpointTypes.has(pair[0]);
        });
}


function applySavedLegendState(chart, storageKey) {
    var raw = localStorage.getItem(storageKey);
    if (!raw) return;

    try {
        var hidden = JSON.parse(raw);
        hidden.forEach(function (isHidden, i) {
            if (!chart.data.datasets[i]) return;
            chart.data.datasets[i].hidden = !!isHidden;
        });
        chart.update();
    } catch (e) {
        console.error('Failed to parse legend state:', e);
        localStorage.removeItem(storageKey);
    }
}