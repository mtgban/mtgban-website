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

// When the selected date range is wide enough that release markers crowd
// every pixel, the Releases checkbox is force-disabled. We track that as a
// separate flag so the user's saved on/off preference survives a temporary
// range change — flipping back to a shorter range restores their choice.
const RELEASE_SUPPRESS_MIN_DAYS = 1825;
var releasesSuppressedByRange = false;

function setReleasesSuppressedByRange(rangeDays) {
    var suppressed = typeof rangeDays === 'number' && rangeDays >= RELEASE_SUPPRESS_MIN_DAYS;
    if (releasesSuppressedByRange === suppressed) return;
    releasesSuppressedByRange = suppressed;
    var el = document.getElementById('cpToggleRelease');
    if (el) {
        el.disabled = suppressed;
        var pill = el.closest('.cp-pill');
        if (pill) pill.classList.toggle('cp-pill-locked', suppressed);
    }
    if (window.cardChart) window.cardChart.update('none');
}

// Snapshot of the checkpoints currently rendered on the chart. Used by the
// external tooltip handler so price + event context render in one popup.
var currentCheckpoints = [];

// Layout cache for the per-badge xAdjust sweep. Badges on different but close
// dates collide visually because each label is ~30px wide; the sweep nudges
// the earlier badge leftward until adjacent badges are at least one badge-step
// apart. Pushing left (rather than right) anchors the most recent badge at its
// true date, which is usually what the user is looking at. Cached per x-scale
// signature so we don't redo the sort + sweep per annotation on every draw.
var CHECKPOINT_BADGE_WIDTH_PX = 32; // matches STACK_STEP_PX
var checkpointXLayoutCache = { signature: null, offsets: {} };

function getCheckpointXAdjust(chart, idx) {
    var xScale = chart && chart.scales && chart.scales.x;
    if (!xScale) return 0;
    var sig = xScale.min + '|' + xScale.max + '|' + (xScale.width || 0);
    if (checkpointXLayoutCache.signature !== sig) {
        checkpointXLayoutCache.signature = sig;
        checkpointXLayoutCache.offsets = computeCheckpointXLayout(xScale);
    }
    return checkpointXLayoutCache.offsets[idx] || 0;
}

function computeCheckpointXLayout(xScale) {
    // Group by date — same-date stacks share an xAdjust because they're laid
    // out vertically by yAdjust, not horizontally.
    var groups = {};
    var dateKeys = [];
    for (var i = 0; i < currentCheckpoints.length; i++) {
        var cp = currentCheckpoints[i];
        if (!cp || !cp.date) continue;
        var key = cp.date;
        if (!groups[key]) {
            var px = xScale.getPixelForValue(new Date(cp.date).getTime());
            if (!isFinite(px)) continue;
            groups[key] = { px: px, idxs: [] };
            dateKeys.push(key);
        }
        groups[key].idxs.push(i);
    }
    dateKeys.sort(function (a, b) { return groups[a].px - groups[b].px; });

    var offsets = {};
    var nextPx = Infinity;
    for (var j = dateKeys.length - 1; j >= 0; j--) {
        var g = groups[dateKeys[j]];
        var adjusted = Math.min(g.px, nextPx - CHECKPOINT_BADGE_WIDTH_PX);
        var shift = adjusted - g.px;
        for (var k = 0; k < g.idxs.length; k++) {
            offsets[g.idxs[k]] = shift;
        }
        nextPx = adjusted;
    }
    return offsets;
}

function isCheckpointDarkMode() {
    return document.body && document.body.classList.contains('dark-theme');
}

// Cache <img> loads and the colorized canvases we generate from them. The
// raw image is shared across themes (one fetch per URL), but each color
// variant gets its own canvas under a separate key.
const CHECKPOINT_ICON_SIZE = 20;
const checkpointIconRawCache = new Map();   // url -> Image
const checkpointIconCanvasCache = new Map(); // url|color -> canvas

function getCheckpointIcon(url, glyphColor, onLoad) {
    var key = url + '|' + glyphColor;
    if (checkpointIconCanvasCache.has(key)) return checkpointIconCanvasCache.get(key);

    var canvas = document.createElement('canvas');
    canvas.width = CHECKPOINT_ICON_SIZE;
    canvas.height = CHECKPOINT_ICON_SIZE;
    checkpointIconCanvasCache.set(key, canvas);

    function paint(img) {
        var ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, CHECKPOINT_ICON_SIZE, CHECKPOINT_ICON_SIZE);
        ctx.drawImage(img, 0, 0, CHECKPOINT_ICON_SIZE, CHECKPOINT_ICON_SIZE);
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

    var canvas = document.createElement('canvas');
    canvas.width = KEYRUNE_CANVAS_SIZE;
    canvas.height = KEYRUNE_CANVAS_SIZE;
    var ctx = canvas.getContext('2d');
    ctx.font = KEYRUNE_FONT_PX + 'px Keyrune';
    ctx.fillStyle = glyphColor;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(ch, KEYRUNE_CANVAS_SIZE / 2, KEYRUNE_CANVAS_SIZE / 2);

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
    // New dataset → previous xAdjust offsets are stale.
    checkpointXLayoutCache = { signature: null, offsets: {} };
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
    // so the largest box is 30px tall. Step is 2px wider so adjacent circles
    // have a small gap rather than touching.
    var LABEL_PADDING_PX = 4;
    var LABEL_HALF_PX = KEYRUNE_CANVAS_SIZE / 2 + LABEL_PADDING_PX;  // 15
    var STACK_STEP_PX = KEYRUNE_CANVAS_SIZE + 2 * LABEL_PADDING_PX + 2;

    // Reserve a band above the plot for ABOVE_CAPACITY badges. Anything
    // beyond that stacks downward into the chart, keeping a constant step so
    // the visual spacing stays uniform when the stack crosses the plot edge.
    // The reference is the lowest above-plot slot: its bottom edge sits flush
    // with the plot top, then each step up adds STACK_STEP_PX.
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

        // Stack position within the same-date group, counting only currently
        // visible siblings that appear before this one in the list. Hiding a
        // type via its checkbox (or range-suppressing releases) collapses the
        // empty slot. Slot (ABOVE_CAPACITY - 1) sits flush with the plot top;
        // earlier slots stack upward into the reserved band, later slots
        // continue downward into the chart, all with the same step.
        var yAdjustFn = function () {
            var group = sameDateGroups[cp.date] || [i];
            var visibleSlot = 0;
            for (var j = 0; j < group.length; j++) {
                if (group[j] === i) break;
                var prev = checkpoints[group[j]];
                var prevKey = checkpointToggleKey(prev.type);
                if (prevKey === 'release' && releasesSuppressedByRange) continue;
                if (visibleCheckpointTypes.has(prevKey)) {
                    visibleSlot++;
                }
            }
            return -LABEL_HALF_PX + (visibleSlot - (ABOVE_CAPACITY - 1)) * STACK_STEP_PX;
        };

        // Scriptable so each draw re-evaluates: the first draw may fire
        // before the Keyrune font is ready; subsequent draws (after font
        // load triggers redraw above) pick up the real glyph character.
        //
        // Release markers use a black-circle/white-glyph palette in light
        // mode; in dark mode that flips to a white circle with the glyph
        // drawn in the (black) palette color so the badge stays visible
        // against the dark chart background. Bans/unbans/reprints already
        // use vivid palette colors that read fine in either theme, so we
        // leave their white glyph alone.
        var shouldInvert = function () {
            return cp.type === 'release' && isCheckpointDarkMode();
        };
        var contentFn = function () {
            var glyphColor = shouldInvert() ? palette.label : '#ffffff';
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
            borderColor: palette.line,
            // Release markers are noisy when the chart spans years — there
            // can be dozens of set-release lines crowding the canvas. At 2+
            // years of visible range we drop the dashed line for releases and
            // keep only the keyrune label at the top. Bans/unbans/reprints
            // stay dashed regardless since they're per-card and far sparser.
            borderWidth: function (ctx) {
                if (cp.type !== 'release') return 1.5;
                return chartSpansAtLeastDays(ctx.chart, 730) ? 0 : 1.5;
            },
            borderDash: [4, 4],
            display: function () {
                var key = checkpointToggleKey(cp.type);
                if (key === 'release' && releasesSuppressedByRange) return false;
                return visibleCheckpointTypes.has(key);
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
                // Releases invert in dark mode (see shouldInvert above);
                // every other type keeps its original palette in both themes.
                backgroundColor: function () {
                    return shouldInvert() ? '#ffffff' : palette.label;
                },
                color: function () {
                    return shouldInvert() ? palette.label : '#ffffff';
                },
                borderRadius: 12,
                padding: 4,
                font: fontFn,
                yAdjust: yAdjustFn,
                xAdjust: function (ctx) {
                    return getCheckpointXAdjust(ctx.chart, i);
                },
            },
            enter: function (ctx) {
                ctx.chart.canvas.style.cursor = cp.url ? 'pointer' : 'default';
                return true;
            },
            leave: function (ctx) {
                ctx.chart.canvas.style.cursor = 'default';
                return true;
            },
            click: function () {
                if (cp.url) window.open(cp.url, '_blank', 'noopener');
            },
        };
    });

    return annotations;
}

function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
        return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c];
    });
}

// Coalesce rapid toggles into a single update per frame. Without this, rapid
// clicks racing with Chart.js's responsive ResizeObserver can compound layout
// changes and grow the canvas continuously until the next idle moment.
var pendingCheckpointUpdate = false;
function toggleCheckpointType(type, on) {
    if (on) visibleCheckpointTypes.add(type);
    else visibleCheckpointTypes.delete(type);
    persistCheckpointTypes();
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
        localStorage.setItem(
            CHECKPOINT_TYPES_KEY,
            JSON.stringify(Array.from(visibleCheckpointTypes))
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