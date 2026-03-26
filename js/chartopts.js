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
                position: 'top',
                align: 'center',
                labels: {
                    color: textColor,
                    usePointStyle: true,
                    pointStyle: 'circle',
                    padding: 16,
                    font: { size: 11 },
                },
                onHover: function (e) { e.native.target.style.cursor = 'pointer'; },
                onLeave: function (e) { e.native.target.style.cursor = 'default'; },
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

function rethemeFirstAxes(chart) {
    if (!chart || !chart.options) return;

    var grid = readVar('--chartjs-grid');
    var text = readVar('--chartjs-text') || '#000000';

    // Legend text
    var legend = chart.options.plugins && chart.options.plugins.legend;
    if (legend && legend.labels) {
        legend.labels.color = text;
    }

    // X axis
    var xScale = chart.options.scales && chart.options.scales.x;
    if (xScale) {
        xScale.ticks = xScale.ticks || {};
        xScale.ticks.color = text;
        xScale.grid  = xScale.grid  || {};
        xScale.grid.color = grid;
    }

    // Y axis
    var yScale = chart.options.scales && chart.options.scales.y;
    if (yScale) {
        yScale.ticks = yScale.ticks || {};
        yScale.ticks.color = text;
        yScale.grid  = yScale.grid  || {};
        yScale.grid.color = grid;
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