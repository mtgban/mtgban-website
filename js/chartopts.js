// Custom chart type which copies the "line" one and draws
// an extra vertical line on hover
Chart.defaults.banWithLine = Chart.defaults.line;
Chart.controllers.banWithLine = Chart.controllers.line.extend({
    draw: function(ease) {
        Chart.controllers.line.prototype.draw.call(this, ease);

        if (this.chart.tooltip._active && this.chart.tooltip._active.length) {
            var activePoint = this.chart.tooltip._active[0];
            var ctx = this.chart.ctx;
            var x = activePoint.tooltipPosition().x;
            var topY = this.chart.legend.bottom;
            var bottomY = this.chart.chartArea.bottom;

            // Draw vertical line
            ctx.save();
            ctx.beginPath();
            ctx.moveTo(x, topY);
            ctx.lineTo(x, bottomY);
            ctx.lineWidth = 2;
            ctx.strokeStyle = '#92929242';
            ctx.stroke();
            ctx.restore();
        }
    }
});

// Custom positioner to draw the tooltip on the bottom or top if it covers anything
Chart.Tooltip.positioners.bottom = function(elements, position) {
    if (!elements.length) {
        return false;
    }
    var pos = this._chart.chartArea.bottom;
    var topPos = this._chart.chartArea.top;

    // The very first hover event might not have drawn the tooltip yet so make up
    // some height value using the default font size plus some margin
    var tooltipHeight = elements.length * 12 + 26;
    if (this._chart.tooltip._view) {
        tooltipHeight = this._chart.tooltip._view.height + this._chart.tooltip._view.footerMarginTop;
    }

    elements.forEach(function(element) {
        if (element._view.y > pos - tooltipHeight) {
            pos = topPos + tooltipHeight * 2 / 3;
        }
    });

    return {
        x: elements[0]._view.x,
        y: pos,
    }
};

function getChartOpts(xAxisLabels, gaps) {
    if (gaps === null) {
        gaps = true;
    } else {
        gaps = (gaps === "true");
    }
    return {
        responsive: true,
        // Controls the gaps in the graph when data is missing
        spanGaps: gaps,
        legend: {
            position: "top",
            align: "center",
            onHover: function(e) { this.chart.canvas.style.cursor = 'pointer'; },
            onLeave: function(e) { this.chart.canvas.style.cursor = 'default'; },
        },
        // Speed up initial animation
        animation: {
            duration: 1000,
        },
        // The labels appearing on top of points
        tooltips: {
            mode: "index",
            position: "bottom",
            backgroundColor: 'rgba(10, 10, 10, 220)',
            intersect: false,
            callbacks: {
                // Make sure there is a $ and floating point looks sane
                label: function(tooltipItems, data) {
                    return data.datasets[tooltipItems.datasetIndex].label + ': $' + parseFloat(data.datasets[tooltipItems.datasetIndex].data[tooltipItems.index]).toFixed(2);
                },
            },
        },
        // The animation when hovering on an axis
        hover: {
            mode: "x-axis",
            intersect: true,
            animationDuration: 0,
        },
        scales: {
            xAxes: [
                {
                    id: 'x-time',
                    display: true,
                    type: "time",
                    distribution: "linear",
                    time: {
                        unit: "day",
                        stepSize: 7,
                    },
                },
                // This is an invisible axis so that we have better sizing
                // and positioning for our set symbols
                {
                    id: 'x-top',
                    type: 'category',
                    position: 'top',
                    display: true,
                    // These labels are not going to be visible but will serve
                    // as input ticks to check for where to put symbols
                    labels: xAxisLabels,
                    gridLines: {
                        display: false,
                    },
                    ticks: {
                        fontColor: 'transparent',
                        fontSize: 4,
                        reverse: true,
                    },
                },
            ],
            yAxes: [
                {
                    id: 'y-data',
                    display: true,
                    ticks: {
                        beginAtZero: true,
                        callback: function(value, index, values) {
                            return '$' + value.toFixed(2);
                        },
                    },
                    afterDataLimits: function(axis) {
                        // Keep a 10% buffer
                        axis.max *= 1.1;
                    },
                },
            ],
        },
    }
}

// Read a CSS variable from the current document
function readVar(name) {
    let el = document.documentElement;
    if (document.body.classList.contains('light-theme') || document.body.classList.contains('dark-theme')) {
        el = document.body;
    }
    // Trim to remove possible whitespaces
    return window.getComputedStyle(el).getPropertyValue(name).trim();
}

// Read chart options and set the appropriate theme color for grid and text
// Only the first two axis are set to let invisible ones alone
function rethemeFirstAxes(chart) {
    if (!chart || !chart.options) {
        return;
    }

    const grid = readVar('--chartjs-grid');
    const text = readVar('--chartjs-text');

    // Legend + title text
    chart.options.legend = chart.options.legend || {};
    chart.options.legend.labels = chart.options.legend.labels || {};
    chart.options.legend.labels.fontColor = text;
    if (chart.options.title) {
        chart.options.title.fontColor = text;
    }

    // Only first x axis and first y axis
    const scales = chart.options.scales || (chart.options.scales = {});
    const x0 = (scales.xAxes && scales.xAxes[0]) || null;
    const y0 = (scales.yAxes && scales.yAxes[0]) || null;

    if (x0) {
        x0.ticks = x0.ticks || {};
        x0.ticks.fontColor = text;
        x0.gridLines = x0.gridLines || {};
        x0.gridLines.color = grid;
        x0.gridLines.zeroLineColor = grid;
    }

    if (y0) {
        y0.ticks = y0.ticks || {};
        y0.ticks.fontColor = text;
        y0.gridLines = y0.gridLines || {};
        y0.gridLines.color = grid;
        y0.gridLines.zeroLineColor = grid;
    }

    // Redraw
    chart.update();
}

// Extend chart options to capture clicks and save state in local storage
function withLegendPersistence(legendStorageKey, opts) {
    var orig = (Chart.defaults.global.legend && Chart.defaults.global.legend.onClick) || function(){};

    opts.legend = opts.legend || {};
    opts.legend.onClick = function(e, legendItem) {
        // Run the default toggle
        orig.call(this, e, legendItem);

        // Save hidden flags using computed visibility
        var chart = this.chart;
        var hidden = chart.data.datasets.map(function(ds, i) {
            return !chart.isDatasetVisible(i);
        });
        localStorage.setItem(legendStorageKey, JSON.stringify(hidden));
    };

    return opts;
}

// Load legend state from local storage and apply it
function applySavedLegendState(chart) {
    var raw = localStorage.getItem(legendStorageKey);
    if (!raw) {
        return;
    }

    try {
        var hidden = JSON.parse(raw);

        hidden.forEach(function(isHidden, i) {
            // Guard for dataset count changes
            if (!chart.data.datasets[i]) {
                return;
            }

            // Source of truth: dataset.hidden
            chart.data.datasets[i].hidden = !!isHidden;

            // Let the default legend logic control visibility going forward
            chart.getDatasetMeta(i).hidden = null;
        });

        // Redraw chart
        chart.update();
    } catch (e) {
        console.error('Failed to parse legend state:', e);

        // Delete bad state
        localStorage.removeItem(legendStorageKey);
    }
}
