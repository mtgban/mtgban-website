// Mobile Chart - price history in a bottom drawer with pinch/pan/zoom
(function() {
    var currentChart = null;
    var currentCardId = null;
    var currentMaxLoaded = 0;
    var prefetchPromise = null;
    var libsLoaded = false;
    var libsLoading = false;

    function pickInitialRange() {
        var saved = parseInt(localStorage.getItem('chartDateRange'));
        if (isNaN(saved) || saved <= 0) saved = 180;
        var sel = document.getElementById('m-chart-range');
        if (!sel) return saved;
        var bestEnabled = 30;
        var matched = false;
        for (var i = 0; i < sel.options.length; i++) {
            var opt = sel.options[i];
            if (opt.disabled) continue;
            var v = parseInt(opt.value);
            if (v <= saved && v > bestEnabled) bestEnabled = v;
            if (v === saved) matched = true;
        }
        return matched ? saved : bestEnabled;
    }

    function applyRangeFilter(range) {
        if (!currentChart) return;
        var labels = currentChart.data.labels;
        if (!labels || range === 0 || range >= labels.length) {
            currentChart.options.scales.x.min = undefined;
        } else {
            currentChart.options.scales.x.min = labels[range - 1];
        }
        currentChart.update();
    }

    function loadChartLibs(callback) {
        if (libsLoaded) { callback(); return; }
        if (libsLoading) {
            var check = setInterval(function() {
                if (libsLoaded) { clearInterval(check); callback(); }
            }, 50);
            return;
        }
        libsLoading = true;

        var scripts = [
            'https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js',
            'https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns@3/dist/chartjs-adapter-date-fns.bundle.min.js',
            'https://cdn.jsdelivr.net/npm/hammerjs@2/hammer.min.js',
            'https://cdn.jsdelivr.net/npm/chartjs-plugin-zoom@2/dist/chartjs-plugin-zoom.min.js'
        ];

        var loaded = 0;
        function loadNext() {
            if (loaded >= scripts.length) {
                libsLoaded = true;
                libsLoading = false;
                callback();
                return;
            }
            var s = document.createElement('script');
            s.src = scripts[loaded];
            s.onload = function() { loaded++; loadNext(); };
            s.onerror = function() {
                console.error('Failed to load', scripts[loaded]);
                loaded++; loadNext();
            };
            document.head.appendChild(s);
        }
        loadNext();
    }

    function readVar(name) {
        var el = document.documentElement;
        if (document.body.classList.contains('light-theme') || document.body.classList.contains('dark-theme')) {
            el = document.body;
        }
        return window.getComputedStyle(el).getPropertyValue(name).trim();
    }

    function createChart(canvas, data) {
        var textColor = readVar('--chartjs-text') || '#aaa';
        var gridColor = readVar('--chartjs-grid') || 'rgba(150,150,150,0.06)';

        var datasets = data.datasets.map(function(ds) {
            return {
                label: ds.name,
                data: ds.data.map(function(v) {
                    var n = parseFloat(v);
                    return isNaN(n) ? null : n;
                }),
                borderColor: ds.color,
                fill: 'origin',
                tension: 0.15,
                borderWidth: 2,
                pointRadius: 0,
                pointHoverRadius: 4,
                pointHitRadius: 8,
            };
        });

        var gradientPlugin = {
            id: 'mobileGradient',
            afterLayout: function(chart) {
                var area = chart.chartArea;
                if (!area) return;
                chart.data.datasets.forEach(function(ds) {
                    var color = ds.borderColor;
                    if (!color || typeof color !== 'string') return;
                    var match = color.match(/(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/);
                    if (!match) return;
                    var grad = chart.ctx.createLinearGradient(0, area.top, 0, area.bottom);
                    grad.addColorStop(0, 'rgba(' + match[1] + ',' + match[2] + ',' + match[3] + ',0.10)');
                    grad.addColorStop(0.5, 'rgba(' + match[1] + ',' + match[2] + ',' + match[3] + ',0.03)');
                    grad.addColorStop(1, 'rgba(' + match[1] + ',' + match[2] + ',' + match[3] + ',0)');
                    ds.backgroundColor = grad;
                });
            }
        };

        var crosshairPlugin = {
            id: 'mobileCrosshair',
            afterDatasetsDraw: function(chart) {
                var active = chart.tooltip && chart.tooltip.getActiveElements();
                if (!active || !active.length) return;
                var x = active[0].element.x;
                var top = chart.chartArea.top;
                var bottom = chart.chartArea.bottom;
                var ctx = chart.ctx;
                ctx.save();
                ctx.beginPath();
                ctx.setLineDash([4, 3]);
                ctx.moveTo(x, top);
                ctx.lineTo(x, bottom);
                ctx.lineWidth = 1;
                ctx.strokeStyle = readVar('--chartjs-crosshair') || 'rgba(150,150,150,0.4)';
                ctx.stroke();
                ctx.restore();
            }
        };

        return new Chart(canvas, {
            type: 'line',
            data: {
                labels: data.axisLabels,
                datasets: datasets,
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                spanGaps: true,
                animation: { duration: 400 },
                interaction: { mode: 'index', intersect: false },
                elements: {
                    line: { tension: 0.15, borderWidth: 2 },
                    point: { radius: 0, hoverRadius: 4, hitRadius: 8 },
                },
                plugins: {
                    legend: {
                        display: false,
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                        titleFont: { size: 11 },
                        bodyFont: { size: 11 },
                        callbacks: {
                            title: function(items) {
                                if (!items.length) return '';
                                var d = new Date(items[0].parsed.x);
                                return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
                            },
                            label: function(ctx) {
                                var val = parseFloat(ctx.raw);
                                if (isNaN(val)) return null;
                                return ctx.dataset.label + ': $' + val.toFixed(2);
                            },
                        },
                    },
                    zoom: {
                        pan: {
                            enabled: true,
                            mode: 'x',
                        },
                        zoom: {
                            wheel: { enabled: false },
                            pinch: { enabled: true },
                            mode: 'x',
                        },
                    },
                },
                scales: {
                    x: {
                        type: 'time',
                        time: { unit: 'day', stepSize: 14, displayFormats: { day: 'MMM d' } },
                        grid: { color: gridColor, drawTicks: false },
                        ticks: { color: textColor, padding: 6, maxRotation: 0, font: { size: 9 }, maxTicksLimit: 7 },
                        border: { display: false },
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: gridColor, drawTicks: false },
                        ticks: {
                            color: textColor,
                            padding: 6,
                            font: { size: 9 },
                            callback: function(v) { return '$' + v.toFixed(2); },
                        },
                        border: { display: false },
                        afterDataLimits: function(axis) { axis.max *= 1.1; },
                    },
                },
            },
            plugins: [gradientPlugin, crosshairPlugin],
        });
    }

    var shortNames = {
        'TCGplayer Low': 'TCG Low',
        'TCGplayer Market': 'TCG Market',
        'Card Kingdom Retail': 'CK Retail',
        'Card Kingdom Buylist': 'CK Buylist',
        'Cardmarket Low': 'MKM Low',
        'Cardmarket Trend': 'MKM Trend',
        'Star City Games Buylist': 'SCG Buylist',
        'ABU Games Buylist': 'ABU Buylist',
        'Cool Stuff Inc Buylist': 'CSI Buylist',
    };

    function shortName(name) {
        return shortNames[name] || name;
    }

    function renderChartLegend(datasets, chart) {
        var container = document.getElementById('m-chart-legend');
        if (!container) return;
        var html = '';
        datasets.forEach(function(ds, i) {
            var visible = chart.isDatasetVisible(i);
            html += '<button class="m-chart-legend-item' + (visible ? '' : ' hidden') + '" data-index="' + i + '" style="border-color:' + ds.color + '">';
            html += '<span class="m-chart-legend-dot" style="background:' + ds.color + '"></span>';
            html += shortName(ds.name);
            html += '</button>';
        });
        container.innerHTML = html;

        // Toggle dataset visibility on click
        container.querySelectorAll('.m-chart-legend-item').forEach(function(btn) {
            btn.addEventListener('click', function() {
                var idx = parseInt(this.getAttribute('data-index'));
                var visible = chart.isDatasetVisible(idx);
                chart.setDatasetVisibility(idx, !visible);
                chart.update();
                this.classList.toggle('hidden');
            });
        });
    }

    window.showChartDrawer = function(cardId, isSealed, cardName) {
        var overlay = document.getElementById('m-chart-overlay');
        var drawer = document.getElementById('m-chart-drawer');
        var nameEl = document.getElementById('m-chart-name');
        var loading = document.getElementById('m-chart-loading');
        var canvas = document.getElementById('m-chart-canvas');
        var resetBtn = document.getElementById('m-chart-reset');
        var legendEl = document.getElementById('m-chart-legend');
        var rangeSel = document.getElementById('m-chart-range');

        nameEl.textContent = cardName;
        loading.style.display = 'block';
        loading.textContent = 'Loading chart...';
        if (legendEl) legendEl.innerHTML = '';
        canvas.style.display = 'none';
        resetBtn.style.display = 'none';
        if (rangeSel) rangeSel.disabled = true;
        overlay.classList.add('open');
        drawer.classList.add('open');

        if (currentChart) {
            currentChart.destroy();
            currentChart = null;
        }
        currentCardId = cardId;
        currentMaxLoaded = 0;
        prefetchPromise = null;

        var initialRange = pickInitialRange();
        if (rangeSel) rangeSel.value = String(initialRange);

        loadChartLibs(function() {
            fetch('/api/chart/' + encodeURIComponent(cardId) + '?range=' + initialRange)
                .then(function(r) { return r.json(); })
                .then(function(data) {
                    if (currentCardId !== cardId) return;
                    loading.style.display = 'none';
                    if (!data.datasets || data.datasets.length === 0) {
                        loading.style.display = 'block';
                        loading.textContent = 'No chart data available';
                        return;
                    }
                    canvas.style.display = 'block';
                    resetBtn.style.display = 'inline-block';
                    currentChart = createChart(canvas.getContext('2d'), data);
                    renderChartLegend(data.datasets, currentChart);
                    currentMaxLoaded = initialRange;
                    if (rangeSel) rangeSel.disabled = false;
                })
                .catch(function(err) {
                    loading.style.display = 'block';
                    loading.textContent = 'Failed to load chart';
                    console.error(err);
                });
        });
    };

    window.hideChartDrawer = function() {
        document.getElementById('m-chart-overlay').classList.remove('open');
        document.getElementById('m-chart-drawer').classList.remove('open');
    };

    window.resetChartZoom = function() {
        if (currentChart) currentChart.resetZoom();
    };

    window.changeChartRange = function(range) {
        if (isNaN(range) || range <= 0) return;
        localStorage.setItem('chartDateRange', String(range));
        if (currentChart) currentChart.resetZoom();
        if (range <= currentMaxLoaded) {
            applyRangeFilter(range);
        }
    };

    function wireRangePicker() {
        var sel = document.getElementById('m-chart-range');
        if (!sel) return;
        sel.addEventListener('change', function() {
            var v = parseInt(this.value);
            window.changeChartRange(v);
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', wireRangePicker);
    } else {
        wireRangePicker();
    }
})();