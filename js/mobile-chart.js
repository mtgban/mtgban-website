// Mobile Chart - price history in a bottom drawer with pinch/pan/zoom
(function() {
    var currentChart = null;
    var currentCardId = null;
    var currentMaxLoaded = 0;
    var prefetchPromise = null;
    // The ceiling's answer, fetched ahead and kept off the chart until a range
    // past what it draws is picked.
    var prefetched = null;
    var libsLoaded = false;
    var libsLoading = false;

    var HIDDEN_COOKIE = 'MobileChartHidden';

    function readHiddenVendors() {
        var match = document.cookie.match(new RegExp('(?:^|; )' + HIDDEN_COOKIE + '=([^;]*)'));
        if (!match) return [];
        try {
            return decodeURIComponent(match[1]).split(',').filter(Boolean);
        } catch (e) {
            return [];
        }
    }

    function writeHiddenVendors(names) {
        var maxAge = 60 * 60 * 24 * 365 * 5;
        document.cookie = HIDDEN_COOKIE + '=' + encodeURIComponent(names.join(',')) + '; path=/; max-age=' + maxAge + '; SameSite=Lax';
    }

    // Remember which stores are currently hidden so the next chart restores them.
    function saveHiddenVendors(chart) {
        var hidden = [];
        chart.data.datasets.forEach(function(ds, i) {
            if (!chart.isDatasetVisible(i)) hidden.push(ds.label);
        });
        writeHiddenVendors(hidden);
    }

    function pickInitialRange() {
        var saved = parseInt(localStorage.getItem('chartDateRange'));
        if (isNaN(saved) || saved <= 0) saved = 180;
        var select = document.getElementById('m-chart-range');
        if (!select) return saved;
        var bestEnabled = 30;
        var matched = false;
        for (var i = 0; i < select.options.length; i++) {
            var opt = select.options[i];
            if (opt.disabled) continue;
            var v = parseInt(opt.value);
            if (v <= saved && v > bestEnabled) bestEnabled = v;
            if (v === saved) matched = true;
        }
        return matched ? saved : bestEnabled;
    }

    function setRangePickerValue(v) {
        var select = document.getElementById('m-chart-range');
        if (select) select.value = String(v);
    }

    function setRangePickerDisabled(disabled) {
        var select = document.getElementById('m-chart-range');
        if (select) select.disabled = disabled;
    }

    function setRangeFailed(failed) {
        var note = document.getElementById('m-chart-range-failed');
        if (note) note.hidden = !failed;
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

    function fetchChart(cardId, range) {
        return fetch('/api/chart/' + encodeURIComponent(cardId) + '?range=' + range)
            .then(function(r) {
                // An error status is a chart that failed to load, not a card
                // with no history, so it must not read as an empty answer.
                if (!r.ok) throw new Error('chart ' + r.status);
                return r.json();
            });
    }

    function prefetchFullRange(cardId, fullRange) {
        prefetchPromise = fetchChart(cardId, fullRange)
            .then(function(data) {
                if (currentCardId !== cardId || !currentChart) return;
                // A wider window holds the one drawn, so an empty answer is a
                // failed widening, as the desktop loader takes it too.
                if (!data || !data.datasets || !data.datasets.length) throw new Error('chart prefetch: empty payload');
                // Drawing it now would widen the chart past the range the
                // select still names.
                prefetched = { data: data, days: fullRange };
            })
            .catch(function(err) {
                console.error('chart prefetch failed', err);
                prefetchPromise = null;
            });
        return prefetchPromise;
    }

    // The wider window can hold stores the drawn one lacks, which shifts where
    // /api/chart lists the rest, so the lines are rebuilt from it: matched by
    // position, a line would draw another store's prices.
    function installPrefetched() {
        if (!prefetched || !currentChart) return;
        currentChart.data.labels = prefetched.data.axisLabels;
        currentChart.data.datasets = chartDatasets(prefetched.data.datasets);
        renderChartLegend(prefetched.data.datasets, currentChart);
        currentMaxLoaded = prefetched.days;
        prefetched = null;
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
            'https://cdn.jsdelivr.net/npm/chart.js@4.5.1/dist/chart.umd.min.js',
            'https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns@3.0.0/dist/chartjs-adapter-date-fns.bundle.min.js',
            'https://cdn.jsdelivr.net/npm/hammerjs@2.0.8/hammer.min.js',
            'https://cdn.jsdelivr.net/npm/chartjs-plugin-zoom@2.2.0/dist/chartjs-plugin-zoom.min.js'
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

    // chartDatasets turns /api/chart's datasets into the chart's lines, one per
    // store, hiding the stores the viewer hid on this card or an earlier one.
    function chartDatasets(datasets) {
        var hidden = readHiddenVendors();
        return datasets.map(function(ds) {
            return {
                label: ds.name,
                data: ds.data.map(function(v) {
                    var n = parseFloat(v);
                    return isNaN(n) ? null : n;
                }),
                hidden: hidden.indexOf(ds.name) !== -1,
                borderColor: ds.color,
                fill: 'origin',
                tension: 0.15,
                borderWidth: 2,
                pointRadius: 0,
                pointHoverRadius: 4,
                pointHitRadius: 8,
            };
        });
    }

    function createChart(canvas, data) {
        var textColor = readVar('--chartjs-text') || '#aaa';
        var gridColor = readVar('--chartjs-grid') || 'rgba(150,150,150,0.06)';

        var datasets = chartDatasets(data.datasets);

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
                // Persist immediately, not only when the drawer closes.
                saveHiddenVendors(chart);
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
        nameEl.textContent = cardName;
        loading.style.display = 'block';
        loading.textContent = 'Loading chart...';
        if (legendEl) legendEl.innerHTML = '';
        canvas.style.display = 'none';
        resetBtn.style.display = 'none';
        setRangePickerDisabled(true);
        setRangeFailed(false);
        overlay.classList.add('open');
        drawer.classList.add('open');
        // Lock background scrolling while the chart drawer is open
        document.body.style.overflow = 'hidden';

        if (currentChart) {
            currentChart.destroy();
            currentChart = null;
        }
        currentCardId = cardId;
        currentMaxLoaded = 0;
        prefetchPromise = null;
        prefetched = null;

        var initialRange = pickInitialRange();
        setRangePickerValue(initialRange);

        loadChartLibs(function() {
            var loaded = initialRange;
            fetchChart(cardId, initialRange)
                .then(function(data) {
                    // An empty window may only mean the card's prices all predate
                    // it, as a retired printing's do: ask for all the tier allows.
                    if (currentCardId === cardId && data.datasets && !data.datasets.length && data.maxLookbackDays > initialRange) {
                        loaded = data.maxLookbackDays;
                        return fetchChart(cardId, loaded);
                    }
                    return data;
                })
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
                    currentMaxLoaded = loaded;
                    setRangePickerDisabled(false);
                    if (data.maxLookbackDays && data.maxLookbackDays > loaded) {
                        prefetchFullRange(cardId, data.maxLookbackDays);
                    }
                })
                .catch(function(err) {
                    loading.style.display = 'block';
                    loading.textContent = 'Failed to load chart';
                    console.error(err);
                });
        });
    };

    window.hideChartDrawer = function() {
        if (currentChart) {
            saveHiddenVendors(currentChart);
        }
        document.getElementById('m-chart-overlay').classList.remove('open');
        document.getElementById('m-chart-drawer').classList.remove('open');
        // Restore background scrolling
        document.body.style.overflow = '';
    };

    window.resetChartZoom = function() {
        if (currentChart) currentChart.resetZoom();
    };

    window.changeChartRange = function(range) {
        if (isNaN(range) || range <= 0) return;
        localStorage.setItem('chartDateRange', String(range));
        setRangePickerValue(range);
        if (currentChart) currentChart.resetZoom();

        if (range <= currentMaxLoaded) {
            setRangeFailed(false);
            applyRangeFilter(range);
            return;
        }

        var cardId = currentCardId;
        setRangePickerDisabled(true);

        var p = prefetchPromise;
        if (!p) {
            // Prefetch was never started or failed - fire one now.
            // Fall back to `range` itself as the upper bound; this is a best-effort
            // expansion since we no longer know maxLookbackDays in this scope.
            p = prefetchFullRange(cardId, range);
        }

        p.then(function() {
            if (currentCardId !== cardId) return;
            installPrefetched();
            // A widening that failed leaves the chart what it had: draw all of
            // it, set the select to it so picking the range again retries, and
            // say so.
            var failed = range > currentMaxLoaded;
            setRangeFailed(failed);
            if (failed) {
                range = currentMaxLoaded;
                setRangePickerValue(range);
            }
            applyRangeFilter(range);
        }).catch(function() {
            // Swallow - the catch in prefetchFullRange already logged.
        }).then(function() {
            if (currentCardId === cardId) setRangePickerDisabled(false);
        });
    };

})();