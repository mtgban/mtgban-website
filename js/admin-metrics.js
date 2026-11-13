// Draws the admin Metrics charts from window.BAN_ADMIN_METRICS; the tables beside them stay.

// adminMetricsConfig is the Chart.js config for one chart, or null when it has nothing to draw.
function adminMetricsConfig(chart) {
    var GREY = '#888888';
    var PALETTE = ['#2f7ed8', '#e4572e', '#29a36a', '#a05fd1', '#d4a017', '#17a2b8'];

    // readVar follows chartopts.js: the body holds the variables when a theme class is set.
    function readVar(name) {
        try {
            var el = document.documentElement;
            if (document.body.classList.contains('light-theme') || document.body.classList.contains('dark-theme')) {
                el = document.body;
            }
            return String(getComputedStyle(el).getPropertyValue(name) || '').trim() || GREY;
        } catch (e) {
            return GREY;
        }
    }

    if (!chart || typeof chart !== 'object' || !Array.isArray(chart.labels) || !Array.isArray(chart.series) || !chart.series.length) {
        return null;
    }
    var datasets = [];
    for (var i = 0; i < chart.series.length; i++) {
        var s = chart.series[i];
        if (!s || typeof s !== 'object' || !Array.isArray(s.data) || !s.data.length) {
            return null;
        }
        // one finite number per label, or the chart is skipped and its table stays
        if (s.data.length !== chart.labels.length || !s.data.every(function (v) { return typeof v === 'number' && isFinite(v); })) {
            return null;
        }
        var color = PALETTE[i % PALETTE.length];
        datasets.push({ label: String(s.label), data: s.data.slice(), borderColor: color, backgroundColor: color });
    }
    var text = readVar('--chartjs-text');
    var grid = readVar('--chartjs-grid');
    var axis = function () {
        return { ticks: { color: text }, grid: { color: grid } };
    };
    var data = { labels: chart.labels.slice(), datasets: datasets };

    switch (chart.kind) {
    case 'line':
        var y = axis();
        y.beginAtZero = true;
        return {
            type: 'line',
            data: data,
            options: {
                animation: false,
                responsive: true,
                maintainAspectRatio: false,
                scales: { x: axis(), y: y },
                plugins: { legend: { display: datasets.length > 1, labels: { color: text } } },
            },
        };
    case 'bars':
        return {
            type: 'bar',
            data: data,
            options: {
                indexAxis: 'y',
                animation: false,
                responsive: true,
                maintainAspectRatio: false,
                scales: { x: axis(), y: axis() },
                plugins: { legend: { display: false } },
            },
        };
    case 'spark':
        datasets.forEach(function (d) {
            d.pointRadius = 0;
            d.borderWidth = 1.5;
        });
        return {
            type: 'line',
            data: data,
            options: {
                animation: false,
                responsive: true,
                maintainAspectRatio: false,
                events: [],
                scales: { x: { display: false }, y: { display: false, beginAtZero: true } },
                plugins: { legend: { display: false }, tooltip: { enabled: false } },
            },
        };
    }
    return null;
}

// drawAdminMetrics draws each chart on its canvas; with no Chart.js or no list it does nothing.
function drawAdminMetrics(doc, charts, Chart) {
    if (typeof Chart !== 'function' || !Array.isArray(charts) || !doc || typeof doc.getElementById !== 'function') {
        return;
    }
    charts.forEach(function (chart) {
        try {
            var canvas = chart && typeof chart.id === 'string' ? doc.getElementById(chart.id) : null;
            var config = canvas ? adminMetricsConfig(chart) : null;
            if (config) {
                new Chart(canvas, config);
            }
        } catch (e) {
            // the table beside it still holds the numbers
        }
    });
}

drawAdminMetrics(document, (window.BAN_ADMIN_METRICS || {}).charts, window.Chart);
