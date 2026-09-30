function showResTab(panel, btn) {
    document.querySelectorAll('.res-panel').forEach(function(p) { p.classList.remove('active'); });
    document.getElementById('panel-' + panel).classList.add('active');
    document.querySelectorAll('.res-tab').forEach(function(t) { t.classList.remove('on'); });
    btn.classList.add('on');
    // Remember the view so a reload/refresh can return to it
    try { sessionStorage.setItem('uploadResView', panel); } catch (e) {}
}
function showUresView(view, btn) {
    var views = document.querySelector('.ures-views');
    if (views) { views.setAttribute('data-ures-view', view); }
    var bar = btn.closest('.ures-subtabs');
    if (bar) {
        bar.querySelectorAll('.ures-subtab').forEach(function(b) { b.classList.remove('on'); });
    }
    btn.classList.add('on');
    updateExportButtons(view);
}
// One-time localStorage → cookie migration for the upload optimizer
document.addEventListener('DOMContentLoaded', function migrateUploadPrefs() {
    var existing = getCookie('UploadOptimizerOpts');
    if (existing !== null && existing !== '') return; // already migrated or has cookie state
    if (localStorage.getItem('lowval') === null && localStorage.getItem('percspread') === null) return; // nothing to migrate
    var bits = [];
    ['lowval','highval','lowvalabs','highvalabs','minmargin','nocond','noprice','customperc','noresults'].forEach(function (k) {
        if (localStorage.getItem(k) === 'true') bits.push(k);
    });
    setCookie('UploadOptimizerOpts', bits.join(',') + (bits.length ? ',' : ''), 1000);
    var textMap = {
        percspread: 'UploadPercSpread',
        percspreadmax: 'UploadPercSpreadMax',
        minval: 'UploadMinVal',
        maxval: 'UploadMaxVal',
        margin: 'UploadMargin',
        custompercmax: 'UploadCustomPercMax',
        multiplier: 'UploadMultiplier',
        maxqty: 'UploadMaxQty',
        sorting: 'UploadSorting',
        altPrice: 'UploadAltPrice',
        pricesource: 'UploadPriceSource',
    };
    Object.keys(textMap).forEach(function (k) {
        var v = localStorage.getItem(k);
        if (v !== null && v !== '') setCookie(textMap[k], v, 1000);
    });
    // Cleanup so we don't migrate again
    var allKeys = Object.keys(textMap).concat(['lowval','highval','lowvalabs','highvalabs','minmargin','nocond','noprice','customperc','noresults']);
    allKeys.forEach(function (k) { localStorage.removeItem(k); });
});
// Jump to the optimizer only on a fresh submission (from the main page
// or elsewhere). On a reload — page refresh or the Reload button — keep
// the view the user was in instead of forcing the optimizer.
//
// Unpacking is the exception to the preference: it was asked in order to
// read what is inside these products, and the optimizer answers a
// different question - what to buy and where - so a standing preference
// for it does not carry to a view that exists to be read. A reload still
// keeps whichever view was open, including the optimizer if it was picked
// by hand: that is an answer to what the reader just did, not a setting.
var uploadIsUnpacked = window.BAN_UPLOAD_TABS.unpacked;
document.addEventListener('DOMContentLoaded', function () {
    var nav = performance.getEntriesByType('navigation')[0];
    var navType = nav ? nav.type : 'navigate';
    var isReload = navType !== 'navigate' || sessionStorage.getItem('uploadReload') === '1';
    sessionStorage.removeItem('uploadReload');

    var panel;
    if (isReload) {
        panel = sessionStorage.getItem('uploadResView') || 'results';
    } else if (uploadIsUnpacked) {
        panel = 'results';
    } else {
        var opts = (getCookie('UploadOptimizerOpts') || '').split(',').filter(Boolean);
        panel = opts.indexOf('noresults') >= 0 ? 'optimizer' : 'results';
    }
    // 'results' is already the active panel; only act for the optimizer
    if (panel === 'optimizer') {
        var optBtn = document.querySelector('.res-tab:nth-child(2)');
        if (optBtn) showResTab('optimizer', optBtn);
    }
});
