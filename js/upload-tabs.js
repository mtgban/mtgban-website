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
    setCookie('UploadOptimizerOpts', bits.join(',') + ',', 1000);
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
// The inline guard before the panels picks the start view, so that a page
// starting on the optimizer never paints the results first; this makes it
// the active panel for good.
(function () {
    var holder = document.querySelector('.res-start-optimizer');
    var optBtn = document.querySelector('.res-tab:nth-child(2)');
    if (!holder || !optBtn) return;
    showResTab('optimizer', optBtn);
    holder.classList.remove('res-start-optimizer');
})();
