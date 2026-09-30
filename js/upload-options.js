function syncUploadOptionsFromSettings() {
    var form = document.getElementById('upload_form');
    if (!form) return;
    // Remove any previously-injected hidden inputs
    form.querySelectorAll('[data-injected-opt]').forEach(function (el) { el.remove(); });
    function add(name, val) {
        var inp = document.createElement('input');
        inp.type = 'hidden';
        inp.name = name;
        inp.value = val == null ? '' : val;
        inp.dataset.injectedOpt = '1';
        form.appendChild(inp);
    }
    var optsRaw = getCookie('UploadOptimizerOpts');
    var opts = (optsRaw === null || optsRaw === '')
        ? ['lowval', 'lowvalabs', 'minmargin', 'customperc']
        : optsRaw.split(',').filter(Boolean);
    ['lowval','highval','lowvalabs','highvalabs','minmargin','nocond','noprice','customperc','noresults'].forEach(function (k) {
        if (opts.indexOf(k) >= 0) add(k, 'true');
    });
    // The results page carries an unpack field of its own, which the Unpack
    // action sets. A re-post from there says what that click said rather
    // than what the setting says, so reloading a page of opened cards does
    // not try to open them again.
    if (opts.indexOf('unpack') >= 0 && !form.querySelector('[name="unpack"]')) {
        add('unpack', 'true');
    }
    add('percspread',     getCookie('UploadPercSpread')    || '60');
    add('percspreadmax',  getCookie('UploadPercSpreadMax') || '0');
    add('minval',         getCookie('UploadMinVal')        || '1');
    add('maxval',         getCookie('UploadMaxVal')        || '0');
    add('margin',         getCookie('UploadMargin')        || '10');
    add('custompercmax',  getCookie('UploadCustomPercMax') || '100');
    add('multiplier',     getCookie('UploadMultiplier')    || '1');
    add('maxqty',         getCookie('UploadMaxQty')        || '0');
    add('sorting',        getCookie('UploadSorting')       || '');
    add('altPrice',       getCookie('UploadAltPrice')      || '');
    add('pricesource',    getCookie('UploadPriceSource')   || '');
    var customOpts = (getCookie('UploadCustomOpts') || '').split(',').filter(Boolean);
    if (customOpts.indexOf('enabled') >= 0) {
        add('custombuylist',      'true');
        add('customseller',       getCookie('UploadCustomBuyer')       || 'TCGLow');
        add('customsealedseller', getCookie('UploadCustomSealedBuyer') || 'TCGSealed');
        add('customminprice',     getCookie('UploadCustomMinPrice')    || '7');
        add('customrate',         getCookie('UploadCustomRate')        || '0.8');
    }
}
