// Per-store price adjustments: a retail discount and a credit value per
// store, kept in the synced preference mtgban_store_factors and mirrored
// into the SearchStoreFactors cookie the search handler reads.
(function () {
    'use strict';

    var PREF_KEY = 'mtgban_store_factors';
    var COOKIE = 'SearchStoreFactors';
    var RELOADED_KEY = 'mtgban_store_factors_reloaded';
    var DISCOUNT = { min: 1, max: 90 };
    var CREDIT = { min: 10, max: 300 };

    function parse(raw) {
        try {
            var o = JSON.parse(raw);
            return o && typeof o === 'object' && !Array.isArray(o) ? o : {};
        } catch (e) {
            return {};
        }
    }

    function rawPref() {
        try { return localStorage.getItem(PREF_KEY); } catch (e) { return null; }
    }

    function read() {
        var raw = rawPref();
        return raw ? parse(raw) : {};
    }

    function inRange(v, r) {
        return Number.isInteger(v) && v >= r.min && v <= r.max;
    }

    // Keeps what the server would apply: known stores, integer percents in
    // range, a discount where the store sells and a credit where it buys.
    function normalize(obj, stores) {
        var byKey = {};
        (stores || []).forEach(function (s) { byKey[s.k] = s; });
        var out = {};
        Object.keys(obj || {}).forEach(function (k) {
            var s = byKey[k];
            var e = obj[k];
            if (!s || !e || typeof e !== 'object') return;
            var clean = {};
            if (s.r && inRange(e.discount, DISCOUNT)) clean.discount = e.discount;
            if (s.b && inRange(e.credit, CREDIT) && e.credit !== 100) clean.credit = e.credit;
            if (Object.keys(clean).length) out[k] = clean;
        });
        return out;
    }

    function toCookie(obj) {
        return Object.keys(obj || {}).sort().map(function (k) {
            var e = obj[k] || {};
            return k + ':' + (e.discount || '') + ':' + (e.credit || '');
        }).join(',');
    }

    function fromCookie(str) {
        var out = {};
        String(str || '').split(',').forEach(function (item) {
            var parts = item.split(':');
            if (parts.length !== 3 || !parts[0]) return;
            var e = {};
            if (parts[1] !== '') e.discount = Number(parts[1]);
            if (parts[2] !== '') e.credit = Number(parts[2]);
            if ('discount' in e && !inRange(e.discount, DISCOUNT)) return;
            if ('credit' in e && !inRange(e.credit, CREDIT)) return;
            if (Object.keys(e).length) out[parts[0]] = e;
        });
        return out;
    }

    // Both copies, written together; an empty save keeps the key as {} so
    // the sync carries the clearing to other devices.
    function save(obj) {
        var clean = {};
        Object.keys(obj || {}).forEach(function (k) {
            if (obj[k] && Object.keys(obj[k]).length) clean[k] = obj[k];
        });
        try { localStorage.setItem(PREF_KEY, JSON.stringify(clean)); } catch (e) {}
        setCookie(COOKIE, toCookie(clean), 1000);
    }

    function onSearchPage() {
        var p = (window.location && window.location.pathname) || '';
        return p === '/search' || p.indexOf('/search/') === 0 || p === '/sealed' || p.indexOf('/sealed/') === 0;
    }

    // Brings the cookie to the preference on every page, reloading only
    // the pages that apply it. When they differ the preference is later;
    // a device with a cookie and no preference yet adopts the cookie.
    function mirror() {
        var raw = rawPref();
        var cookie = fromCookie(getCookie(COOKIE));
        if (raw === null || raw === '') {
            if (Object.keys(cookie).length) {
                try { localStorage.setItem(PREF_KEY, JSON.stringify(cookie)); } catch (e) {}
            }
            return;
        }
        var want = toCookie(fromCookie(toCookie(parse(raw))));
        if (want === toCookie(cookie)) return;
        setCookie(COOKIE, want, 1000);
        if (!onSearchPage()) return;
        // Once per preference value, should the cookie not have taken
        try {
            if (sessionStorage.getItem(RELOADED_KEY) === raw) return;
            sessionStorage.setItem(RELOADED_KEY, raw);
        } catch (e) {
            return;
        }
        window.location.reload();
    }

    function storesOf(container) {
        try {
            var list = JSON.parse(container.getAttribute('data-stores') || '[]');
            return Array.isArray(list) ? list : [];
        } catch (e) {
            return [];
        }
    }

    function el(tag, cls, text) {
        var e = document.createElement(tag);
        if (cls) e.className = cls;
        if (text !== undefined) e.textContent = text;
        return e;
    }

    function numberInput(cls, range, label, value) {
        var input = el('input', cls);
        input.type = 'number';
        input.min = range.min;
        input.max = range.max;
        input.step = 1;
        input.setAttribute('min', range.min);
        input.setAttribute('max', range.max);
        input.setAttribute('step', 1);
        input.setAttribute('inputmode', 'numeric');
        input.setAttribute('placeholder', label);
        input.setAttribute('aria-label', label);
        if (value) input.value = String(value);
        return input;
    }

    function changed(container) {
        container.dispatchEvent(new Event('change', { bubbles: true }));
    }

    function usedStores(container) {
        var used = {};
        container.querySelectorAll('.store-factors-row').forEach(function (row) {
            used[row.querySelector('.store-factors-store').value] = true;
        });
        return used;
    }

    // Add is off when no store is left without a row
    function syncAdd(container, list) {
        var add = container.querySelector('.store-factors-add');
        if (!add) return;
        var used = usedStores(container);
        add.disabled = !list.some(function (s) { return !used[s.k]; });
    }

    function rowFor(container, list, key, entry) {
        var row = el('div', 'store-factors-row');
        var select = el('select', 'store-factors-store');
        select.setAttribute('aria-label', 'Store');
        // Singles and sealed stores can share a name, so each gets a group,
        // and a sealed name says so where the closed select shows it alone
        var grouped = list.some(function (s) { return s.s; });
        var groups = {};
        list.forEach(function (s) {
            var opt = el('option', '', s.s ? s.n + ' (Sealed)' : s.n);
            opt.value = s.k;
            if (s.k === key) opt.selected = true;
            if (!grouped) {
                select.appendChild(opt);
                return;
            }
            var label = s.s ? 'Sealed' : 'Singles';
            if (!groups[label]) {
                groups[label] = el('optgroup');
                groups[label].setAttribute('label', label);
                select.appendChild(groups[label]);
            }
            groups[label].appendChild(opt);
        });
        select.value = key;
        var discount = numberInput('store-factors-discount', DISCOUNT, 'Discount %', entry.discount);
        var credit = numberInput('store-factors-credit', CREDIT, 'Credit %', entry.credit);
        var remove = el('button', 'store-factors-remove', 'Remove');
        remove.type = 'button';
        remove.setAttribute('aria-label', 'Remove store');
        // A store that only sells has no credit to value, and the reverse
        function enable() {
            var s = list.filter(function (x) { return x.k === select.value; })[0] || {};
            discount.disabled = !s.r;
            if (!s.r) discount.value = '';
            credit.disabled = !s.b;
            if (!s.b) credit.value = '';
        }
        select.addEventListener('change', function () { enable(); syncAdd(container, list); changed(container); });
        discount.addEventListener('input', function () { changed(container); });
        credit.addEventListener('input', function () { changed(container); });
        remove.addEventListener('click', function () { row.remove(); syncAdd(container, list); changed(container); });
        enable();
        row.appendChild(select);
        row.appendChild(discount);
        row.appendChild(credit);
        row.appendChild(remove);
        return row;
    }

    // Draws obj's rows for the stores the container names, then Add store.
    function render(container, obj) {
        var list = storesOf(container);
        var known = {};
        list.forEach(function (s) { known[s.k] = true; });
        container.textContent = '';
        var rows = el('div', 'store-factors-rows');
        Object.keys(obj || {}).sort().forEach(function (k) {
            if (known[k] && obj[k]) rows.appendChild(rowFor(container, list, k, obj[k]));
        });
        var add = el('button', 'store-factors-add', 'Add store');
        add.type = 'button';
        add.disabled = !list.length;
        add.addEventListener('click', function () {
            var used = usedStores(container);
            var free = list.filter(function (s) { return !used[s.k]; })[0];
            if (!free) return;
            rows.appendChild(rowFor(container, list, free.k, {}));
            syncAdd(container, list);
            changed(container);
        });
        container.appendChild(rows);
        container.appendChild(add);
        syncAdd(container, list);
    }

    // The rows as a clean object; a later row for the same store wins.
    function collect(container) {
        var obj = {};
        container.querySelectorAll('.store-factors-row').forEach(function (row) {
            var k = row.querySelector('.store-factors-store').value;
            var d = row.querySelector('.store-factors-discount').value;
            var c = row.querySelector('.store-factors-credit').value;
            var e = {};
            if (d !== '') e.discount = Number(d);
            if (c !== '') e.credit = Number(c);
            if (Object.keys(e).length) obj[k] = e;
        });
        return normalize(obj, storesOf(container));
    }

    // Entries for stores this deployment does not list ride through a save
    // untouched: another deployment of the same game may still have them.
    function keepUnknown(obj, stores) {
        var known = {};
        (stores || []).forEach(function (s) { known[s.k] = true; });
        var out = {};
        Object.keys(obj || {}).forEach(function (k) {
            if (!known[k] && obj[k] && typeof obj[k] === 'object' && Object.keys(obj[k]).length) out[k] = obj[k];
        });
        return out;
    }

    // Saves the editor's rows plus the entries it could not show.
    function saveEditor(container) {
        var merged = keepUnknown(read(), storesOf(container));
        var rows = collect(container);
        Object.keys(rows).forEach(function (k) { merged[k] = rows[k]; });
        save(merged);
    }

    // What settings.js wires: load draws, save writes, serialize feeds dirty.
    function binding(container) {
        return {
            load: function () { render(container, read()); },
            save: function () { saveEditor(container); },
            serialize: function () { return 'StoreFactors=' + JSON.stringify(collect(container)); },
        };
    }

    window.StoreFactors = {
        DISCOUNT: DISCOUNT,
        CREDIT: CREDIT,
        read: read,
        normalize: normalize,
        toCookie: toCookie,
        fromCookie: fromCookie,
        save: save,
        mirror: mirror,
        render: render,
        collect: collect,
        saveEditor: saveEditor,
        binding: binding,
    };

    mirror();
})();
