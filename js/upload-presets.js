// Upload presets: save, match and apply the uploader's configuration.
(function () {
    var FLAG_KEYS = ['lowval', 'highval', 'lowvalabs', 'highvalabs', 'minmargin', 'nocond', 'noprice', 'customperc', 'noresults', 'unpack'];
    var FLAG_DEFAULTS = ['lowval', 'lowvalabs', 'minmargin', 'customperc'];
    // Field name, cookie name, default. Same table upload-options.js injects from.
    var TEXTS = [
        ['percspread', 'UploadPercSpread', '60'], ['percspreadmax', 'UploadPercSpreadMax', '0'],
        ['minval', 'UploadMinVal', '1'], ['maxval', 'UploadMaxVal', '0'],
        ['margin', 'UploadMargin', '10'], ['custompercmax', 'UploadCustomPercMax', '100'],
        ['multiplier', 'UploadMultiplier', '1'], ['maxqty', 'UploadMaxQty', '0'],
        ['sorting', 'UploadSorting', ''], ['altPrice', 'UploadAltPrice', ''], ['pricesource', 'UploadPriceSource', ''],
    ];
    var CUSTOM = [
        ['customseller', 'UploadCustomBuyer', 'TCGLow'], ['customsealedseller', 'UploadCustomSealedBuyer', 'TCGSealed'],
        ['customminprice', 'UploadCustomMinPrice', '7'], ['customrate', 'UploadCustomRate', '0.8'],
    ];
    var NUMERIC = ['percspread', 'percspreadmax', 'minval', 'maxval', 'margin', 'custompercmax', 'multiplier', 'maxqty', 'customminprice', 'customrate'];
    var STORE_LISTS = ['stores', 'sealed_stores', 'index_stores', 'sealed_index_stores'];
    var OPTION_DEFAULTS = {};
    TEXTS.concat(CUSTOM).forEach(function (t) { OPTION_DEFAULTS[t[0]] = t[2]; });

    function splitList(raw) { return (raw || '').split(',').filter(Boolean); }

    function normNumber(v) {
        var n = Number(v);
        if (v === '' || isNaN(n)) return String(v);
        return String(n);
    }

    function sortUnique(list, offered) {
        var seen = {};
        return list.filter(function (s) {
            if (seen[s] || (offered && offered.indexOf(s) < 0)) return false;
            seen[s] = true;
            return true;
        }).sort();
    }

    // canonical sorts keys, normalises numbers and store lists; unknown keys are kept.
    function canonical(opts, ctx) {
        var out = {};
        Object.keys(opts).sort().forEach(function (k) {
            var v = opts[k];
            if (STORE_LISTS.indexOf(k) >= 0) {
                var offered = ctx && ctx.offered ? ctx.offered[k] : null;
                out[k] = sortUnique(Array.isArray(v) ? v.slice() : [], offered);
            } else if (NUMERIC.indexOf(k) >= 0) {
                out[k] = normNumber(v);
            } else {
                out[k] = v == null ? '' : String(v);
            }
        });
        return out;
    }

    function fromState(state, cookies, ctx) {
        var o = { mode: state.mode === 'true' ? 'true' : 'false', tab: state.tab === 'sealed' ? 'sealed' : 'singles' };
        var raw = cookies('UploadOptimizerOpts');
        var flags = (raw === null || raw === '') ? FLAG_DEFAULTS : splitList(raw);
        FLAG_KEYS.forEach(function (k) { if (flags.indexOf(k) >= 0) o[k] = 'true'; });
        TEXTS.forEach(function (t) { o[t[0]] = cookies(t[1]) || t[2]; });
        if (splitList(cookies('UploadCustomOpts')).indexOf('enabled') >= 0) {
            o.custombuylist = 'true';
            CUSTOM.forEach(function (t) { o[t[0]] = cookies(t[1]) || t[2]; });
        }
        if (ctx && ctx.canChangeStores) {
            STORE_LISTS.forEach(function (k) { o[k] = (state[k] || []).slice(); });
        }
        return canonical(o, ctx);
    }

    function equal(a, b) {
        var ka = Object.keys(a).sort(), kb = Object.keys(b).sort();
        if (ka.length !== kb.length) return false;
        for (var i = 0; i < ka.length; i++) {
            var k = ka[i];
            if (k !== kb[i]) return false;
            var va = a[k], vb = b[k];
            if (Array.isArray(va) || Array.isArray(vb)) {
                if (!Array.isArray(va) || !Array.isArray(vb) || va.length !== vb.length) return false;
                for (var j = 0; j < va.length; j++) if (va[j] !== vb[j]) return false;
            } else if (va !== vb) {
                return false;
            }
        }
        return true;
    }

    function findMatch(opts, presets) {
        for (var i = 0; i < presets.length; i++) {
            if (presets[i] && presets[i].opts && equal(opts, presets[i].opts)) return presets[i];
        }
        return null;
    }

    var KEY = 'mtgban_upload_presets';
    var CAP = 10;
    var memory = null; // the list when storage cannot be read or written

    function readAll() {
        if (memory) return memory.slice();
        try {
            var raw = localStorage.getItem(KEY);
            var list = raw ? JSON.parse(raw) : [];
            return Array.isArray(list) ? list.filter(function (p) { return p && p.id && p.name && p.opts; }) : [];
        } catch (e) { return []; }
    }
    function writeAll(list) {
        list.sort(function (a, b) { return a.name.toLowerCase() < b.name.toLowerCase() ? -1 : a.name.toLowerCase() > b.name.toLowerCase() ? 1 : 0; });
        try {
            localStorage.setItem(KEY, JSON.stringify(list));
            memory = null;
            return true;
        } catch (e) {
            memory = list;
            return false;
        }
    }
    function newId() { return 'p_' + Math.random().toString(36).slice(2, 10); }

    var store = {
        list: function () { return readAll().sort(function (a, b) { return a.name.toLowerCase() < b.name.toLowerCase() ? -1 : a.name.toLowerCase() > b.name.toLowerCase() ? 1 : 0; }); },
        newId: newId,
        save: function (p) {
            var list = readAll();
            var idx = -1;
            for (var i = 0; i < list.length; i++) if (list[i].id === p.id) idx = i;
            var rec = { id: p.id || newId(), name: String(p.name), savedAt: Date.now(), opts: canonical(p.opts) };
            if (idx >= 0) list[idx] = rec;
            else if (list.length >= CAP) return { ok: false, reason: 'cap' };
            else list.push(rec);
            var ok = writeAll(list);
            return ok ? { ok: true, preset: rec } : { ok: false, reason: 'storage' };
        },
        rename: function (id, name) {
            var list = readAll(), hit = false;
            list.forEach(function (p) { if (p.id === id) { p.name = String(name); hit = true; } });
            return hit && writeAll(list);
        },
        remove: function (id) {
            var list = readAll(), next = list.filter(function (p) { return p.id !== id; });
            return next.length !== list.length && writeAll(next);
        },
    };

    var GRIDS = { stores: 'singlesBox', sealed_stores: 'sealedBox', index_stores: 'singlesIndexRow', sealed_index_stores: 'sealedIndexRow' };

    function boxes(doc, id) {
        var el = doc.getElementById(id);
        return el ? Array.prototype.slice.call(el.querySelectorAll('input[type="checkbox"]')) : [];
    }
    function readMode(doc) {
        var form = doc.getElementById('upload_form');
        var radios = form ? Array.prototype.slice.call(form.querySelectorAll('input[name="mode"]')) : [];
        for (var i = 0; i < radios.length; i++) if (radios[i].checked) return radios[i].value === 'true' ? 'true' : 'false';
        return 'false';
    }
    function readTab(doc) {
        var t = doc.getElementById('tab-sealed');
        return t && t.classList.contains('active') ? 'sealed' : 'singles';
    }
    function readState(doc) {
        var s = { mode: readMode(doc), tab: readTab(doc) };
        STORE_LISTS.forEach(function (k) {
            s[k] = boxes(doc, GRIDS[k]).filter(function (b) { return b.checked; }).map(function (b) { return b.value; });
        });
        return s;
    }
    function readCtx(doc) {
        var form = doc.getElementById('upload_form');
        var ctx = { canChangeStores: !!(form && form.dataset && form.dataset.canChangeStores === 'true'), offered: {} };
        STORE_LISTS.forEach(function (k) { ctx.offered[k] = boxes(doc, GRIDS[k]).map(function (b) { return b.value; }); });
        return ctx;
    }
    function current(doc) { return fromState(readState(doc), getCookie, readCtx(doc)); }

    // persistStores writes the store cookies the upload handler reads (#213).
    // only, when given, limits the write to those STORE_LISTS keys.
    function persistStores(doc, only) {
        var ctx = readCtx(doc);
        if (!ctx.canChangeStores) return {};
        var buylist = readMode(doc) === 'true';
        var names = {
            stores: buylist ? 'enabledVendors' : 'enabledSellers',
            sealed_stores: buylist ? 'enabledSealedVendors' : 'enabledSealedSellers',
            index_stores: 'enabledIndexes',
            sealed_index_stores: 'enabledSealedIndexes',
        };
        var keys = only || STORE_LISTS;
        var state = readState(doc), out = {};
        keys.forEach(function (k) {
            out[names[k]] = state[k].join('|');
            setCookie(names[k], out[names[k]], 3650);
        });
        return out;
    }

    function applyCookies(opts) {
        var flags = FLAG_KEYS.filter(function (k) { return opts[k] === 'true'; });
        setCookie('UploadOptimizerOpts', flags.join(',') + (flags.length ? ',' : ''), 1000);
        TEXTS.forEach(function (t) { setCookie(t[1], opts[t[0]] == null ? t[2] : opts[t[0]], 1000); });
        if (opts.custombuylist === 'true') {
            setCookie('UploadCustomOpts', 'enabled,', 1000);
            CUSTOM.forEach(function (t) { setCookie(t[1], opts[t[0]] == null ? t[2] : opts[t[0]], 1000); });
        } else {
            setCookie('UploadCustomOpts', '', 1000);
        }
    }

    // apply never submits and leaves the file, text and URL inputs alone.
    function apply(preset, doc) {
        var opts = preset.opts || {};
        applyCookies(opts);
        var form = doc.getElementById('upload_form');
        var radios = form ? Array.prototype.slice.call(form.querySelectorAll('input[name="mode"]')) : [];
        var trueRadio = null;
        for (var i = 0; i < radios.length; i++) if (radios[i].value === 'true') trueRadio = radios[i];
        // a disabled Buylist radio (no .CanBuylist) falls back to retail, matching the server (upload.go)
        var modeForced = opts.mode === 'true' && !!(trueRadio && trueRadio.disabled);
        var mode = (opts.mode === 'true' && !modeForced) ? 'true' : 'false';
        radios.forEach(function (r) { r.checked = (r.value === 'true') === (mode === 'true'); });
        if (window.reloadSelect) window.reloadSelect(mode === 'true' ? 'buylist' : 'retail');
        if (window.selectTab) window.selectTab(opts.tab === 'sealed' ? 'sealed' : 'singles');
        var unavailable = [];
        var seenUnavailable = {};
        var ctx = readCtx(doc);
        var storesSkipped = false;
        if (ctx.canChangeStores) {
            // A forced-retail fallback means the preset's seller/vendor picks don't
            // apply to this mode: leave stores/sealed_stores untouched and unpersisted,
            // index lists still apply normally.
            var applyLists = modeForced ? ['index_stores', 'sealed_index_stores'] : STORE_LISTS;
            applyLists.forEach(function (k) {
                if (!Array.isArray(opts[k])) return;
                var want = opts[k];
                var seen = {};
                boxes(doc, GRIDS[k]).forEach(function (b) { seen[b.value] = true; b.checked = want.indexOf(b.value) >= 0; });
                want.forEach(function (v) {
                    if (!seen[v] && !seenUnavailable[v]) { seenUnavailable[v] = true; unavailable.push(v); }
                });
            });
            persistStores(doc, modeForced ? ['index_stores', 'sealed_index_stores'] : null);
        } else {
            storesSkipped = STORE_LISTS.some(function (k) { return Array.isArray(opts[k]) && opts[k].length > 0; });
        }
        return { unavailableStores: unavailable, storesSkipped: storesSkipped };
    }

    // decideSave picks empty, duplicate, update or create, in that order.
    function decideSave(args) {
        var name = String(args.name || '').trim();
        if (!name) return { action: 'empty' };
        var presets = args.presets || [];
        var byName = null;
        presets.forEach(function (p) { if (p.name.toLowerCase() === name.toLowerCase()) byName = p; });
        var same = findMatch(args.current, presets);
        if (same && (!byName || same.id !== byName.id)) return { action: 'duplicate', preset: same };
        if (byName) return { action: 'update', preset: byName };
        return { action: 'create' };
    }

    function el(doc, id) { return doc.getElementById(id); }
    function text(node, s) { if (node) node.textContent = s; }

    // mount wires the preset row, the save row and store persistence on the upload page.
    function mount(doc) {
        var form = el(doc, 'upload_form');
        var select = el(doc, 'preset-select');
        if (!form || !select) return;
        var note = el(doc, 'preset-note');
        var nameInput = el(doc, 'preset-name');
        var saveRow = el(doc, 'preset-save-row');
        var saveBtn = el(doc, 'preset-save');
        var renameBtn = el(doc, 'preset-rename');
        var deleteBtn = el(doc, 'preset-delete');
        // The settings modal's Save always reloads this page (settings.js has
        // no reprocessUploadResults here), which would otherwise drop which
        // preset was selected right as a changed setting needs to show against
        // it. sessionStorage survives that reload without outliving the tab.
        var SEL_KEY = 'mtgban_upload_selected_preset';
        var selectedId = null;
        try { selectedId = sessionStorage.getItem(SEL_KEY); } catch (e) { /* ignore */ }
        function setSelected(id) {
            selectedId = id;
            try {
                if (id) sessionStorage.setItem(SEL_KEY, id);
                else sessionStorage.removeItem(SEL_KEY);
            } catch (e) { /* ignore */ }
        }

        function render() {
            var presets = store.list();
            var cur = current(doc);
            var match = findMatch(cur, presets);
            if (match) setSelected(match.id);
            var selected = null;
            presets.forEach(function (p) { if (p.id === selectedId) selected = p; });
            select.innerHTML = '';
            var head = doc.createElement('option');
            head.value = '';
            head.textContent = presets.length ? 'Presets' : 'No presets yet';
            select.appendChild(head);
            presets.forEach(function (p) {
                var o = doc.createElement('option');
                o.value = p.id;
                o.textContent = p.name + (selected && p.id === selected.id && !match ? ' (modified)' : '');
                if (selected && p.id === selected.id) o.selected = true;
                select.appendChild(o);
            });
            var has = !!selected;
            if (renameBtn) renameBtn.disabled = !has;
            if (deleteBtn) deleteBtn.disabled = !has;
            // While the save row is open the label tracks what typing the name
            // would do, not just the current selection: an existing name updates
            // even with no preset selected, and a new name creates even while one
            // is "(modified)". Closed, it just reflects the current match.
            if (saveBtn) {
                if (saveRow && !saveRow.hidden) {
                    var d = decideSave({ name: nameInput ? nameInput.value : '', current: cur, presets: presets });
                    saveBtn.textContent = d.action === 'update' ? 'Update ' + d.preset.name : 'Save';
                } else {
                    saveBtn.textContent = selected && !match ? 'Update ' + selected.name : 'Save';
                }
            }
        }

        select.addEventListener('change', function () {
            var id = select.value;
            var presets = store.list(), hit = null;
            presets.forEach(function (p) { if (p.id === id) hit = p; });
            if (!hit) { setSelected(null); render(); return; }
            setSelected(hit.id);
            var res = apply(hit, doc);
            var msg = '';
            if (res.storesSkipped) {
                msg = 'Store selection not applied for your tier';
            } else if (res.unavailableStores.length) {
                msg = res.unavailableStores.length + ' store' + (res.unavailableStores.length === 1 ? '' : 's') + ' unavailable on this page';
            }
            text(note, msg);
            render();
        });

        var toggle = el(doc, 'preset-save-toggle');
        var cancelBtn = el(doc, 'preset-cancel');

        // Hides the save row and returns focus to the toggle that opened it,
        // whether it closed via Save, Cancel or Escape.
        function closeSaveRow() {
            saveRow.hidden = true;
            if (toggle) {
                toggle.setAttribute('aria-expanded', 'false');
                toggle.focus();
            }
        }

        if (toggle) toggle.addEventListener('click', function () {
            var opening = saveRow.hidden;
            saveRow.hidden = !opening;
            toggle.setAttribute('aria-expanded', opening ? 'true' : 'false');
            if (opening) {
                var presets = store.list(), sel = null;
                presets.forEach(function (p) { if (p.id === selectedId) sel = p; });
                nameInput.value = sel ? sel.name : '';
                nameInput.focus();
                render();
            }
        });

        if (cancelBtn) cancelBtn.addEventListener('click', closeSaveRow);

        // Enter saves instead of submitting the upload form; Escape backs out.
        if (nameInput) nameInput.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                if (saveBtn) saveBtn.click();
            } else if (e.key === 'Escape') {
                closeSaveRow();
            }
        });

        // Keeps the Save label in step with what typing the name would do;
        // see the comment on render's own label logic.
        if (nameInput) nameInput.addEventListener('input', render);

        if (saveBtn) saveBtn.addEventListener('click', function () {
            var presets = store.list();
            var cur = current(doc);
            var d = decideSave({ name: nameInput.value, current: cur, presets: presets, selectedId: selectedId });
            if (d.action === 'empty') { text(note, 'Give the preset a name'); return; }
            if (d.action === 'duplicate') { text(note, 'These settings are already saved as ' + d.preset.name); setSelected(d.preset.id); render(); return; }
            var r = store.save({ id: d.action === 'update' ? d.preset.id : undefined, name: nameInput.value.trim(), opts: cur });
            if (!r.ok) { text(note, r.reason === 'cap' ? 'You can keep 10 presets; delete one first' : 'Could not save: browser storage is unavailable'); return; }
            setSelected(r.preset.id);
            closeSaveRow();
            text(note, d.action === 'update' ? 'Updated ' + r.preset.name : 'Saved ' + r.preset.name);
            render();
        });

        if (renameBtn) renameBtn.addEventListener('click', function () {
            var presets = store.list(), sel = null;
            presets.forEach(function (p) { if (p.id === selectedId) sel = p; });
            if (!sel) return;
            var name = window.prompt ? window.prompt('Rename preset', sel.name) : null;
            if (!name || !name.trim()) return;
            name = name.trim().slice(0, 40);
            var clash = null;
            presets.forEach(function (p) { if (p.id !== sel.id && p.name.toLowerCase() === name.toLowerCase()) clash = p; });
            if (clash) { text(note, 'A preset named ' + clash.name + ' already exists'); return; }
            if (!store.rename(sel.id, name)) { text(note, 'Could not rename: browser storage is unavailable'); return; }
            render();
        });
        if (deleteBtn) deleteBtn.addEventListener('click', function () {
            var presets = store.list(), sel = null;
            presets.forEach(function (p) { if (p.id === selectedId) sel = p; });
            if (!sel) return;
            if (!window.confirm || window.confirm('Delete preset ' + sel.name + '?')) { store.remove(sel.id); setSelected(null); render(); }
        });

        // Store checkboxes persist on change (#213). Bulk actions (Select all,
        // Clear, only/exclude) set .checked without a real click, so they
        // dispatch a CustomEvent on the form with detail.stores to say so; a
        // tab switch dispatches a plain change event and does not persist, so
        // a reader who never customised stores doesn't get them frozen in.
        form.addEventListener('change', function (e) {
            var t = e.target;
            var fromGrid = t && t.closest && t.closest('#singlesBox, #sealedBox, #singlesIndexRow, #sealedIndexRow');
            var fromFormDetail = t === form && e.detail && e.detail.stores;
            if (fromGrid || fromFormDetail) persistStores(doc);
            render();
        });
        // Catches live edits a change event would miss, debounced so typing
        // doesn't re-render on every keystroke.
        var renderTimer = null;
        form.addEventListener('input', function () {
            clearTimeout(renderTimer);
            renderTimer = setTimeout(render, 150);
        });
        render();
    }

    window.UploadPresets = {
        OPTION_DEFAULTS: OPTION_DEFAULTS, FLAG_KEYS: FLAG_KEYS, STORE_LISTS: STORE_LISTS,
        TEXTS: TEXTS, CUSTOM: CUSTOM,
        canonical: canonical, fromState: fromState, equal: equal, findMatch: findMatch,
        store: store,
        readState: readState, readCtx: readCtx, current: current, persistStores: persistStores, apply: apply,
        decideSave: decideSave, mount: mount,
    };
})();
