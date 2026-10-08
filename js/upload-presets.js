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

    // shown is a preset as this page can show it: the stores it offers, none
    // for a tier that cannot change them, and under forced retail the page's
    // own mode and seller picks. A list the preset lacks takes the page's ticks.
    function shown(opts, cur, ctx) {
        var o = {};
        Object.keys(opts).forEach(function (k) {
            if (ctx.canChangeStores || STORE_LISTS.indexOf(k) < 0) o[k] = opts[k];
        });
        if (ctx.canChangeStores) {
            STORE_LISTS.forEach(function (k) { if (!Array.isArray(o[k]) && k in cur) o[k] = cur[k]; });
        }
        if (ctx.buylistOff && o.mode === 'true') {
            o.mode = 'false';
            ['stores', 'sealed_stores'].forEach(function (k) {
                if (k in cur) o[k] = cur[k];
                else delete o[k];
            });
        }
        return canonical(o, ctx);
    }

    // findMatch returns the first preset equal to opts, or preferId's when it is
    // equal too. With ctx, presets are compared as the page can show them.
    function findMatch(opts, presets, ctx, preferId) {
        function same(p) { return p && p.opts && equal(opts, ctx ? shown(p.opts, opts, ctx) : p.opts); }
        for (var j = 0; preferId && j < presets.length; j++) {
            if (presets[j] && presets[j].id === preferId) {
                if (same(presets[j])) return presets[j];
                break;
            }
        }
        for (var i = 0; i < presets.length; i++) {
            if (same(presets[i])) return presets[i];
        }
        return null;
    }

    var KEY = 'mtgban_upload_presets';
    // CAP bounds what this device adds; a merge with another device's list
    // keeps every preset, so more can be listed than may be added.
    var CAP = 10;
    // A deleted preset stays behind as {id, del, savedAt} for this long, so
    // the delete syncs to other devices rather than the preset coming back.
    var TOMB_TTL_MS = 30 * 24 * 60 * 60 * 1000;

    function byName(a, b) { return a.name.toLowerCase() < b.name.toLowerCase() ? -1 : a.name.toLowerCase() > b.name.toLowerCase() ? 1 : 0; }

    function readRaw() {
        try {
            var raw = localStorage.getItem(KEY);
            var list = raw ? JSON.parse(raw) : [];
            return Array.isArray(list) ? list.filter(function (p) { return p && p.id; }) : [];
        } catch (e) { return []; }
    }
    function readAll() {
        return readRaw().filter(function (p) { return !p.del && p.name && p.opts; });
    }
    // tombstones keeps the unexpired deletes of ids not live in list.
    function tombstones(list) {
        var live = {}, now = Date.now();
        list.forEach(function (p) { live[p.id] = true; });
        return readRaw().filter(function (p) { return p.del && !live[p.id] && now - (p.savedAt || 0) <= TOMB_TTL_MS; });
    }
    // A full or missing store drops the write, as list-storage.js does.
    function writeAll(list, deleted) {
        list.sort(byName);
        var tombs = tombstones(list);
        if (deleted) tombs.push({ id: deleted, del: true, savedAt: Date.now() });
        try {
            localStorage.setItem(KEY, JSON.stringify(list.concat(tombs)));
            return true;
        } catch (e) {
            return false;
        }
    }
    function newId() { return 'p_' + Math.random().toString(36).slice(2, 10); }

    var store = {
        list: function () { return readAll().sort(byName); },
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
        // rename and remove return 'missing' for an id that is gone, else whether storage took the write.
        rename: function (id, name) {
            var list = readAll(), hit = false;
            list.forEach(function (p) { if (p.id === id) { p.name = String(name); p.savedAt = Date.now(); hit = true; } });
            return hit ? writeAll(list) : 'missing';
        },
        remove: function (id) {
            var list = readAll(), next = list.filter(function (p) { return p.id !== id; });
            return next.length !== list.length ? writeAll(next, id) : 'missing';
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
        var ctx = { canChangeStores: !!(form && form.dataset && form.dataset.canChangeStores === 'true'), offered: {}, buylistOff: buylistDisabled(doc) };
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

    // forUpdate merges the page into an existing preset, keeping what the page
    // could not show: stores it does not offer, all lists for a tier that cannot
    // change stores, and a buylist preset's mode and picks under forced retail.
    function forUpdate(cur, old, ctx) {
        var out = {};
        Object.keys(cur).forEach(function (k) { out[k] = cur[k]; });
        // The seller and vendor grids differ, so after a mode switch the old
        // mode's stores are not hidden here, just from the other grid.
        var sameMode = (old.mode === 'true') === (cur.mode === 'true');
        STORE_LISTS.forEach(function (k) {
            var was = Array.isArray(old[k]) ? old[k] : null;
            if (!ctx.canChangeStores) {
                if (was) out[k] = was.slice();
                return;
            }
            if (!sameMode && (k === 'stores' || k === 'sealed_stores')) was = null;
            var offered = ctx.offered[k] || [];
            var hidden = (was || []).filter(function (s) { return offered.indexOf(s) < 0; });
            out[k] = (cur[k] || []).concat(hidden);
        });
        if (ctx.buylistOff && old.mode === 'true') {
            out.mode = old.mode;
            ['stores', 'sealed_stores'].forEach(function (k) {
                if (Array.isArray(old[k])) out[k] = old[k].slice();
                else delete out[k];
            });
        }
        return out;
    }
    function buylistDisabled(doc) {
        var form = doc.getElementById('upload_form');
        var radios = form ? Array.prototype.slice.call(form.querySelectorAll('input[name="mode"]')) : [];
        return radios.some(function (r) { return r.value === 'true' && r.disabled; });
    }

    // decideSave picks empty, duplicate, update or create, in that order.
    function decideSave(args) {
        var name = String(args.name || '').trim();
        if (!name) return { action: 'empty' };
        var presets = args.presets || [];
        var byName = null;
        presets.forEach(function (p) { if (p.name.toLowerCase() === name.toLowerCase()) byName = p; });
        // Exact, not as the page shows it: settings that save differently are a new preset.
        var same = findMatch(args.current, presets, null, args.selectedId);
        if (same && (!byName || same.id !== byName.id)) return { action: 'duplicate', preset: same };
        if (byName) return { action: 'update', preset: byName };
        return { action: 'create' };
    }

    function el(doc, id) { return doc.getElementById(id); }
    function text(node, s) { if (node) node.textContent = s; }

    var mountedRender = null;

    // refresh re-reads the list and redraws the mounted row, e.g. after a sync.
    function refresh() { if (mountedRender) mountedRender(); }

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

        // Set while apply runs: selectTab's change would match the half-applied form.
        var applying = false;
        var renderedKey = null;

        function render() {
            if (applying) return;
            var presets = store.list();
            var cur = current(doc);
            var ctx = readCtx(doc);
            var match = findMatch(cur, presets, ctx, selectedId);
            if (match) setSelected(match.id);
            var selected = null;
            presets.forEach(function (p) { if (p.id === selectedId) selected = p; });
            var rows = [['', presets.length ? 'Presets' : 'No presets yet']];
            presets.forEach(function (p) {
                rows.push([p.id, p.name + (selected && p.id === selected.id && !match ? ' (modified)' : '')]);
            });
            var want = selected ? selected.id : '';
            // Rebuilding closes an open dropdown, so skip it when nothing would change.
            var key = JSON.stringify([rows, want]);
            if (key !== renderedKey || select.value !== want) {
                renderedKey = key;
                select.innerHTML = '';
                rows.forEach(function (r) {
                    var o = doc.createElement('option');
                    o.value = r[0];
                    o.textContent = r[1];
                    if (r[0] && r[0] === want) o.selected = true;
                    select.appendChild(o);
                });
            }
            var has = !!selected;
            if (renameBtn) renameBtn.disabled = !has;
            if (deleteBtn) deleteBtn.disabled = !has;
            // While the save row is open the label tracks what typing the name
            // would do, not just the current selection: an existing name updates
            // even with no preset selected, and a new name creates even while one
            // is "(modified)". Closed, it just reflects the current match.
            if (saveBtn) {
                if (saveRow && !saveRow.hidden) {
                    var d = decideSave({ name: nameInput ? nameInput.value : '', current: cur, presets: presets, selectedId: selectedId });
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
            var res;
            applying = true;
            try { res = apply(hit, doc); } finally { applying = false; }
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
            var ctx = readCtx(doc);
            var d = decideSave({ name: nameInput.value, current: cur, presets: presets, selectedId: selectedId });
            if (d.action === 'empty') { text(note, 'Give the preset a name'); return; }
            if (d.action === 'duplicate') { text(note, 'These settings are already saved as ' + d.preset.name); setSelected(d.preset.id); render(); return; }
            var opts = d.action === 'update' ? forUpdate(cur, d.preset.opts || {}, ctx) : cur;
            var r = store.save({ id: d.action === 'update' ? d.preset.id : undefined, name: nameInput.value.trim(), opts: opts });
            if (!r.ok) { text(note, r.reason === 'cap' ? 'You can keep 10 presets; delete one first' : 'Could not save: browser storage is unavailable'); return; }
            setSelected(r.preset.id);
            closeSaveRow();
            text(note, d.action === 'update' ? 'Updated ' + r.preset.name : 'Saved ' + r.preset.name);
            render();
        });

        // Another tab deleted the preset while a prompt or confirm was open.
        function gone() {
            text(note, 'That preset no longer exists');
            setSelected(null);
            render();
        }

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
            var r = store.rename(sel.id, name);
            if (r === 'missing') { gone(); return; }
            if (!r) { text(note, 'Could not rename: browser storage is unavailable'); return; }
            render();
        });
        if (deleteBtn) deleteBtn.addEventListener('click', function () {
            var presets = store.list(), sel = null;
            presets.forEach(function (p) { if (p.id === selectedId) sel = p; });
            if (!sel) return;
            if (window.confirm && !window.confirm('Delete preset ' + sel.name + '?')) return;
            var r = store.remove(sel.id);
            if (r === 'missing') { gone(); return; }
            if (!r) { text(note, 'Could not delete: browser storage is unavailable'); return; }
            setSelected(null);
            render();
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
        mountedRender = render;
        render();
    }

    window.UploadPresets = {
        OPTION_DEFAULTS: OPTION_DEFAULTS, FLAG_KEYS: FLAG_KEYS, STORE_LISTS: STORE_LISTS,
        TEXTS: TEXTS, CUSTOM: CUSTOM,
        canonical: canonical, fromState: fromState, equal: equal, findMatch: findMatch,
        store: store,
        readState: readState, readCtx: readCtx, current: current, persistStores: persistStores, apply: apply,
        decideSave: decideSave, mount: mount, refresh: refresh,
    };
})();
