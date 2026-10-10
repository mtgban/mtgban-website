// The arbitrage pages' filter presets: the filter bar saved under a name and
// picked from the Preset select. Kept in localStorage, which user-state.js
// syncs to the reader's other devices; one list for Arbit and Reverse, one
// for Global, as for the saved filters. arbit.html sets window.BAN_ARBIT.
(function () {
    var cfg = window.BAN_ARBIT || {};

    var KEY = 'mtgban_arbit_presets';
    // How many presets a page group keeps
    var CAP = 10;
    // A deleted preset stays behind as {id, del, savedAt} for this long, so
    // the delete syncs to other devices rather than the preset coming back.
    var TOMB_TTL_MS = 30 * 24 * 60 * 60 * 1000;
    var SEL_KEY = 'mtgban_arbit_selected_preset';

    var group = cfg.cookie === 'GlobalFilters' ? 'global' : 'arbit';

    // The built-in preset: the page's own defaults. It is never stored, so
    // nothing can overwrite, rename or delete it, and its name is reserved.
    var DEFAULT = { id: 'default', name: 'Default', q: 'f=1' };

    function reserved(name) { return String(name).trim().toLowerCase() === DEFAULT.name.toLowerCase(); }

    function byName(a, b) {
        var x = a.name.toLowerCase(), y = b.name.toLowerCase();
        return x < y ? -1 : x > y ? 1 : 0;
    }

    function readRaw() {
        try {
            var list = JSON.parse(localStorage.getItem(KEY) || '[]');
            return Array.isArray(list) ? list.filter(function (p) { return p && p.id; }) : [];
        } catch (e) {
            return [];
        }
    }

    function readAll() {
        return readRaw().filter(function (p) {
            return !p.del && p.name && typeof p.q === 'string' && (p.group === 'arbit' || p.group === 'global');
        });
    }

    // tombstones keeps the unexpired deletes of ids not live in list.
    function tombstones(list) {
        var live = {}, now = Date.now();
        list.forEach(function (p) { live[p.id] = true; });
        return readRaw().filter(function (p) { return p.del && !live[p.id] && now - (p.savedAt || 0) <= TOMB_TTL_MS; });
    }

    // A full or missing store drops the write.
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
        // list is this page group's presets, by name.
        list: function () {
            return readAll().filter(function (p) { return p.group === group; }).sort(byName);
        },
        save: function (p) {
            var all = readAll();
            var idx = -1;
            for (var i = 0; i < all.length; i++) if (all[i].id === p.id) idx = i;
            var rec = { id: p.id || newId(), name: String(p.name), savedAt: Date.now(), group: group, q: String(p.q) };
            if (idx >= 0) {
                all[idx] = rec;
            } else if (store.list().length >= CAP) {
                return { ok: false, reason: 'cap' };
            } else {
                all.push(rec);
            }
            return writeAll(all) ? { ok: true, preset: rec } : { ok: false, reason: 'storage' };
        },
        // rename and remove return 'missing' for an id that is gone, else
        // whether storage took the write.
        rename: function (id, name) {
            var all = readAll(), hit = false;
            all.forEach(function (p) {
                if (p.id === id) { p.name = String(name); p.savedAt = Date.now(); hit = true; }
            });
            return hit ? writeAll(all) : 'missing';
        },
        remove: function (id) {
            var all = readAll(), next = all.filter(function (p) { return p.id !== id; });
            return next.length !== all.length ? writeAll(next, id) : 'missing';
        },
    };

    // normalize is a query as this page applies it: without the marker,
    // sort and save time, the keys the page does not apply, and every key at
    // the page's default, in key order. Two queries filtering this page the
    // same normalize the same.
    function normalize(q) {
        var ignored = cfg.ignored || [], defaults = cfg.defaults || {};
        var out = [];
        new URLSearchParams(q || '').forEach(function (v, k) {
            if (k === 'f' || k === 'sort' || k === 't') return;
            if (ignored.indexOf(k) >= 0) return;
            if (Object.prototype.hasOwnProperty.call(defaults, k) && defaults[k] === v) return;
            out.push([k, v]);
        });
        out.sort(function (a, b) { return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0; });
        return new URLSearchParams(out).toString();
    }

    // findMatch is the preset filtering as q does, the page's own state where
    // q is not given, preferId's where it is one.
    function findMatch(presets, preferId, q) {
        var page = normalize(q === undefined ? cfg.query : q);
        var hit = null;
        presets.forEach(function (p) {
            if (normalize(p.q) !== page) return;
            if (!hit || p.id === preferId) hit = p;
        });
        return hit;
    }

    // decideSave picks empty, duplicate, update or create, in that order, for
    // saving the filters q (the page's own where not given).
    function decideSave(name, presets, selectedId, q) {
        name = String(name || '').trim();
        if (!name) return { action: 'empty' };
        if (reserved(name)) return { action: 'reserved' };
        var named = null;
        presets.forEach(function (p) { if (p.name.toLowerCase() === name.toLowerCase()) named = p; });
        var same = findMatch(presets, selectedId, q);
        if (!same && normalize(q === undefined ? cfg.query : q) === '') same = DEFAULT;
        if (same && (!named || same.id !== named.id)) return { action: 'duplicate', preset: same };
        if (named) return { action: 'update', preset: named };
        return { action: 'create' };
    }

    // formState is the filter bar's form as the query the server would write
    // for it once applied (arbitState.values): a picker with every box
    // ticked left out, the others as one list in box order, numbers as
    // numbers, and the toggles the bar shows as 1 or 0.
    function formState(form) {
        var params = [['f', '1']];
        Array.prototype.forEach.call(form.querySelectorAll('[data-pick]'), function (group) {
            var boxes = Array.prototype.slice.call(group.querySelectorAll('input[type=checkbox]'));
            if (!boxes.length || boxes.every(function (b) { return b.checked; })) return;
            params.push([boxes[0].name, boxes.filter(function (b) { return b.checked; }).map(function (b) { return b.value; }).join(',')]);
        });
        Array.prototype.forEach.call(form.querySelectorAll('input[type=number]'), function (input) {
            var n = Number(input.value);
            if (input.value !== '' && isFinite(n)) params.push([input.name, String(n)]);
        });
        var shown = form.querySelector('input[name=toggles_on]');
        (shown ? shown.value.split(',') : []).forEach(function (key) {
            var box = key ? form.querySelector('input[type=checkbox][name="' + key + '"]') : null;
            if (box) params.push([key, box.checked ? '1' : '0']);
        });
        // The settings of options greyed for this source, kept as they were
        Array.prototype.forEach.call(form.querySelectorAll('input[data-carry]'), function (input) {
            params.push([input.name, input.value]);
        });
        params.sort(function (a, b) { return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0; });
        return new URLSearchParams(params).toString();
    }

    // presetURL is the page with a preset's filters and the page's own sort.
    function presetURL(p) {
        var sort = cfg.sort ? '&sort=' + encodeURIComponent(cfg.sort) : '';
        return '?source=' + encodeURIComponent(cfg.source || '') + '&' + p.q + sort;
    }

    // apply opens the page on a preset, saving it as the reader's filters
    // with the page's sort, as Apply would. A preset is read back out of
    // storage, which anything on the origin can write, so the URL is
    // checked (utils.js) rather than trusted before it becomes a navigation.
    function apply(p) {
        var url = sameSiteURL(presetURL(p));
        if (!url) return;
        var sort = cfg.sort ? '&sort=' + encodeURIComponent(cfg.sort) : '';
        if (window.ArbitFilters) window.ArbitFilters.save(p.q + sort);
        window.location.href = url;
    }

    var mountedRender = null;

    // refresh redraws the select, e.g. after a sync wrote the list.
    function refresh() { if (mountedRender) mountedRender(); }

    function mount(doc) {
        function el(id) { return doc.getElementById(id); }
        var box = el('arbPresetBox'), select = el('arbPresetSelect');
        if (!box || !select || !cfg.cookie) return;
        var controls = el('arbPresetControls'), note = el('arbPresetNote');
        var toggle = el('arbPresetSaveToggle'), saveRow = el('arbPresetSaveRow');
        var nameInput = el('arbPresetName'), saveBtn = el('arbPresetSave'), cancelBtn = el('arbPresetCancel');
        var renameBtn = el('arbPresetRename'), deleteBtn = el('arbPresetDelete');
        var form = el('arbFilters');
        box.hidden = false;
        if (controls) controls.hidden = false;

        function say(s) { if (note) note.textContent = s; }

        var selectedId = null;
        try { selectedId = sessionStorage.getItem(SEL_KEY); } catch (e) { /* ignore */ }
        function setSelected(id) {
            selectedId = id;
            try {
                if (id) sessionStorage.setItem(SEL_KEY, id);
                else sessionStorage.removeItem(SEL_KEY);
            } catch (e) { /* ignore */ }
        }

        // A preset saves the bar as it stands: the page's own state, or the
        // form's where it holds edits not yet applied, which saving applies.
        var formQuery = window.ArbitFilters && window.ArbitFilters.formQuery;
        var loaded = form && formQuery ? formQuery(form) : '';
        function dirty() { return !!(form && formQuery && formQuery(form) !== loaded); }
        function wanted() { return dirty() ? formState(form) : cfg.query; }

        var renderedKey = null;
        function render() {
            var presets = store.list();
            var match = findMatch(presets, selectedId);
            if (match) setSelected(match.id);
            var selected = null;
            presets.forEach(function (p) { if (p.id === selectedId) selected = p; });
            var rows = [['', 'Presets'], [DEFAULT.id, DEFAULT.name]];
            presets.forEach(function (p) {
                rows.push([p.id, p.name + (selected && p.id === selected.id && !match ? ' (modified)' : '')]);
            });
            var atDefault = !match && normalize(cfg.query) === '';
            var want = selected ? selected.id : atDefault ? DEFAULT.id : '';
            // Rebuilding closes an open dropdown, so skip it when nothing would change.
            var key = JSON.stringify([rows, want]);
            if (key !== renderedKey || select.value !== want) {
                renderedKey = key;
                select.innerHTML = '';
                rows.forEach(function (r) {
                    var o = doc.createElement('option');
                    o.value = r[0];
                    o.textContent = r[1];
                    // The placeholder labels the menu, as "Jump to…" does
                    // beside it, and is not a choice
                    if (!r[0]) o.disabled = true;
                    if (r[0] === want) o.selected = true;
                    select.appendChild(o);
                });
            }
            if (renameBtn) renameBtn.disabled = !selected;
            if (deleteBtn) deleteBtn.disabled = !selected;
            if (saveBtn && saveRow && !saveRow.hidden) {
                var d = decideSave(nameInput ? nameInput.value : '', presets, selectedId, wanted());
                saveBtn.textContent = d.action === 'update' ? 'Update ' + d.preset.name : 'Save';
            }
        }

        function applyForm() {
            if (form.requestSubmit) form.requestSubmit();
            else form.submit();
        }

        function closeSaveRow() {
            if (!saveRow) return;
            saveRow.hidden = true;
            if (toggle) toggle.setAttribute('aria-expanded', 'false');
        }

        select.addEventListener('change', function () {
            if (select.value === DEFAULT.id) {
                setSelected(null);
                apply(DEFAULT);
                return;
            }
            var hit = null;
            store.list().forEach(function (p) { if (p.id === select.value) hit = p; });
            if (!hit) { setSelected(null); render(); return; }
            setSelected(hit.id);
            apply(hit);
        });

        if (toggle) toggle.addEventListener('click', function () {
            var opening = saveRow.hidden;
            saveRow.hidden = !opening;
            toggle.setAttribute('aria-expanded', opening ? 'true' : 'false');
            if (!opening) return;
            var sel = null;
            store.list().forEach(function (p) { if (p.id === selectedId) sel = p; });
            nameInput.value = sel ? sel.name : '';
            nameInput.focus();
            render();
        });
        if (cancelBtn) cancelBtn.addEventListener('click', function () {
            closeSaveRow();
            if (toggle) toggle.focus();
        });
        if (nameInput) {
            nameInput.addEventListener('keydown', function (e) {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    if (saveBtn) saveBtn.click();
                } else if (e.key === 'Escape') {
                    closeSaveRow();
                    if (toggle) toggle.focus();
                }
            });
            nameInput.addEventListener('input', render);
        }

        if (saveBtn) saveBtn.addEventListener('click', function () {
            var unapplied = dirty();
            var q = wanted();
            var presets = store.list();
            var d = decideSave(nameInput.value, presets, selectedId, q);
            if (d.action === 'empty') { say('Give the preset a name'); return; }
            if (d.action === 'reserved') { say('Default is built in; pick another name'); return; }
            if (d.action === 'duplicate') {
                say('Already saved as ' + d.preset.name);
                setSelected(d.preset.id);
                // Edits that make an existing preset are applied, as a save
                // would, so the page shows that preset rather than modified
                if (unapplied) {
                    applyForm();
                    return;
                }
                render();
                return;
            }
            var r = store.save({ id: d.action === 'update' ? d.preset.id : undefined, name: nameInput.value.trim(), q: q });
            if (!r.ok) {
                say(r.reason === 'cap' ? 'You can keep ' + CAP + ' presets; delete one first' : 'Could not save: browser storage is unavailable');
                return;
            }
            setSelected(r.preset.id);
            closeSaveRow();
            say((d.action === 'update' ? 'Updated ' : 'Saved ') + r.preset.name);
            // The page shows what was just saved rather than calling it modified
            if (unapplied) {
                applyForm();
                return;
            }
            render();
        });

        // Another tab or device deleted the preset while a prompt was open.
        function gone() {
            say('That preset no longer exists');
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
            if (reserved(name)) { say('Default is built in; pick another name'); return; }
            var clash = null;
            presets.forEach(function (p) { if (p.id !== sel.id && p.name.toLowerCase() === name.toLowerCase()) clash = p; });
            if (clash) { say('A preset named ' + clash.name + ' already exists'); return; }
            var r = store.rename(sel.id, name);
            if (r === 'missing') { gone(); return; }
            if (!r) { say('Could not rename: browser storage is unavailable'); return; }
            render();
        });

        if (deleteBtn) deleteBtn.addEventListener('click', function () {
            var sel = null;
            store.list().forEach(function (p) { if (p.id === selectedId) sel = p; });
            if (!sel) return;
            if (window.confirm && !window.confirm('Delete preset ' + sel.name + '?')) return;
            var r = store.remove(sel.id);
            if (r === 'missing') { gone(); return; }
            if (!r) { say('Could not delete: browser storage is unavailable'); return; }
            setSelected(null);
            render();
        });

        if (form) {
            form.addEventListener('change', render);
            form.addEventListener('input', render);
        }
        // Back from a picked preset, a page the browser kept shows the select
        // as it was left: draw it again for the filters this page shows.
        window.addEventListener('pageshow', function (e) {
            if (!e.persisted) return;
            setSelected(null);
            render();
        });
        mountedRender = render;
        render();
    }

    window.ArbitPresets = {
        store: store, normalize: normalize, findMatch: findMatch, decideSave: decideSave, formState: formState,
        presetURL: presetURL, apply: apply, mount: mount, refresh: refresh,
    };
    mount(document);
})();
