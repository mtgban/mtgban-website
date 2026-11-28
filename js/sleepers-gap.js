// The Ocean Gap pairs a reader saved from the Custom Comparison, each one
// click under the built-in presets. Kept in localStorage, which user-state.js
// syncs to the reader's other devices, one list per game. sleep.html loads
// it only for readers who may build a custom pair.
(function () {
    var KEY = 'mtgban_sleepers_gap_pairs';
    // How many pairs a game keeps; user-state.js merges to the same cap
    var CAP = 10;
    // A removed pair stays behind as {id, del, savedAt} for this long, so
    // the removal syncs to other devices rather than the pair coming back.
    var TOMB_TTL_MS = 30 * 24 * 60 * 60 * 1000;

    var game = (document.body && document.body.dataset.game) || '';

    // On the server's clock once a sync has read it (user-state.js)
    function now() {
        return window.UserState ? window.UserState.now() : Date.now();
    }
    function later(a, b) {
        return window.UserState ? window.UserState.later(a, b) : (a || 0) > (b || 0);
    }

    function readRaw() {
        try {
            var list = JSON.parse(localStorage.getItem(KEY) || '[]');
            return Array.isArray(list) ? list.filter(function (p) { return p && p.id; }) : [];
        } catch (e) {
            return [];
        }
    }

    function isLive(p) {
        return !p.del && p.game === game && typeof p.ref === 'string' && typeof p.target === 'string';
    }

    // A full or missing store drops the write.
    function writeRaw(list) {
        var at = now();
        list = list.filter(function (p) { return !p.del || at - (p.savedAt || 0) <= TOMB_TTL_MS; });
        try {
            localStorage.setItem(KEY, JSON.stringify(list));
            return true;
        } catch (e) {
            return false;
        }
    }

    function pairId(ref, target) { return game + ':' + ref + '>' + target; }

    var store = {
        // list is this game's pairs, newest first.
        list: function () {
            return readRaw().filter(isLive).sort(function (a, b) {
                if (later(a.savedAt, b.savedAt)) return -1;
                if (later(b.savedAt, a.savedAt)) return 1;
                return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
            });
        },
        has: function (ref, target) {
            var id = pairId(ref, target);
            return store.list().some(function (p) { return p.id === id; });
        },
        // save answers true, or why not: 'invalid', 'saved', 'full', 'storage'.
        save: function (ref, target) {
            if (!game || !ref || !target || ref === target) return 'invalid';
            if (store.has(ref, target)) return 'saved';
            if (store.list().length >= CAP) return 'full';
            var id = pairId(ref, target);
            var raw = readRaw();
            var prev = raw.filter(function (p) { return p.id === id; })[0];
            // Past a removal of the same pair, which may run ahead of the clock
            var stamp = Math.max(now(), prev ? (prev.savedAt || 0) + 1 : 0);
            raw = raw.filter(function (p) { return p.id !== id; });
            raw.push({ id: id, game: game, ref: ref, target: target, savedAt: stamp });
            return writeRaw(raw) || 'storage';
        },
        remove: function (id) {
            var raw = readRaw();
            var prev = raw.filter(function (p) { return p.id === id && isLive(p); })[0];
            if (!prev) return false;
            raw = raw.filter(function (p) { return p.id !== id; });
            raw.push({ id: id, del: true, savedAt: Math.max(now(), (prev.savedAt || 0) + 1) });
            return writeRaw(raw);
        },
    };

    function q(sel) { return document.querySelector(sel); }

    // The stores' names, by shorthand, as the form offers them
    function storeNames() {
        var names = {};
        var sel = q('[data-gap-form] select[name="ref"]');
        if (!sel) return names;
        for (var i = 0; i < sel.options.length; i++) {
            var o = sel.options[i];
            if (o.value) names[o.value] = o.textContent.trim();
        }
        return names;
    }

    function render() {
        var box = q('[data-gap-saved]');
        var tpl = q('template[data-gap-row]');
        if (!box || !tpl) return;
        var names = storeNames();
        box.textContent = '';
        store.list().forEach(function (p) {
            // A store this page does not offer keeps its row, by shorthand,
            // so that the pair can still be removed to free its slot
            var ref = names[p.ref] || p.ref, target = names[p.target] || p.target;
            var row = tpl.content.firstElementChild.cloneNode(true);
            row.dataset.gapId = p.id;
            row.querySelector('[data-gap-link]').href = '?page=gap&ref=' + encodeURIComponent(p.ref) + '&target=' + encodeURIComponent(p.target);
            row.querySelector('[data-gap-ref]').textContent = ref;
            row.querySelector('[data-gap-target]').textContent = target;
            row.querySelector('[data-gap-remove]').setAttribute('aria-label', 'Remove ' + ref + ' vs ' + target);
            box.appendChild(row);
        });
        box.hidden = !box.firstElementChild;
    }

    // Compare needs two different stores; Save also a pair not yet kept
    function check() {
        var form = q('[data-gap-form]');
        if (!form) return;
        var ref = form.querySelector('select[name="ref"]').value;
        var target = form.querySelector('select[name="target"]').value;
        var valid = !!(ref && target && ref !== target);
        var go = form.querySelector('[data-gap-go]');
        if (go) go.disabled = !valid;
        var save = form.querySelector('[data-gap-save]');
        if (!save) return;
        var saved = valid && store.has(ref, target);
        var full = store.list().length >= CAP;
        save.disabled = !valid || saved || full;
        save.textContent = saved ? '★ Saved' : '☆ Save';
        save.title = saved ? 'Already in your comparisons' : full ? CAP + ' saved — remove one' : 'Keep this pair under the presets';
    }

    function refresh() {
        render();
        check();
    }

    function init() {
        var form = q('[data-gap-form]');
        if (form) {
            form.querySelectorAll('select').forEach(function (s) { s.addEventListener('change', check); });
            var save = form.querySelector('[data-gap-save]');
            if (save) {
                save.addEventListener('click', function () {
                    store.save(form.querySelector('select[name="ref"]').value, form.querySelector('select[name="target"]').value);
                    refresh();
                });
            }
        }
        var box = q('[data-gap-saved]');
        if (box) {
            box.addEventListener('click', function (e) {
                var btn = e.target.closest('[data-gap-remove]');
                if (!btn) return;
                e.preventDefault();
                store.remove(btn.closest('[data-gap-id]').dataset.gapId);
                refresh();
            });
        }
        refresh();
    }

    window.SleepersGap = { store: store, refresh: refresh };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
