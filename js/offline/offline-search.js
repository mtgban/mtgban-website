// Offline navbar search controller: local-data suggestions and in-place query.
(function () {
    'use strict';
    var self = typeof window !== 'undefined' ? window : globalThis;

    var MIN_CHARS = 3;
    var MAX_ROWS = 10;

    // Build display suggestion rows from the local name index and card store.
    function suggest(rawValue, deps) {
        var needle = deps.normName(rawValue);
        if (needle.length < MIN_CHARS) return Promise.resolve([]);
        return deps.allNames().then(function (names) {
            // Collect more candidates than MAX_ROWS to account for sealed-mode filtering.
            var hits = [];
            var cap = MAX_ROWS * 4;
            for (var i = 0; i < names.length && hits.length < cap; i++) {
                if (names[i].key.indexOf(needle) !== -1) hits.push(names[i]);
            }
            return Promise.all(hits.map(function (h) {
                return deps.getCard(h.uuids[0]);
            }));
        }).then(function (cards) {
            var rows = [];
            for (var j = 0; j < cards.length && rows.length < MAX_ROWS; j++) {
                var c = cards[j];
                if (!c) continue;
                // Scope suggestions to the active mode when one is set.
                if (deps.sealed != null && !!c.s !== deps.sealed) continue;
                var set = deps.sets[c.set] || {};
                rows.push({
                    uuid: c.uuid,
                    name: c.n,
                    setCode: c.set,
                    setName: set.n || c.set,
                    number: c.num || '',
                    keyrune: set.k || ''
                });
            }
            return rows;
        });
    }

    function escapeHtml(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function rowHtml(r) {
        var icon = r.keyrune
            ? '<i class="ss ss-fw ss-' + escapeHtml(r.keyrune) + '"></i>'
            : '<span class="ac-swatch"></span>';
        var sub = escapeHtml(r.setCode) + (r.number ? ' #' + escapeHtml(r.number) : '');
        return '<span class="ac-icon">' + icon + '</span>' +
            '<span class="ac-label">' + escapeHtml(r.name) + '</span>' +
            '<span class="ac-sub">' + sub + '</span>';
    }

    function mount(opts) {
        var input = opts.input;
        if (!input || input.getAttribute('data-offline-search') === '1') return;
        input.setAttribute('data-offline-search', '1');
        input.setAttribute('autocomplete', 'off');

        var parent = input.parentNode;
        var list = null;
        var rows = [];
        var active = -1;
        var reqId = 0;

        function close() {
            if (list && list.parentNode) list.parentNode.removeChild(list);
            list = null;
            active = -1;
        }

        function submit() {
            close();
            opts.onSubmit(input.value.trim());
        }

        function choose(i) {
            input.value = rows[i].name;
            submit();
        }

        function render() {
            close();
            if (!rows.length) return;
            list = document.createElement('div');
            list.className = 'autocomplete-items ac-dropdown';
            for (var i = 0; i < rows.length; i++) {
                var row = document.createElement('div');
                row.innerHTML = rowHtml(rows[i]);
                (function (idx) {
                    row.addEventListener('mousedown', function (e) {
                        e.preventDefault();
                        choose(idx);
                    });
                })(i);
                list.appendChild(row);
            }
            parent.appendChild(list);
        }

        function highlight(next) {
            if (!list) return;
            var items = list.children;
            if (active >= 0 && items[active]) items[active].classList.remove('autocomplete-active');
            active = next;
            if (active < 0) active = items.length - 1;
            if (active >= items.length) active = 0;
            if (items[active]) items[active].classList.add('autocomplete-active');
        }

        input.addEventListener('input', function () {
            var id = ++reqId;
            suggest(input.value, opts.deps).then(function (r) {
                if (id !== reqId) return;
                rows = r;
                render();
            });
        });

        input.addEventListener('keydown', function (e) {
            if (e.key === 'ArrowDown') { e.preventDefault(); highlight(active + 1); return; }
            if (e.key === 'ArrowUp') { e.preventDefault(); highlight(active - 1); return; }
            if (e.key === 'Escape') { close(); return; }
            if (e.key === 'Enter') {
                e.preventDefault();
                if (list && active >= 0) { choose(active); return; }
                submit();
            }
        });

        input.addEventListener('blur', function () { setTimeout(close, 120); });

        if (opts.form) {
            opts.form.addEventListener('submit', function (e) {
                e.preventDefault();
                submit();
            });
        }
    }

    self.OfflineSearch = { suggest: suggest, mount: mount };
})();
