// Offline navbar search controller: local-data suggestions and in-place query.
(function () {
    'use strict';
    var self = typeof window !== 'undefined' ? window : globalThis;

    var MIN_CHARS = 3;
    var MAX_ROWS = 10;
    // Index hits loaded per round of card lookups, and the rounds one
    // keystroke may spend when the loaded cards keep failing the filters.
    // A comma name that sorts past those hits is left out, so an empty
    // list after a comma does not prove there is no such card.
    var BATCH = MAX_ROWS * 4;
    var MAX_ROUNDS = 5;

    // The leading words a typed name may leave out, in normName form, as
    // the online matcher's __acSkippablePrefixes (js/autocomplete.js).
    var SKIPPABLE = ['the ', 'secret lair drop '];

    function squash(key) { return key.replace(/ /g, ''); }

    function startsAt(key, needle, offset) {
        return key.lastIndexOf(needle, offset) === offset;
    }

    var SKIPPABLE_SQUASHED = SKIPPABLE.map(squash);

    // Whether the typed text starts the name, as the online matcher reads
    // it (internal/suggest, __acMatchSpan in js/autocomplete.js): by the
    // normalized key, by that key with its spaces closed on both sides so
    // "blue eyed" reaches "Blue-Eyed ..." and "solring" reaches "Sol Ring",
    // or either way after a leading word the reader may leave out, so
    // "urdragon" reaches "The Ur-Dragon".
    function matches(key, needle, squashed) {
        if (startsAt(key, needle, 0)) return true;
        var sq = squash(key);
        if (startsAt(sq, squashed, 0)) return true;
        for (var i = 0; i < SKIPPABLE.length; i++) {
            var skip = SKIPPABLE[i];
            var skipSq = SKIPPABLE_SQUASHED[i];
            if (startsAt(key, skip, 0) && startsAt(key, needle, skip.length)) return true;
            if (startsAt(sq, skipSq, 0) && startsAt(sq, squashed, skipSq.length)) return true;
        }
        return false;
    }

    // Letters, digits and commas alone, as __acCommaFold (js/autocomplete.js).
    function commaFold(text) {
        return text.normalize('NFD').replace(/[\u0300-\u036f]/g, '')
            .replace(/[^\p{L}\p{N},]/gu, '').toLowerCase();
    }

    // Whether the name has the typed commas where they were typed, read from
    // where the match begins: the front, or past a leading word the reader
    // left out. A typed comma is the one punctuation mark that narrows the
    // list: "Saheeli," means the name goes on past one, as "Saheeli, Sublime
    // Artificer" does and "Saheeli Rai" does not. The index keys have lost
    // their commas, so this reads the name itself, once the card is loaded.
    function commasMatch(name, commas) {
        var folded = commaFold(name);
        if (startsAt(folded, commas, 0)) return true;
        for (var i = 0; i < SKIPPABLE_SQUASHED.length; i++) {
            var skip = SKIPPABLE_SQUASHED[i];
            if (startsAt(folded, skip, 0) && startsAt(folded, commas, skip.length)) return true;
        }
        return false;
    }

    // Build display suggestion rows from the local name index and card store.
    // stale, when given, says the caller no longer wants the answer, which
    // ends the walk before its next round of lookups.
    function suggest(rawValue, deps, stale) {
        var needle = deps.normName(rawValue);
        if (needle.length < MIN_CHARS) return Promise.resolve([]);
        var squashed = squash(needle);
        var commas = rawValue.indexOf(',') >= 0 ? commaFold(rawValue) : '';
        return deps.allNames().then(function (names) {
            var rows = [];
            var i = 0;
            var rounds = 0;
            // Index hits are loaded a batch at a time, and only as far as
            // filling the list needs: the comma and mode filters read the
            // loaded card, so a batch can pass fewer rows than it holds, and
            // the names that pass can sort past any one batch of hits. The
            // rounds are capped, since a comma few names carry would
            // otherwise walk every prefix match.
            function next() {
                if (rounds >= MAX_ROUNDS || (stale && stale())) return rows;
                rounds++;
                var batch = [];
                for (; i < names.length && batch.length < BATCH; i++) {
                    if (matches(names[i].key, needle, squashed)) batch.push(names[i]);
                }
                if (!batch.length) return rows;
                return Promise.all(batch.map(function (h) {
                    return deps.getCard(h.uuids[0]);
                })).then(function (cards) {
                    for (var j = 0; j < cards.length && rows.length < MAX_ROWS; j++) {
                        var c = cards[j];
                        if (!c) continue;
                        if (commas && !commasMatch(c.n, commas)) continue;
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
                    return rows.length < MAX_ROWS ? next() : rows;
                });
            }
            return next();
        });
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
            suggest(input.value, opts.deps, function () { return id !== reqId; }).then(function (r) {
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

    self.OfflineSearch = { suggest: suggest, matches: matches, mount: mount };
})();
