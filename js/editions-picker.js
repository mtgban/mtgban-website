(function () {
    'use strict';

    function escapeRegex(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

    function highlight(label, query) {
        const span = label.querySelector('.row-name');
        if (!span) return;
        const orig = span.dataset.orig || span.textContent;
        span.dataset.orig = orig;
        if (!query) { span.textContent = orig; return; }
        const re = new RegExp('(' + escapeRegex(query) + ')', 'ig');
        span.innerHTML = orig.replace(re, '<mark>$1</mark>');
    }

    function matchesQuery(label, query) {
        if (!query) return true;
        const q = query.toLowerCase();
        const name = (label.dataset.name || '').toLowerCase();
        const code = (label.dataset.code || '').toLowerCase();
        return name.indexOf(q) >= 0 || code.indexOf(q) >= 0;
    }

    function updateGroupState(group) {
        const boxes = group.querySelectorAll('.editions-grid input[type="checkbox"]');
        let checked = 0, visible = 0;
        boxes.forEach(function (cb) {
            const row = cb.closest('label');
            if (!row.classList.contains('row-hidden')) visible++;
            if (cb.checked) checked++;
        });
        const total = boxes.length;
        const counter = group.querySelector('.editions-group-count');
        if (counter) counter.textContent = '(' + checked + ' of ' + total + ' selected)';
        const tri = group.querySelector('.editions-group-checkbox');
        if (tri) {
            tri.checked = checked === total && total > 0;
            tri.indeterminate = checked > 0 && checked < total;
            tri.classList.toggle('indeterminate', tri.indeterminate);
        }
        group.classList.toggle('hidden-by-filter', visible === 0);
    }

    function initPicker(root) {
        const search = root.querySelector('.editions-picker-search input');
        const groups = root.querySelectorAll('.editions-group');
        let lastClicked = null;
        let dragging = false;
        let dragTarget = null;

        function forEachGroup(fn) { groups.forEach(fn); }

        function applyFilter(query) {
            forEachGroup(function (g) {
                g.querySelectorAll('.editions-grid label').forEach(function (l) {
                    const ok = matchesQuery(l, query);
                    l.classList.toggle('row-hidden', !ok);
                    highlight(l, query);
                });
                updateGroupState(g);
            });
            root.querySelectorAll('[data-role="visible-actions"]').forEach(function (el) {
                el.hidden = !query;
            });
        }

        if (search) {
            search.addEventListener('input', function () { applyFilter(search.value.trim()); });
        }

        forEachGroup(function (g) {
            const header = g.querySelector('.editions-group-header');
            const tri = g.querySelector('.editions-group-checkbox');
            header.addEventListener('click', function (e) {
                if (e.target === tri) return;
                g.classList.toggle('expanded');
            });
            if (tri) {
                tri.addEventListener('click', function (e) { e.stopPropagation(); });
                tri.addEventListener('change', function () {
                    const should = tri.checked;
                    g.querySelectorAll('.editions-grid input[type="checkbox"]').forEach(function (cb) {
                        const row = cb.closest('label');
                        if (row.classList.contains('row-hidden')) return;
                        cb.checked = should;
                    });
                    updateGroupState(g);
                    root.dispatchEvent(new Event('change', { bubbles: true }));
                });
            }
            updateGroupState(g);
        });

        const allBoxes = Array.from(root.querySelectorAll('.editions-grid input[type="checkbox"]'));
        function indexOf(cb) { return allBoxes.indexOf(cb); }

        root.addEventListener('mousedown', function (e) {
            const cb = e.target.closest('.editions-grid input[type="checkbox"]');
            if (!cb) return;
            if (e.shiftKey && lastClicked) {
                e.preventDefault();
                const from = indexOf(lastClicked);
                const to = indexOf(cb);
                if (from < 0 || to < 0) return;
                const lo = Math.min(from, to);
                const hi = Math.max(from, to);
                const target = !lastClicked.checked ? true : false;
                for (let i = lo; i <= hi; i++) {
                    const box = allBoxes[i];
                    const row = box.closest('label');
                    if (row.classList.contains('row-hidden')) continue;
                    box.checked = target;
                }
                lastClicked = cb;
                groups.forEach(updateGroupState);
                root.dispatchEvent(new Event('change', { bubbles: true }));
                return;
            }
            dragging = true;
            dragTarget = !cb.checked;
            cb.checked = dragTarget;
            lastClicked = cb;
            root.classList.add('dragging');
            groups.forEach(updateGroupState);
            root.dispatchEvent(new Event('change', { bubbles: true }));
        });

        root.addEventListener('mouseover', function (e) {
            if (!dragging) return;
            const cb = e.target.closest('.editions-grid input[type="checkbox"]');
            if (!cb) return;
            const row = cb.closest('label');
            if (row.classList.contains('row-hidden')) return;
            if (cb.checked === dragTarget) return;
            cb.checked = dragTarget;
            groups.forEach(updateGroupState);
            root.dispatchEvent(new Event('change', { bubbles: true }));
        });

        function endDrag() {
            if (!dragging) return;
            dragging = false;
            dragTarget = null;
            root.classList.remove('dragging');
        }
        document.addEventListener('mouseup', endDrag);
        document.addEventListener('mouseleave', endDrag);

        function actOn(predicate, value) {
            allBoxes.forEach(function (cb) {
                const row = cb.closest('label');
                if (!predicate(row)) return;
                cb.checked = value;
            });
            groups.forEach(updateGroupState);
            root.dispatchEvent(new Event('change', { bubbles: true }));
        }
        root.querySelectorAll('[data-action="select-all"]').forEach(function (b) {
            b.addEventListener('click', function () { actOn(function () { return true; }, true); });
        });
        root.querySelectorAll('[data-action="clear-all"]').forEach(function (b) {
            b.addEventListener('click', function () { actOn(function () { return true; }, false); });
        });
        root.querySelectorAll('[data-action="select-visible"]').forEach(function (b) {
            b.addEventListener('click', function () {
                actOn(function (row) { return !row.classList.contains('row-hidden'); }, true);
            });
        });
        root.querySelectorAll('[data-action="clear-visible"]').forEach(function (b) {
            b.addEventListener('click', function () {
                actOn(function (row) { return !row.classList.contains('row-hidden'); }, false);
            });
        });

        const exp = root.querySelector('.editions-group[data-category="Expansions"]');
        if (exp) exp.classList.add('expanded');
    }

    function loadFromCookie(root, cookieName) {
        const list = getCookie(cookieName);
        const items = list ? list.split(',').filter(Boolean) : [];
        root.querySelectorAll('.editions-grid input[type="checkbox"]').forEach(function (cb) {
            cb.checked = items.indexOf(cb.name) >= 0;
        });
        refresh(root);
    }

    function refresh(root) {
        root.querySelectorAll('.editions-group').forEach(function (g) {
            const boxes = g.querySelectorAll('.editions-grid input[type="checkbox"]');
            let checked = 0;
            boxes.forEach(function (cb) { if (cb.checked) checked++; });
            const counter = g.querySelector('.editions-group-count');
            if (counter) counter.textContent = '(' + checked + ' of ' + boxes.length + ' selected)';
            const tri = g.querySelector('.editions-group-checkbox');
            if (tri) {
                tri.checked = checked === boxes.length && boxes.length > 0;
                tri.indeterminate = checked > 0 && checked < boxes.length;
            }
        });
    }

    function serialize(root) {
        const names = [];
        root.querySelectorAll('.editions-grid input[type="checkbox"]:checked').forEach(function (cb) {
            names.push(cb.name);
        });
        return names.join(',') + (names.length ? ',' : '');
    }

    function saveToCookie(root, cookieName) {
        setCookie(cookieName, serialize(root), 1000);
    }

    window.EditionsPicker = {
        init: initPicker,
        load: loadFromCookie,
        save: saveToCookie,
        serialize: serialize,
    };
})();
