// The custom buylist's rules after the first, for singles or for sealed:
// rows drawn from the first rule's, kept in the cookie the container's
// data-rules names as rate:min:seller:fallback items joined by commas, with
// :product:kind after each where the container's data-kinds lists those.
// The first rule's fields keep their own cookies.
(function () {
    'use strict';

    // The most a tier can set, as maxCustomBuylistRules in search.go
    var MAX = 10;
    var FIELDS = ['rate', 'min', 'seller', 'fallback', 'product', 'kind'];
    // How many of them every rule has
    var REQUIRED = 4;

    function validRate(v) {
        var n = Number(v);
        return v !== '' && isFinite(n) && n > 0;
    }

    // limit is how many rules the reader's tier allows, the first included:
    // the container's data-max, which the server fills from UploadCustomMax.
    function limit(container) {
        var n = parseInt(container.getAttribute('data-max'), 10);
        return n >= 1 ? Math.min(n, MAX) : 1;
    }

    // parse reads the cookie into rules of up to six strings, as many as
    // follow the first within max, dropping what the server drops: an item
    // short of four fields or with no valid rate.
    function parse(raw, max) {
        var out = [];
        String(raw || '').split(',').forEach(function (item) {
            var parts = item.split(':');
            if (parts.length < REQUIRED || !validRate(parts[0])) return;
            if (out.length < max - 1) out.push(parts.slice(0, FIELDS.length));
        });
        return out;
    }

    function format(rules) {
        return rules.map(function (r) { return r.join(':'); }).join(',');
    }

    function field(row, name) {
        return row.querySelector('[data-field="' + name + '"]');
    }

    function values(row) {
        return FIELDS.map(function (f) { return field(row, f); }).filter(Boolean).map(function (e) { return e.value; });
    }

    function label(v) {
        v = v.replace(/_/g, ' ');
        return v.charAt(0).toUpperCase() + v.slice(1);
    }

    // options redraws a select as Any and names, then picks value, kept as
    // an option of its own when the datastore no longer has it.
    function options(select, names, value) {
        names = names.slice().sort();
        if (value && names.indexOf(value) < 0) names.push(value);
        while (select.options.length > 1) select.remove(1);
        names.forEach(function (name) {
            var o = document.createElement('option');
            o.value = name;
            o.textContent = label(name);
            select.appendChild(o);
        });
        select.value = value;
    }

    // kindsOf is the kinds of one product in data-kinds, of every one for Any.
    function kindsOf(container, product) {
        var kinds = JSON.parse(container.getAttribute('data-kinds'));
        if (product) return kinds[product] || [];
        var all = [];
        Object.keys(kinds).forEach(function (p) {
            kinds[p].forEach(function (k) { if (all.indexOf(k) < 0) all.push(k); });
        });
        return all;
    }

    // cover sets a row's product and kind, each drawn from data-kinds.
    function cover(container, row, product, kind) {
        if (!field(row, 'product')) return;
        options(field(row, 'product'), Object.keys(JSON.parse(container.getAttribute('data-kinds'))), product);
        options(field(row, 'kind'), kindsOf(container, product), kind);
    }

    // write puts a rule's values in row.
    function write(container, row, vals) {
        FIELDS.slice(0, REQUIRED).forEach(function (f, i) { field(row, f).value = vals[i]; });
        cover(container, row, vals[4] || '', vals[5] || '');
        markRate(row);
    }

    // wireProduct lists only the kinds the picked product has, dropping a
    // kind it has not.
    function wireProduct(container, row) {
        var product = field(row, 'product');
        if (!product) return;
        product.addEventListener('change', function () {
            var kind = field(row, 'kind').value;
            var kinds = kindsOf(container, product.value);
            options(field(row, 'kind'), kinds, kinds.indexOf(kind) < 0 ? '' : kind);
        });
    }

    function changed(container) {
        container.dispatchEvent(new Event('change', { bubbles: true }));
    }

    function rowsOf(container) {
        return Array.prototype.slice.call(container.querySelectorAll('.custom-rule'));
    }

    // sync hides Add at the limit, and the grips with one rule to order.
    function sync(container) {
        var count = rowsOf(container).length;
        var add = container.querySelector('.custom-rules-add');
        if (add) add.hidden = count >= limit(container);
        container.querySelectorAll('.custom-rule-grip').forEach(function (g) { g.hidden = count < 2; });
    }

    function markRate(row) {
        var rate = field(row, 'rate');
        if (validRate(rate.value)) rate.removeAttribute('aria-invalid');
        else rate.setAttribute('aria-invalid', 'true');
    }

    // move puts rule from at to. The values move and the rows stay, since the
    // first row is the one bound to its own cookies.
    function move(container, from, to) {
        var rows = rowsOf(container);
        var rules = rows.map(values);
        rules.splice(to, 0, rules.splice(from, 1)[0]);
        rows.forEach(function (row, i) { write(container, row, rules[i]); });
    }

    // rowAt is the index of the row at height y, the nearest past either end.
    function rowAt(container, y) {
        var at = 0;
        rowsOf(container).forEach(function (row, i) {
            if (field(row, 'rate').getBoundingClientRect().top <= y) at = i;
        });
        return at;
    }

    function moved(container) {
        changed(container);
        if (window.BAN && window.BAN.track) window.BAN.track('ui.settings.custom_rule', 'move');
    }

    // addGrip gives row a handle to drag it by, or to move it with the arrows.
    function addGrip(container, row) {
        var grip = document.createElement('button');
        grip.type = 'button';
        grip.className = 'settings-btn custom-rule-grip';
        grip.textContent = '⠿';
        grip.title = 'Drag to reorder';
        grip.setAttribute('aria-label', 'Move rule');
        var start = -1;
        var at = -1;
        function end() {
            if (at < 0) return;
            rowsOf(container)[at].classList.remove('dragging');
            var changedPlace = at !== start;
            at = -1;
            if (changedPlace) moved(container);
        }
        grip.addEventListener('pointerdown', function (e) {
            if (e.button !== 0) return;
            grip.setPointerCapture(e.pointerId);
            start = at = rowsOf(container).indexOf(row);
            row.classList.add('dragging');
        });
        grip.addEventListener('pointermove', function (e) {
            if (at < 0) return;
            var to = rowAt(container, e.clientY);
            if (to === at) return;
            var rows = rowsOf(container);
            rows[at].classList.remove('dragging');
            rows[to].classList.add('dragging');
            move(container, at, to);
            at = to;
            field(rows[to], 'rate').scrollIntoView({ block: 'nearest' });
        });
        grip.addEventListener('pointerup', end);
        grip.addEventListener('pointercancel', end);
        grip.addEventListener('keydown', function (e) {
            var step = e.key === 'ArrowUp' ? -1 : e.key === 'ArrowDown' ? 1 : 0;
            if (!step) return;
            e.preventDefault();
            var rows = rowsOf(container);
            var from = rows.indexOf(row);
            var target = rows[from + step];
            if (!target) return;
            move(container, from, from + step);
            target.querySelector('.custom-rule-grip').focus();
            moved(container);
        });
        row.appendChild(grip);
    }

    // rowFrom copies the first rule's row, without the ids and cookies that
    // bind it, with vals in its fields and a remove button.
    function rowFrom(container, vals) {
        var first = container.querySelector('.custom-rule');
        var row = first.cloneNode(true);
        row.querySelectorAll('[id]').forEach(function (e) { e.removeAttribute('id'); });
        row.querySelectorAll('[data-cookie]').forEach(function (e) { e.removeAttribute('data-cookie'); });
        row.querySelectorAll('.custom-rule-grip').forEach(function (g) { g.remove(); });
        write(container, row, vals);
        wireProduct(container, row);
        addGrip(container, row);
        var remove = document.createElement('button');
        remove.type = 'button';
        remove.className = 'settings-btn custom-rule-remove';
        remove.textContent = '×';
        remove.setAttribute('aria-label', 'Remove rule');
        remove.setAttribute('data-track', 'ui.settings.custom_rule');
        remove.setAttribute('data-track-value', 'remove');
        remove.addEventListener('click', function () {
            row.remove();
            sync(container);
            changed(container);
        });
        row.appendChild(remove);
        row.addEventListener('input', function () { markRate(row); });
        return row;
    }

    function render(container, rules) {
        container.querySelectorAll('.custom-rule ~ .custom-rule').forEach(function (r) { r.remove(); });
        var add = container.querySelector('.custom-rules-add');
        rules.forEach(function (vals) { container.insertBefore(rowFrom(container, vals), add); });
        sync(container);
    }

    // The extra rows a save keeps: those at a valid rate, as the server
    // reads, with numbers written plainly, so no comma or colon gets in.
    function collect(container) {
        return rowsOf(container).slice(1).map(values).filter(function (v) { return validRate(v[0]); }).map(function (v) {
            var min = Number(v[1]);
            v[0] = String(Number(v[0]));
            v[1] = v[1] !== '' && isFinite(min) ? String(min) : '';
            return v;
        });
    }

    // binding is what settings.js wires: load draws, save writes, serialize
    // feeds the dirty check. Add copies the last row, the usual next tier.
    function binding(container) {
        var cookie = container.getAttribute('data-rules');
        var add = container.querySelector('.custom-rules-add');
        var first = container.querySelector('.custom-rule');
        if (!container.dataset.wired) {
            container.dataset.wired = '1';
            wireProduct(container, first);
        }
        if (add && !add.dataset.wired) {
            add.dataset.wired = '1';
            addGrip(container, first);
            first.addEventListener('input', function () { markRate(first); });
            add.addEventListener('click', function () {
                var rows = container.querySelectorAll('.custom-rule');
                if (rows.length >= limit(container)) return;
                container.insertBefore(rowFrom(container, values(rows[rows.length - 1])), add);
                sync(container);
                changed(container);
            });
        }
        return {
            load: function () {
                if (field(first, 'product')) {
                    cover(container, first, getCookie(field(first, 'product').dataset.cookie), getCookie(field(first, 'kind').dataset.cookie));
                }
                render(container, parse(getCookie(cookie), limit(container)));
            },
            save: function () { setCookie(cookie, format(collect(container)), 1000); },
            serialize: function () { return cookie + '=' + format(collect(container)); },
        };
    }

    window.CustomBuylistRules = { MAX: MAX, parse: parse, format: format, collect: collect, move: move, rowAt: rowAt, render: render, binding: binding };
})();
