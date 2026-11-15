// The custom buylist's rules after the first: rows drawn from the first
// rule's, kept in the UploadCustomRules cookie as
// rate:min:seller:fallback:sealed:sealedfallback items joined by commas.
// The first rule's fields keep their own cookies.
(function () {
    'use strict';

    var COOKIE = 'UploadCustomRules';
    // The most a tier can set, as maxCustomBuylistRules in search.go
    var MAX = 10;
    var FIELDS = ['rate', 'min', 'seller', 'fallback', 'sealed', 'sealedfallback'];

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

    // parse reads the cookie into rules of six strings, as many as follow
    // the first within max, dropping what the server drops: an item that is
    // not six fields or has no valid rate.
    function parse(raw, max) {
        var out = [];
        String(raw || '').split(',').forEach(function (item) {
            var parts = item.split(':');
            if (parts.length !== FIELDS.length || !validRate(parts[0])) return;
            if (out.length < max - 1) out.push(parts);
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
        return FIELDS.map(function (f) { return field(row, f).value; });
    }

    function changed(container) {
        container.dispatchEvent(new Event('change', { bubbles: true }));
    }

    function syncAdd(container) {
        var add = container.querySelector('.custom-rules-add');
        if (add) add.hidden = container.querySelectorAll('.custom-rule').length >= limit(container);
    }

    function markRate(row) {
        var rate = field(row, 'rate');
        if (validRate(rate.value)) rate.removeAttribute('aria-invalid');
        else rate.setAttribute('aria-invalid', 'true');
    }

    // rowFrom copies the first rule's row, without the ids and cookies that
    // bind it, with vals in its fields and a remove button.
    function rowFrom(container, vals) {
        var first = container.querySelector('.custom-rule');
        var row = first.cloneNode(true);
        row.querySelectorAll('[id]').forEach(function (e) { e.removeAttribute('id'); });
        row.querySelectorAll('[data-cookie]').forEach(function (e) { e.removeAttribute('data-cookie'); });
        FIELDS.forEach(function (f, i) { field(row, f).value = vals[i]; });
        markRate(row);
        var remove = document.createElement('button');
        remove.type = 'button';
        remove.className = 'custom-rule-remove';
        remove.textContent = '×';
        remove.setAttribute('aria-label', 'Remove rule');
        remove.setAttribute('data-track', 'ui.settings.custom_rule');
        remove.setAttribute('data-track-value', 'remove');
        remove.addEventListener('click', function () {
            row.remove();
            syncAdd(container);
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
        syncAdd(container);
    }

    // The extra rows a save keeps: those at a valid rate, as the server
    // reads, with numbers written plainly, so no comma or colon gets in.
    function collect(container) {
        var rows = Array.prototype.slice.call(container.querySelectorAll('.custom-rule')).slice(1);
        return rows.map(values).filter(function (v) { return validRate(v[0]); }).map(function (v) {
            var min = Number(v[1]);
            v[0] = String(Number(v[0]));
            v[1] = v[1] !== '' && isFinite(min) ? String(min) : '';
            return v;
        });
    }

    // binding is what settings.js wires: load draws, save writes, serialize
    // feeds the dirty check. Add copies the last row, the usual next tier.
    function binding(container) {
        var add = container.querySelector('.custom-rules-add');
        if (add && !add.dataset.wired) {
            add.dataset.wired = '1';
            add.addEventListener('click', function () {
                var rows = container.querySelectorAll('.custom-rule');
                if (rows.length >= limit(container)) return;
                container.insertBefore(rowFrom(container, values(rows[rows.length - 1])), add);
                syncAdd(container);
                changed(container);
            });
        }
        return {
            load: function () { render(container, parse(getCookie(COOKIE), limit(container))); },
            save: function () { setCookie(COOKIE, format(collect(container)), 1000); },
            serialize: function () { return COOKIE + '=' + format(collect(container)); },
        };
    }

    window.CustomBuylistRules = { MAX: MAX, parse: parse, format: format, collect: collect, render: render, binding: binding };
})();
