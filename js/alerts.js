// Price alerts: the create/edit dialog (templates/partials/alert-modal.html)
// and the row actions on /alerts. Everything talks to /api/alerts/.
(function () {
    'use strict';

    var CONDITIONS = ['NM', 'SP', 'MP', 'HP', 'PO'];

    var modal, backdrop, form, saveBtn;
    var state = null;

    function api(method, path, body) {
        return fetch(path, {
            method: method,
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: body ? JSON.stringify(body) : undefined
        }).then(function (res) {
            if (res.status === 204) return null;
            var contentType = res.headers.get('content-type') || '';
            if (contentType.indexOf('application/json') === -1) {
                throw new Error('request failed: ' + res.status);
            }
            return res.json().then(function (data) {
                if (!res.ok) throw new Error(data.error || ('request failed: ' + res.status));
                return data;
            });
        });
    }

    function money(v) { return '$' + Number(v).toFixed(2); }

    function toast(text) {
        var el = document.getElementById('alerts-toast');
        if (!el) {
            el = document.createElement('div');
            el.id = 'alerts-toast';
            el.className = 'settings-toast';
            document.body.appendChild(el);
        }
        el.textContent = text;
        void el.offsetWidth;
        el.classList.add('show');
        setTimeout(function () { el.classList.remove('show'); }, 2000);
    }

    function els() {
        if (modal) return true;
        modal = document.getElementById('alert-modal');
        backdrop = document.getElementById('alert-modal-backdrop');
        form = document.getElementById('alert-form');
        saveBtn = modal ? modal.querySelector('[data-role="save"]') : null;
        return !!(modal && backdrop && form && saveBtn);
    }

    // ── Rendering ────────────────────────────────────────────

    function setPills(field, current) {
        var group = form.querySelector('[data-field="' + field + '"]');
        if (!group) return;
        Array.prototype.forEach.call(group.querySelectorAll('.settings-pill'), function (b) {
            var on = b.getAttribute('data-value') === current;
            b.classList.toggle('active', on);
            b.setAttribute('aria-checked', on ? 'true' : 'false');
        });
    }

    function renderConditions() {
        var group = form.querySelector('[data-field="condition"]');
        var list = (state.options && state.options.conditions) || CONDITIONS;
        group.innerHTML = '';
        list.forEach(function (c) {
            var b = document.createElement('button');
            b.type = 'button';
            b.className = 'settings-pill';
            b.setAttribute('role', 'radio');
            b.setAttribute('data-value', c);
            b.textContent = c;
            group.appendChild(b);
        });
        if (list.indexOf(state.condition) === -1) state.condition = list[0];
        setPills('condition', state.condition);
    }

    function renderStores() {
        var host = document.getElementById('alert-stores');
        var stores = (state.options && state.options.stores) || [];
        host.innerHTML = '';
        if (!stores.length) {
            var p = document.createElement('p');
            p.className = 'alert-stores-empty';
            p.textContent = 'No store has an offer for this card right now.';
            host.appendChild(p);
            return;
        }
        var half = Math.ceil(stores.length / 2);
        [stores.slice(0, half), stores.slice(half)].forEach(function (column) {
            var col = document.createElement('div');
            column.forEach(function (s) {
                var label = document.createElement('label');
                var box = document.createElement('input');
                box.type = 'checkbox';
                box.name = 'stores';
                box.value = s.shorthand;
                box.checked = state.stores.some(function (x) { return x.toUpperCase() === s.shorthand.toUpperCase(); });
                var name = document.createElement('span');
                name.textContent = s.name || s.shorthand;
                var price = document.createElement('span');
                price.className = 'alert-store-price';
                price.setAttribute('data-shorthand', s.shorthand);
                label.appendChild(box);
                label.appendChild(name);
                label.appendChild(price);
                col.appendChild(label);
            });
            host.appendChild(col);
        });
        renderStorePrices();
    }

    // The price shown beside each store is the one in the chosen condition.
    function renderStorePrices() {
        var stores = (state.options && state.options.stores) || [];
        stores.forEach(function (s) {
            var el = form.querySelector('.alert-store-price[data-shorthand="' + s.shorthand + '"]');
            if (!el) return;
            var p = s.prices && s.prices[state.condition];
            el.textContent = p ? money(p) : 'no ' + state.condition + ' offer';
            el.classList.toggle('alert-dim', !p);
        });
    }

    // One pill per store with an offer in the chosen condition; picking one fills the reference.
    function renderReferencePicks() {
        var host = document.getElementById('alert-reference-picks');
        var stores = (state.options && state.options.stores) || [];
        host.innerHTML = '';
        stores.forEach(function (s) {
            var p = s.prices && s.prices[state.condition];
            if (!p) return;
            var b = document.createElement('button');
            b.type = 'button';
            b.className = 'settings-pill';
            b.setAttribute('role', 'radio');
            b.setAttribute('data-value', s.shorthand);
            b.setAttribute('data-price', p);
            b.textContent = (s.name || s.shorthand) + ' ' + money(p);
            host.appendChild(b);
        });
        host.hidden = !host.firstChild;
        setPills('reference_pick', state.referenceStore || '');
        if (state.referenceStore) {
            var pick = host.querySelector('.settings-pill.active');
            if (pick) form.elements.reference_price.value = Number(pick.getAttribute('data-price')).toFixed(2);
            else state.referenceStore = '';
        }
    }

    function describeAlert(a) {
        var parts = [(a.side === 'buylist' ? 'Buylist' : 'Retail') + ' ' + a.condition, a.stores && a.stores.length ? a.stores.join(', ') : 'any store'];
        if (a.above && a.above.kind) parts.push('above ' + (a.above.kind === 'pct' ? '+' + a.above.value + '%' : money(a.above.value)));
        if (a.below && a.below.kind) parts.push('below ' + (a.below.kind === 'pct' ? '-' + a.below.value + '%' : money(a.below.value)));
        if (a.status && a.status !== 'active') parts.push(a.status.replace('_', ' '));
        return parts.join(', ');
    }

    // Alerts already on this card sit above a new alert's form, each with an Edit link.
    function renderExisting() {
        var host = document.getElementById('alert-modal-existing');
        host.innerHTML = '';
        var mine = state.alertId ? [] : (state.existing || []).filter(function (a) { return a.card_id === state.cardId; });
        host.hidden = !mine.length;
        if (!mine.length) return;
        var head = document.createElement('span');
        head.className = 'alert-existing-head';
        head.textContent = mine.length === 1 ? 'Already on this card:' : 'Already on this card (' + mine.length + '):';
        host.appendChild(head);
        mine.forEach(function (a) {
            var row = document.createElement('span');
            row.className = 'alert-existing';
            row.textContent = describeAlert(a);
            var edit = document.createElement('button');
            edit.type = 'button';
            edit.className = 'alert-existing-edit';
            edit.setAttribute('data-edit-id', a.id);
            edit.textContent = 'Edit';
            row.appendChild(edit);
            host.appendChild(row);
        });
    }

    function renderThreshold(name, kind, value) {
        setPills(name + '_kind', kind);
        var input = form.elements[name + '_value'];
        input.disabled = !kind;
        input.placeholder = kind === 'pct' ? '% of reference' : (kind === 'abs' ? 'dollars' : '');
        input.step = kind === 'pct' ? '1' : '0.01';
        if (value !== undefined && value !== null && kind) input.value = value;
        if (!kind) input.value = '';
    }

    function renderNotice() {
        var notice = document.getElementById('alert-modal-notice');
        var linked = !state.options || state.options.discord_linked !== false;
        notice.hidden = linked;
        notice.textContent = linked ? '' : 'Alerts arrive as a Discord DM. Link Discord in your Patreon settings, then sign out and back in here.';
        saveBtn.disabled = !linked;
    }

    function render() {
        var card = state.options && state.options.card;
        document.getElementById('alert-modal-title').textContent = state.alertId ? 'Edit alert' : 'Price alert';
        document.getElementById('alert-modal-card').textContent = card
            ? card.name + ', ' + card.set + ' #' + card.number + ', ' + card.finish
            : '';
        setPills('side', state.side);
        var sideGroup = form.querySelector('[data-field="side"]');
        sideGroup.classList.toggle('alert-locked', !!state.alertId);
        renderConditions();
        renderStores();
        var ref = form.elements.reference_price;
        ref.value = state.reference !== null && state.reference !== undefined ? Number(state.reference).toFixed(2) : '';
        renderReferencePicks();
        renderThreshold('above', state.aboveKind, state.aboveValue);
        renderThreshold('below', state.belowKind, state.belowValue);
        renderNotice();
        renderExisting();
        saveBtn.textContent = state.alertId ? 'Save changes' : 'Create alert';
        setError('');
    }

    function setError(text) {
        var box = document.getElementById('alert-form-error');
        box.textContent = text;
        box.hidden = !text;
    }

    // ── Loading ──────────────────────────────────────────────

    function loadOptions() {
        var url = '/api/alerts/options?card=' + encodeURIComponent(state.cardId) + '&side=' + encodeURIComponent(state.side);
        if (state.stores.length) url += '&keep=' + encodeURIComponent(state.stores.join(','));
        return api('GET', url).then(function (opts) { state.options = opts; });
    }

    function loadExisting() {
        return api('GET', '/api/alerts/').then(function (list) { state.existing = list || []; });
    }

    function loadAlert() {
        return api('GET', '/api/alerts/').then(function (list) {
            var a = (list || []).filter(function (x) { return String(x.id) === String(state.alertId); })[0];
            if (!a) throw new Error('That alert no longer exists.');
            state.cardId = a.card_id;
            state.side = a.side;
            state.condition = a.condition;
            state.stores = a.stores || [];
            state.reference = a.reference_price;
            state.aboveKind = a.above && a.above.kind ? a.above.kind : '';
            state.aboveValue = a.above && a.above.kind ? a.above.value : null;
            state.belowKind = a.below && a.below.kind ? a.below.kind : '';
            state.belowValue = a.below && a.below.kind ? a.below.value : null;
        });
    }

    // ── Open, close, save ───────────────────────────────────

    function open(opts) {
        if (!els()) return;
        state = {
            cardId: opts.cardId || '',
            side: opts.side === 'retail' ? 'retail' : 'buylist',
            alertId: opts.alertId || null,
            options: null,
            condition: 'NM',
            stores: [],
            reference: null,
            referenceStore: '',
            existing: null,
            aboveKind: '', aboveValue: null,
            belowKind: '', belowValue: null
        };
        modal.classList.add('open');
        backdrop.classList.add('open');
        document.getElementById('alert-modal-card').textContent = 'Loading';
        var load = state.alertId ? loadAlert().then(loadOptions) : loadOptions().then(loadExisting);
        load.then(render).catch(function (err) {
            document.getElementById('alert-modal-card').textContent = '';
            setError(err.message);
        });
        setTimeout(function () {
            var first = modal.querySelector('.settings-pill.active') || saveBtn;
            if (first) first.focus();
        }, 50);
    }

    function close() {
        if (!els()) return;
        modal.classList.remove('open');
        backdrop.classList.remove('open');
    }

    function readForm() {
        state.stores = Array.prototype.map.call(form.querySelectorAll('input[name=stores]:checked'), function (el) { return el.value; });
        var ref = form.elements.reference_price.value.trim();
        state.reference = ref === '' ? null : parseFloat(ref);
        state.aboveValue = state.aboveKind ? parseFloat(form.elements.above_value.value) : null;
        state.belowValue = state.belowKind ? parseFloat(form.elements.below_value.value) : null;
    }

    // An off side is sent as {} on purpose: the API treats an omitted side
    // as unchanged and an empty object as cleared.
    function threshold(kind, value) {
        if (!kind) return {};
        return { kind: kind, value: value };
    }

    function save() {
        readForm();
        if (!state.aboveKind && !state.belowKind) {
            setError('Turn on at least one threshold.');
            return;
        }
        if ((state.aboveKind && !(state.aboveValue > 0)) || (state.belowKind && !(state.belowValue > 0))) {
            setError('Each threshold you turn on needs a number above zero.');
            return;
        }
        var body = {
            card_id: state.cardId,
            side: state.side,
            condition: state.condition,
            stores: state.stores,
            above: threshold(state.aboveKind, state.aboveValue),
            below: threshold(state.belowKind, state.belowValue),
            delivery: 'discord'
        };
        if (state.reference !== null && isFinite(state.reference)) body.reference_price = state.reference;
        saveBtn.disabled = true;
        var req = state.alertId ? api('PATCH', '/api/alerts/' + state.alertId, body) : api('POST', '/api/alerts/', body);
        req.then(function () {
            close();
            toast(state.alertId ? 'Alert saved' : 'Alert created');
            if (!state.alertId) markExistingBells();
            if (document.getElementById('alerts-page')) setTimeout(function () { window.location.reload(); }, 600);
        }).catch(function (err) {
            setError(err.message);
        }).then(function () { saveBtn.disabled = false; });
    }

    // ── Events ──────────────────────────────────────────────

    function onModalClick(e) {
        var editLink = e.target.closest('[data-edit-id]');
        if (editLink) { open({ alertId: editLink.getAttribute('data-edit-id') }); return; }
        var pill = e.target.closest('.settings-pill[data-value]');
        if (pill && form.contains(pill)) {
            var field = pill.parentNode.getAttribute('data-field');
            var value = pill.getAttribute('data-value');
            if (field === 'side') {
                if (state.alertId || value === state.side) return;
                readForm();
                state.side = value;
                setPills('side', value);
                loadOptions().then(render).catch(function (err) { setError(err.message); });
            } else if (field === 'condition') {
                state.condition = value;
                setPills('condition', value);
                renderStorePrices();
                renderReferencePicks();
            } else if (field === 'reference_pick') {
                state.referenceStore = value;
                form.elements.reference_price.value = Number(pill.getAttribute('data-price')).toFixed(2);
                setPills('reference_pick', value);
            } else if (field === 'above_kind') {
                state.aboveKind = value;
                renderThreshold('above', value, form.elements.above_value.value);
                if (value) form.elements.above_value.focus();
            } else if (field === 'below_kind') {
                state.belowKind = value;
                renderThreshold('below', value, form.elements.below_value.value);
                if (value) form.elements.below_value.focus();
            }
            return;
        }
        var role = e.target.closest('[data-role]');
        if (!role) return;
        if (role.getAttribute('data-role') === 'cancel') close();
        if (role.getAttribute('data-role') === 'save') save();
    }

    function onKeydown(e) {
        if (!modal || !modal.classList.contains('open')) return;
        if (e.key === 'Escape') { e.preventDefault(); close(); }
        if (e.key === 'Enter' && e.target && e.target.tagName === 'INPUT') { e.preventDefault(); save(); }
    }

    // Row actions on the alerts page.
    function runRowAction(id, action) {
        var req = action === 'delete'
            ? api('DELETE', '/api/alerts/' + id)
            : api('PATCH', '/api/alerts/' + id, { status: action === 'pause' ? 'paused' : 'active' });
        req.then(function () { window.location.reload(); })
           .catch(function (err) { toast(err.message); });
    }

    function onTableClick(e) {
        var btn = e.target.closest('button[data-action]');
        if (!btn) return;
        var row = btn.closest('tr[data-id]');
        var id = row.getAttribute('data-id');
        var action = btn.getAttribute('data-action');
        if (action === 'edit') {
            open({ alertId: id, cardId: row.getAttribute('data-card-id'), side: row.getAttribute('data-side') });
            return;
        }
        if (action === 'delete') {
            // js/confirm-dialog.js is callback-style: confirmDialog(message, onConfirm, opts).
            if (typeof window.confirmDialog === 'function') {
                window.confirmDialog('Delete this alert?', function () { runRowAction(id, action); }, { confirmLabel: 'Delete' });
            } else if (window.confirm('Delete this alert?')) {
                runRowAction(id, action);
            }
            return;
        }
        runRowAction(id, action);
    }

    // Bells on result rows fill in, like the star, for cards that already have an alert.
    function markBells(cardIds) {
        var bells = document.querySelectorAll('.alert-link[data-card-id], .m-actions-alert[data-card-id]');
        Array.prototype.forEach.call(bells, function (b) {
            var on = cardIds.indexOf(b.getAttribute('data-card-id')) !== -1;
            b.classList.toggle('active', on);
            b.title = on ? 'Price alert set' : 'Set a price alert';
        });
    }

    function markExistingBells() {
        if (!document.querySelector('.alert-link[data-card-id], .m-actions-alert[data-card-id]')) return;
        api('GET', '/api/alerts/').then(function (list) {
            markBells((list || []).map(function (a) { return a.card_id; }));
        }).catch(function () {});
    }

    document.addEventListener('DOMContentLoaded', function () {
        if (els()) {
            modal.addEventListener('click', onModalClick);
            backdrop.addEventListener('click', close);
            document.addEventListener('keydown', onKeydown);
            form.addEventListener('submit', function (e) { e.preventDefault(); save(); });
            form.elements.reference_price.addEventListener('input', function () { state.referenceStore = ''; setPills('reference_pick', ''); });
        }
        var table = document.querySelector('.alerts-table');
        if (table) table.addEventListener('click', onTableClick);
        markExistingBells();

        // /alerts?card= and ?edit= open the dialog on arrival.
        var page = document.getElementById('alerts-page');
        if (page) {
            if (page.getAttribute('data-open-edit')) {
                open({ alertId: page.getAttribute('data-open-edit') });
            } else if (page.getAttribute('data-open-card')) {
                open({ cardId: page.getAttribute('data-open-card'), side: page.getAttribute('data-open-side') });
            }
        }
    });

    window.openAlertModal = open;
    window.closeAlertModal = close;
})();
