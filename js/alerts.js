// Price alerts: the create/edit dialog (templates/partials/alert-modal.html)
// and the row actions on /alerts. Everything talks to /api/alerts/.
(function () {
    'use strict';

    var CONDITIONS = ['NM', 'SP', 'MP', 'HP', 'PO'];

    var modal, backdrop, form, saveBtn;
    var state = null;

    // ── Channels: pure helpers (exported for tests/alerts-channels.test.js) ──

    var REASON_LABELS = { bounced: 'bounced', complained: 'marked as spam', unsubscribed: 'unsubscribed' };
    var KNOWN_CHANNELS = ['discord', 'email'];

    // channelState labels a GET /api/alerts/channels row for display.
    function channelState(row) {
        if (row.state === 'verified') return 'Verified';
        if (row.state === 'pending') return 'Confirm pending';
        if (row.state === 'disabled') return 'Disabled: ' + (REASON_LABELS[row.reason] || row.reason || '');
        return '';
    }

    // allowedChannels reads a comma list of channel names off a data
    // attribute, trimmed, lowercased, unknown names and duplicates dropped.
    function allowedChannels(attr) {
        if (!attr) return [];
        var out = [];
        attr.split(',').forEach(function (part) {
            var kind = part.trim().toLowerCase();
            if (KNOWN_CHANNELS.indexOf(kind) !== -1 && out.indexOf(kind) === -1) out.push(kind);
        });
        return out;
    }

    // channelButtons is which buttons a channel row offers, by source and state.
    function channelButtons(row) {
        if (row.source === 'user') {
            if (row.state === 'pending') return ['resend', 'remove'];
            if (row.state === 'verified') return ['change', 'remove'];
            if (row.state === 'disabled') {
                if (row.reason === 'unsubscribed') return ['remove'];
                return ['resend', 'remove'];
            }
        } else if (row.source === 'patreon' && row.state === 'disabled' && row.reason !== 'complained') {
            return ['enable'];
        }
        return [];
    }

    // emailLines is the Email section: the patreon line, then the user line,
    // the one mail goes to marked as ChannelFor picks it, and whether to offer Add.
    function emailLines(rows) {
        var email = (rows || []).filter(function (r) { return r.kind === 'email'; });
        var patreon = email.filter(function (r) { return r.source === 'patreon'; })[0] || null;
        var user = email.filter(function (r) { return r.source === 'user'; })[0] || null;
        var receiving = null;
        if (user && user.state === 'verified') receiving = user;
        else if (patreon && patreon.state !== 'disabled') receiving = patreon;
        var lines = [];
        if (patreon) lines.push({ row: patreon, receives: receiving === patreon });
        if (user) lines.push({ row: user, receives: receiving === user });
        return { lines: lines, add: !user };
    }

    var DELIVERY_LABELS = { discord: 'Discord', email: 'Email' };

    // deliveryOptions is the alert form's Delivery control: which pills to
    // show and which is selected. Creating an alert defaults the selection
    // into the allowed set; editing one never changes it away from the
    // alert's own stored value, even when a tier change has since dropped
    // it from `allowed` -- it is kept as an extra, clearly marked option so
    // an edit can still be saved unchanged (the API does not re-check a
    // delivery that did not change). The control is hidden only when there
    // is exactly one allowed channel and the selection already matches it.
    function deliveryOptions(allowed, current, editing) {
        allowed = allowed || [];
        var options = allowed.map(function (kind) {
            return { value: kind, label: DELIVERY_LABELS[kind] || kind, extra: false };
        });
        var selected = current;
        if (editing) {
            if (current && allowed.indexOf(current) === -1) {
                options.push({ value: current, label: (DELIVERY_LABELS[current] || current) + ' (not in your tier)', extra: true });
            }
        } else if (allowed.indexOf(current) === -1) {
            selected = allowed[0] || 'discord';
        }
        var hidden = allowed.length === 1 && selected === allowed[0];
        return { options: options, selected: selected, hidden: hidden };
    }

    var BUTTON_TEXT = { add: 'Add', change: 'Change', save: 'Change', cancel: 'Cancel', resend: 'Resend confirmation', remove: 'Remove', enable: 'Enable' };

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

    // alertsConfig is what the alerts page hands this script as values
    // (window.BAN_ALERTS): the invite and unsubscribe links. A page without
    // it, the search page's copy of the modal, has neither.
    function alertsConfig() {
        return window.BAN_ALERTS || {};
    }

    // deliveryAllowed is the channels the ACL lists on #alerts-page; a page
    // that carries no such element (the search page's copy of this modal)
    // falls back to Discord alone, same as before this control existed.
    function deliveryAllowed() {
        var page = document.getElementById('alerts-page');
        if (!page) return ['discord'];
        return allowedChannels(page.getAttribute('data-alert-channels'));
    }

    // deliveryUsable is whether the given channel will actually accept this
    // alert right now. Discord prefers the fresh GET channels answer over
    // the options call's discord_linked, which can be stale.
    function deliveryUsable(kind) {
        if (kind === 'discord') {
            if (state.channels) return state.channels.some(function (r) { return r.kind === 'discord'; });
            return !state.options || state.options.discord_linked !== false;
        }
        if (kind === 'email') {
            return !!state.channels && state.channels.some(function (r) { return r.kind === 'email' && r.state === 'verified'; });
        }
        return false;
    }

    function renderDelivery() {
        var field = document.getElementById('alert-delivery-field');
        var result = deliveryOptions(deliveryAllowed(), state.delivery, !!state.alertId);
        state.delivery = result.selected;
        field.hidden = result.hidden;
        if (result.hidden) return;
        var group = form.querySelector('[data-field="delivery"]');
        group.innerHTML = '';
        result.options.forEach(function (opt) {
            var b = document.createElement('button');
            b.type = 'button';
            b.className = 'settings-pill';
            b.setAttribute('role', 'radio');
            b.setAttribute('data-value', opt.value);
            b.textContent = opt.label;
            group.appendChild(b);
        });
        setPills('delivery', state.delivery);
    }

    function renderNotice() {
        var notice = document.getElementById('alert-modal-notice');
        var text = '';
        if (state.delivery === 'email') {
            if (!deliveryUsable('email')) text = 'Confirm an email address on the alerts page before choosing email delivery.';
        } else if (!deliveryUsable('discord')) {
            text = 'Alerts arrive as a Discord DM. Link Discord in your Patreon settings, then sign out and back in here.';
        }
        notice.hidden = !text;
        notice.textContent = text;
        saveBtn.disabled = !!text;
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
        renderDelivery();
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
            state.delivery = a.delivery || 'discord';
        });
    }

    // loadDeliveryChannels fetches the live channel states for the Delivery
    // control; a failure leaves state.channels null, falling back to
    // discord_linked for Discord and hiding Email as unusable.
    function loadDeliveryChannels() {
        return api('GET', '/api/alerts/channels').then(function (rows) {
            state.channels = rows || [];
        }).catch(function () {
            state.channels = null;
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
            belowKind: '', belowValue: null,
            delivery: 'discord',
            channels: null
        };
        modal.classList.add('open');
        backdrop.classList.add('open');
        document.getElementById('alert-modal-card').textContent = 'Loading';
        var load = state.alertId ? loadAlert().then(loadOptions) : loadOptions().then(loadExisting);
        load = load.then(loadDeliveryChannels);
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
            delivery: state.delivery
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
            } else if (field === 'delivery') {
                state.delivery = value;
                setPills('delivery', value);
                renderNotice();
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

    // ── Channels box (#alerts-channels on /alerts) ──────────

    var channelsRows = [];
    var channelsError = '';
    var channelsChanging = false;

    function channelsHost() { return document.getElementById('alerts-channels'); }

    // userEmailRow is the address the user entered, null when there is none.
    function userEmailRow(rows) {
        return rows.filter(function (r) { return r.kind === 'email' && r.source === 'user'; })[0] || null;
    }

    function anyEmailVerified(rows) {
        return rows.some(function (r) { return r.kind === 'email' && r.state === 'verified'; });
    }

    // mapChannelError rewords the one 422 the page cannot otherwise act on:
    // a disabled user row only ever shows Remove, so a race that still hits
    // this message needs a next step spelled out.
    function mapChannelError(message, row) {
        if (row && row.source === 'user' && message === 'this address unsubscribed; use Enable to turn it back on') {
            return 'This address unsubscribed. Remove it and add it again to confirm it afresh.';
        }
        return message;
    }

    function channelButton(action) {
        var b = document.createElement('button');
        b.type = 'button';
        b.className = 'settings-btn' + (action === 'remove' ? ' alert-btn-danger' : '');
        b.setAttribute('data-channel-action', action);
        b.textContent = BUTTON_TEXT[action] || action;
        return b;
    }

    // buildEmailError is the inline, aria-live error slot every Email row
    // shape carries, found again (never rebuilt) by showEmailError so a
    // failed request leaves the typed address and the row untouched.
    function buildEmailError() {
        var p = document.createElement('p');
        p.id = 'alerts-email-error';
        p.className = 'alerts-notice alerts-error alerts-channel-error';
        p.setAttribute('aria-live', 'polite');
        p.hidden = true;
        return p;
    }

    function showEmailError(message) {
        var el = document.getElementById('alerts-email-error');
        if (!el) return;
        el.textContent = message || '';
        el.hidden = !message;
    }

    // rowButtons is every button sharing btn's channel row, disabled
    // together so a request in flight cannot be fired twice; re-enabling a
    // button from a row a successful request has since replaced is a no-op.
    function rowButtons(btn) {
        var row = btn.closest('.alerts-channel-row');
        return row ? row.querySelectorAll('button') : [btn];
    }

    function setButtonsDisabled(buttons, disabled) {
        Array.prototype.forEach.call(buttons, function (b) { b.disabled = disabled; });
    }

    function buildChannelRow(label, detail, noteNode, buttons, tag) {
        var row = document.createElement('div');
        row.className = 'alerts-channel-row' + (label ? '' : ' alerts-channel-cont');
        var head = document.createElement('div');
        head.className = 'alerts-channel-head';
        var name = document.createElement('span');
        name.className = 'alerts-channel-label';
        name.textContent = label;
        head.appendChild(name);
        if (detail) {
            var d = document.createElement('span');
            d.className = 'alerts-channel-detail';
            d.textContent = detail;
            if (tag) {
                var t = document.createElement('span');
                t.className = 'alerts-channel-tag';
                t.textContent = tag;
                d.appendChild(document.createTextNode(' '));
                d.appendChild(t);
            }
            head.appendChild(d);
        }
        row.appendChild(head);
        if (noteNode) row.appendChild(noteNode);
        if (buttons && buttons.length) {
            var actions = document.createElement('div');
            actions.className = 'alerts-channel-actions';
            buttons.forEach(function (action) { actions.appendChild(channelButton(action)); });
            row.appendChild(actions);
        }
        return row;
    }

    function discordNote(inviteURL) {
        var p = document.createElement('p');
        p.className = 'alerts-channel-note';
        p.appendChild(document.createTextNode('Alerts arrive as a Discord DM. Link Discord in your Patreon settings, then sign out and back in here.'));
        if (inviteURL) {
            p.appendChild(document.createTextNode(' You also need to be in the '));
            var a = document.createElement('a');
            a.href = inviteURL;
            a.textContent = 'MTGBAN server';
            p.appendChild(a);
            p.appendChild(document.createTextNode('.'));
        }
        return p;
    }

    // buildEmailForm is the address input for Add, or Change on a verified
    // user row (prefilled); heading is the section label, empty under a line.
    function buildEmailForm(address, heading, fieldLabel) {
        var row = document.createElement('div');
        row.className = 'alerts-channel-row' + (heading ? '' : ' alerts-channel-cont');
        if (heading) {
            var head = document.createElement('div');
            head.className = 'alerts-channel-head';
            var name = document.createElement('span');
            name.className = 'alerts-channel-label';
            name.textContent = heading;
            head.appendChild(name);
            row.appendChild(head);
        }
        var label = document.createElement('label');
        label.className = 'alert-field-label';
        label.setAttribute('for', 'alerts-email-input');
        label.textContent = fieldLabel;
        row.appendChild(label);
        var input = document.createElement('input');
        input.type = 'email';
        input.className = 'alert-input';
        input.id = 'alerts-email-input';
        input.placeholder = 'you@example.com';
        if (address) input.value = address;
        row.appendChild(input);
        var actions = document.createElement('div');
        actions.className = 'alerts-channel-actions';
        actions.appendChild(channelButton(address ? 'save' : 'add'));
        if (address) actions.appendChild(channelButton('cancel'));
        row.appendChild(actions);
        return row;
    }

    // buildEmailLine is one stored address: its state, its buttons and
    // whether alert mail goes to it.
    function buildEmailLine(line, heading) {
        var row = line.row;
        if (row.source === 'user' && row.state === 'verified' && channelsChanging) {
            return buildEmailForm(row.address, heading, 'Email address');
        }
        var noteNode = null;
        if (row.source === 'user' && row.state === 'disabled' && row.reason === 'unsubscribed') {
            noteNode = document.createElement('p');
            noteNode.className = 'alerts-channel-note';
            noteNode.textContent = 'Remove it and add it again to confirm it afresh.';
        }
        var detail = row.address + (row.source === 'patreon' ? ' (Patreon)' : '') + ' - ' + channelState(row);
        var el = buildChannelRow(heading, detail, noteNode, channelButtons(row), line.receives ? 'receives alerts' : '');
        el.classList.add('alerts-channel-email');
        return el;
    }

    // buildEmailRows is each stored address on its own line, then Add when
    // there is no user address, with the one error slot on the last.
    function buildEmailRows(rows) {
        var section = emailLines(rows);
        var out = section.lines.map(function (line, i) { return buildEmailLine(line, i === 0 ? 'Email' : ''); });
        if (section.add) {
            out.push(section.lines.length ? buildEmailForm('', '', 'Add another address') : buildEmailForm('', 'Email', 'Email address'));
        }
        out[out.length - 1].appendChild(buildEmailError());
        return out;
    }

    function renderChannels() {
        var host = channelsHost();
        if (!host) return;
        var page = document.getElementById('alerts-page');
        var allowed = allowedChannels(page ? page.getAttribute('data-alert-channels') : '');
        var inviteURL = alertsConfig().inviteURL || '';
        host.innerHTML = '';

        var discord = channelsRows.filter(function (r) { return r.kind === 'discord'; })[0] || null;
        host.appendChild(buildChannelRow('Discord', discord ? 'Linked' : 'Not linked', discord ? null : discordNote(inviteURL), []));

        if (allowed.indexOf('email') !== -1) {
            buildEmailRows(channelsRows).forEach(function (el) { host.appendChild(el); });
        }
        // Email not on this tier: the row is dropped, not noted, so the box
        // still reads clean when Discord is the only channel there is.

        if (channelsError) {
            var err = document.createElement('p');
            err.className = 'alerts-notice alerts-error alerts-channel-error';
            err.textContent = channelsError;
            host.appendChild(err);
        }

        if (anyEmailVerified(channelsRows)) {
            var unsub = alertsConfig().unsubscribeURL || '';
            if (unsub) {
                var a = document.createElement('a');
                a.className = 'alerts-channel-unsub';
                a.href = unsub;
                a.textContent = 'Unsubscribe from alert email';
                host.appendChild(a);
            }
        }
    }

    function loadChannelsBox() {
        return api('GET', '/api/alerts/channels').then(function (rows) {
            channelsRows = rows || [];
            channelsError = '';
            renderChannels();
        }).catch(function (err) {
            channelsError = err.message;
            renderChannels();
        });
    }

    // Each action disables its row's buttons before the request and
    // re-enables them once it settles, whether it succeeded (the row is
    // about to be replaced by loadChannelsBox's re-render, so this is a
    // harmless no-op on the now-detached buttons) or failed (the row stays,
    // so its buttons must work again). A failure never calls renderChannels:
    // it writes straight into the row's own aria-live error element,
    // leaving a typed address and the rest of the row exactly as it was.
    function submitEmail(btn) {
        var input = document.getElementById('alerts-email-input');
        if (!input) return;
        var address = input.value.trim();
        if (!address) {
            showEmailError('enter a valid email address');
            return;
        }
        var row = userEmailRow(channelsRows);
        var buttons = rowButtons(btn);
        setButtonsDisabled(buttons, true);
        showEmailError('');
        api('POST', '/api/alerts/channels/email', { address: address }).then(function (res) {
            channelsChanging = false;
            toast(res.state === 'verified' ? 'Email confirmed' : 'Confirmation mail sent');
            return loadChannelsBox();
        }).catch(function (err) {
            showEmailError(mapChannelError(err.message, row));
        }).then(function () { setButtonsDisabled(buttons, false); });
    }

    function resendEmail(btn) {
        var row = userEmailRow(channelsRows);
        var buttons = rowButtons(btn);
        setButtonsDisabled(buttons, true);
        showEmailError('');
        api('POST', '/api/alerts/channels/email/resend').then(function () {
            toast('Confirmation mail sent');
            return loadChannelsBox();
        }).catch(function (err) {
            showEmailError(mapChannelError(err.message, row));
        }).then(function () { setButtonsDisabled(buttons, false); });
    }

    function removeEmail(btn) {
        function doRemove() {
            var buttons = rowButtons(btn);
            setButtonsDisabled(buttons, true);
            showEmailError('');
            api('DELETE', '/api/alerts/channels/email').then(function () {
                channelsChanging = false;
                toast('Email address removed');
                return loadChannelsBox();
            }).catch(function (err) {
                showEmailError(err.message);
            }).then(function () { setButtonsDisabled(buttons, false); });
        }
        if (typeof window.confirmDialog === 'function') {
            window.confirmDialog('Remove this email address?', doRemove, { confirmLabel: 'Remove' });
        } else if (window.confirm('Remove this email address?')) {
            doRemove();
        }
    }

    function enableEmailChannel(btn) {
        var buttons = rowButtons(btn);
        setButtonsDisabled(buttons, true);
        showEmailError('');
        api('POST', '/api/alerts/channels/enable', { kind: 'email' }).then(function () {
            toast('Email alerts enabled');
            return loadChannelsBox();
        }).catch(function (err) {
            showEmailError(err.message);
        }).then(function () { setButtonsDisabled(buttons, false); });
    }

    function onChannelsClick(e) {
        var btn = e.target.closest('[data-channel-action]');
        if (!btn) return;
        var action = btn.getAttribute('data-channel-action');
        if (action === 'change') { channelsChanging = true; renderChannels(); return; }
        if (action === 'cancel') { channelsChanging = false; renderChannels(); return; }
        if (action === 'add' || action === 'save') { submitEmail(btn); return; }
        if (action === 'resend') { resendEmail(btn); return; }
        if (action === 'remove') { removeEmail(btn); return; }
        if (action === 'enable') { enableEmailChannel(btn); return; }
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

        var channelsBox = channelsHost();
        if (channelsBox) {
            channelsBox.addEventListener('click', onChannelsClick);
            loadChannelsBox();
        }

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
    window.alertsChannels = { channelState: channelState, allowedChannels: allowedChannels, channelButtons: channelButtons, emailLines: emailLines, deliveryOptions: deliveryOptions, alertsConfig: alertsConfig };
})();
