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
            // A verified row waiting on a replacement can resend its link.
            if (row.state === 'verified') return row.pending ? ['change', 'resend', 'remove'] : ['change', 'remove'];
            if (row.state === 'disabled') {
                // The server refuses a confirm mail to either.
                if (row.reason === 'unsubscribed' || row.reason === 'complained') return ['remove'];
                return ['resend', 'remove'];
            }
        } else if (row.source === 'patreon' && row.state === 'disabled' && row.reason !== 'complained') {
            return ['enable'];
        }
        return [];
    }

    // channelNote is the replacement a user address waits on, or why a
    // disabled one offers no way back, or ''.
    function channelNote(row) {
        if (row.pending) return 'Waiting for confirmation: ' + row.pending;
        if (row.state !== 'disabled') return '';
        if (row.reason === 'complained') return 'This address marked our mail as spam, so we cannot send to it again.';
        if (row.source === 'user' && row.reason === 'unsubscribed') return 'Remove it and add it again to confirm it afresh.';
        return '';
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

    // apiError carries the response status, so a caller can tell a 404 apart.
    function apiError(message, status) {
        var err = new Error(message);
        err.status = status;
        return err;
    }

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
                throw apiError('request failed: ' + res.status, res.status);
            }
            return res.json().then(function (data) {
                if (!res.ok) throw apiError(data.error || ('request failed: ' + res.status), res.status);
                return data;
            });
        });
    }

    function money(v) { return '$' + Number(v).toFixed(2); }

    // bestPrice is the lowest retail or highest buylist offer in the
    // condition among the scoped stores (every store but the picked-only
    // ones when scope is empty), or null when none has one, as the server's
    // bestStorePrice picks it.
    function bestPrice(stores, side, condition, scope) {
        var best = null;
        (stores || []).forEach(function (s) {
            if (scope && scope.length) {
                if (!scope.some(function (x) { return x.toUpperCase() === s.shorthand.toUpperCase(); })) return;
            } else if (s.picked_only) {
                return;
            }
            var p = s.prices && s.prices[condition];
            if (p && (best === null || (side === 'buylist' ? p > best : p < best))) best = p;
        });
        return best;
    }

    // storesNote is the hint beside the store list, naming the picked-only
    // stores that watching every store leaves out.
    function storesNote(stores) {
        var left = (stores || []).filter(function (s) { return s.picked_only; }).map(function (s) { return s.name || s.shorthand; });
        return 'leave all unchecked to watch every one' + (left.length ? ' but ' + left.join(', ') : '');
    }

    // referenceUsed is whether either threshold is a percentage, the only
    // thing the reference price is measured for.
    function referenceUsed(aboveKind, belowKind) {
        return aboveKind === 'pct' || belowKind === 'pct';
    }

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

    // Every store on the side is listed, by name, so an alert can watch one
    // not offering the card yet.
    function renderStores() {
        var host = document.getElementById('alert-stores');
        var stores = ((state.options && state.options.stores) || []).slice().sort(function (a, b) {
            return (a.name || a.shorthand).localeCompare(b.name || b.shorthand);
        });
        var note = document.querySelector('#alert-stores-label .alert-label-note');
        if (note) note.textContent = storesNote(stores);
        host.innerHTML = '';
        if (!stores.length) {
            var p = document.createElement('p');
            p.className = 'alert-stores-empty';
            p.textContent = 'No store is available to watch.';
            host.appendChild(p);
            return;
        }
        stores.forEach(function (s) {
            var label = document.createElement('label');
            label.setAttribute('data-shorthand', s.shorthand);
            label.title = s.name || s.shorthand;
            var box = document.createElement('input');
            box.type = 'checkbox';
            box.name = 'stores';
            box.value = s.shorthand;
            box.checked = state.stores.some(function (x) { return x.toUpperCase() === s.shorthand.toUpperCase(); });
            var name = document.createElement('span');
            name.className = 'alert-store-name';
            name.textContent = s.name || s.shorthand;
            var price = document.createElement('span');
            price.className = 'alert-store-price';
            label.appendChild(box);
            label.appendChild(name);
            label.appendChild(price);
            host.appendChild(label);
        });
        renderStorePrices();
    }

    // The price shown beside each store is the one in the chosen condition;
    // a store without one is dimmed.
    function renderStorePrices() {
        var stores = (state.options && state.options.stores) || [];
        stores.forEach(function (s) {
            var label = form.querySelector('.alert-stores label[data-shorthand="' + s.shorthand + '"]');
            if (!label) return;
            var p = s.prices && s.prices[state.condition];
            label.querySelector('.alert-store-price').textContent = p ? money(p) : '';
            label.classList.toggle('alert-store-none', !p);
        });
    }

    // The reference is the best offer among the checked stores, a store's
    // own offer, or a typed price; it only counts for a percentage.
    function renderReference() {
        var pick = document.getElementById('alert-reference-pick');
        var input = form.elements.reference_price;
        var stores = (state.options && state.options.stores) || [];
        var priced = stores.filter(function (s) { return s.prices && s.prices[state.condition]; });
        pick.innerHTML = '';
        var add = function (value, text) {
            var o = document.createElement('option');
            o.value = value;
            o.textContent = text;
            pick.appendChild(o);
        };
        add('', state.side === 'buylist' ? 'Highest offer' : 'Lowest offer');
        priced.forEach(function (s) { add(s.shorthand, (s.name || s.shorthand) + ' ' + money(s.prices[state.condition])); });
        add('custom', 'Custom price');
        var store = priced.filter(function (s) { return s.shorthand === state.referenceStore; })[0];
        if (state.referenceStore !== 'custom' && !store) state.referenceStore = '';
        pick.value = state.referenceStore;
        if (store) {
            input.value = Number(store.prices[state.condition]).toFixed(2);
        } else if (state.referenceStore === '') {
            var best = bestPrice(stores, state.side, state.condition, checkedStores());
            input.value = best === null ? '' : Number(best).toFixed(2);
        }
        var used = referenceUsed(state.aboveKind, state.belowKind);
        pick.disabled = !used;
        input.disabled = !used;
    }

    function describeAlert(a) {
        var parts = [(a.side === 'buylist' ? 'Buylist' : 'Retail') + ' ' + a.condition, a.stores && a.stores.length ? a.stores.join(', ') : 'any store'];
        if (a.above && a.above.kind) parts.push('above ' + (a.above.kind === 'pct' ? '+' + a.above.value + '%' : money(a.above.value)));
        if (a.below && a.below.kind) parts.push('below ' + (a.below.kind === 'pct' ? '-' + a.below.value + '%' : money(a.below.value)));
        if (a.status && a.status !== 'active') parts.push(a.status.replace('_', ' '));
        return parts.join(', ');
    }

    // existingForCard is what the box above a new alert's form lists: the
    // card's own alerts, and nothing while the modal edits one.
    function existingForCard(existing, cardId, alertId) {
        if (alertId) return [];
        return (existing || []).filter(function (a) { return a.card_id === cardId; });
    }

    // Alerts already on this card sit above a new alert's form, each with Edit and Remove.
    function renderExisting() {
        var host = document.getElementById('alert-modal-existing');
        host.innerHTML = '';
        var mine = existingForCard(state.existing, state.cardId, state.alertId);
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
            var remove = document.createElement('button');
            remove.type = 'button';
            remove.className = 'alert-existing-remove';
            remove.setAttribute('data-remove-id', a.id);
            remove.textContent = 'Remove';
            row.appendChild(remove);
            host.appendChild(row);
        });
    }

    // Remove one of the card's alerts from the box; the Alerts page reloads
    // so its table agrees, search updates the box and the bell in place.
    // A 404 means it was already gone, so the row goes all the same.
    function removeExisting(id) {
        var removed = function (note) {
            if (document.getElementById('alerts-page')) { window.location.reload(); return; }
            state.existing = (state.existing || []).filter(function (a) { return String(a.id) !== String(id); });
            renderExisting();
            markExistingBells();
            toast(note);
        };
        var run = function () {
            api('DELETE', '/api/alerts/' + id).then(function () { removed('Alert removed'); })
               .catch(function (err) {
                   if (err.status === 404) { removed('Alert was already removed'); return; }
                   setError(err.message);
               });
        };
        if (typeof window.confirmDialog === 'function') {
            window.confirmDialog('Remove this alert?', run, { confirmLabel: 'Remove' });
        } else if (window.confirm('Remove this alert?')) {
            run();
        }
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

    // deliveryAllowed is the channels the ACL lists in data-alert-channels,
    // on #alerts-page or, on the search page, on the modal itself; a page
    // carrying neither offers Discord alone.
    function deliveryAllowed() {
        var host = document.getElementById('alerts-page') || document.getElementById('alert-modal');
        var list = host ? host.getAttribute('data-alert-channels') : null;
        if (list === null) return ['discord'];
        return allowedChannels(list);
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
        saveBtn.disabled = !!text || state.optionsSide !== state.side;
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
        renderThreshold('above', state.aboveKind, state.aboveValue);
        renderThreshold('below', state.belowKind, state.belowValue);
        renderReference();
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
    //
    // Each loader writes the state it was handed, not the module's: an open
    // over one still loading replaces `state`, and the first open's answers
    // must land in its own, abandoned state rather than the new card's.

    function loadOptions(s) {
        var seq = ++s.optionsSeq;
        var side = s.side;
        var url = '/api/alerts/options?card=' + encodeURIComponent(s.cardId) + '&side=' + encodeURIComponent(side);
        if (s.stores.length) url += '&keep=' + encodeURIComponent(s.stores.join(','));
        // Only the latest request's answer is kept: a side toggled since asked again.
        return api('GET', url).then(function (opts) {
            if (s.optionsSeq !== seq) return;
            s.options = opts;
            s.optionsSide = side;
        });
    }

    function loadExisting(s) {
        return api('GET', '/api/alerts/').then(function (list) { s.existing = list || []; });
    }

    function loadAlert(s) {
        return api('GET', '/api/alerts/').then(function (list) {
            var a = (list || []).filter(function (x) { return String(x.id) === String(s.alertId); })[0];
            if (!a) throw new Error('That alert no longer exists.');
            s.cardId = a.card_id;
            s.side = a.side;
            s.condition = a.condition;
            s.stores = a.stores || [];
            // An alert set on stores offering nothing has no reference.
            s.reference = a.reference_price || null;
            s.referenceStore = a.reference_price ? 'custom' : '';
            s.aboveKind = a.above && a.above.kind ? a.above.kind : '';
            s.aboveValue = a.above && a.above.kind ? a.above.value : null;
            s.belowKind = a.below && a.below.kind ? a.below.kind : '';
            s.belowValue = a.below && a.below.kind ? a.below.value : null;
            s.delivery = a.delivery || 'discord';
        });
    }

    // loadDeliveryChannels fetches the live channel states for the Delivery
    // control; a failure leaves s.channels null, falling back to
    // discord_linked for Discord and hiding Email as unusable.
    function loadDeliveryChannels(s) {
        return api('GET', '/api/alerts/channels').then(function (rows) {
            s.channels = rows || [];
        }).catch(function () {
            s.channels = null;
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
            optionsSeq: 0,
            optionsSide: '',
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
        // Only the latest open draws: s stops being `state` once another
        // open replaces it, and its answers then go nowhere.
        var s = state;
        var load = s.alertId
            ? loadAlert(s).then(function () { return loadOptions(s); })
            : loadOptions(s).then(function () { return loadExisting(s); });
        load = load.then(function () { return loadDeliveryChannels(s); });
        load.then(function () {
            if (s === state) render();
        }).catch(function (err) {
            if (s !== state) return;
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

    function checkedStores() {
        return Array.prototype.map.call(form.querySelectorAll('input[name=stores]:checked'), function (el) { return el.value; });
    }

    function readForm() {
        state.stores = checkedStores();
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
        // The form shows the other side's options until this side's load.
        if (state.optionsSide !== state.side) return;
        readForm();
        if (!state.aboveKind && !state.belowKind) {
            setError('Turn on at least one threshold.');
            return;
        }
        if ((state.aboveKind && !(state.aboveValue > 0)) || (state.belowKind && !(state.belowValue > 0))) {
            setError('Each threshold you turn on needs a number above zero.');
            return;
        }
        if (referenceUsed(state.aboveKind, state.belowKind) && !(state.reference > 0)) {
            setError('A percentage needs a reference price: no store you picked has an offer, so type one.');
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
        if (referenceUsed(state.aboveKind, state.belowKind) && state.reference !== null && isFinite(state.reference)) body.reference_price = state.reference;
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
        var removeLink = e.target.closest('[data-remove-id]');
        if (removeLink) { removeExisting(removeLink.getAttribute('data-remove-id')); return; }
        var pill = e.target.closest('.settings-pill[data-value]');
        if (pill && form.contains(pill)) {
            var field = pill.parentNode.getAttribute('data-field');
            var value = pill.getAttribute('data-value');
            if (field === 'side') {
                if (state.alertId || value === state.side) return;
                readForm();
                state.side = value;
                setPills('side', value);
                // Save waits for this side's options; see renderNotice.
                saveBtn.disabled = true;
                var s = state;
                var load = loadOptions(s);
                var seq = s.optionsSeq;
                load.then(function () {
                    if (s === state && s.optionsSeq === seq) render();
                }).catch(function (err) {
                    if (s !== state || s.optionsSeq !== seq) return;
                    // Back to the side the form shows, so the toggle can be retried.
                    if (s.optionsSide) {
                        s.side = s.optionsSide;
                        setPills('side', s.side);
                        renderNotice();
                    }
                    setError(err.message);
                });
            } else if (field === 'condition') {
                state.condition = value;
                setPills('condition', value);
                renderStorePrices();
                renderReference();
            } else if (field === 'above_kind') {
                state.aboveKind = value;
                renderThreshold('above', value, form.elements.above_value.value);
                renderReference();
                if (value) form.elements.above_value.focus();
            } else if (field === 'below_kind') {
                state.belowKind = value;
                renderThreshold('below', value, form.elements.below_value.value);
                renderReference();
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
        // A confirm open over the modal owns the keyboard until it closes.
        if (document.querySelector('.ban-confirm-dialog-host:not([hidden])')) return;
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

    // deleteAllPrompt is the Delete all confirm's text for n alerts on the page.
    function deleteAllPrompt(n) {
        return n === 1 ? 'Delete your only alert? This cannot be undone.' : 'Delete all ' + n + ' alerts? This cannot be undone.';
    }

    // deletedNote is what Delete all says when the server removed a count
    // other than the n the page showed (alerts added or removed in another
    // tab), or '' when they agree.
    function deletedNote(n, deleted) {
        if (typeof deleted !== 'number' || deleted === n) return '';
        return deleted === 1 ? 'Deleted 1 alert' : 'Deleted ' + deleted + ' alerts';
    }

    function onDeleteAllClick() {
        var n = document.querySelectorAll('.alerts-table tr[data-id]').length;
        var run = function () {
            api('DELETE', '/api/alerts/').then(function (data) {
                var note = deletedNote(n, data && data.deleted);
                if (!note) { window.location.reload(); return; }
                toast(note);
                setTimeout(function () { window.location.reload(); }, 1500);
            }).catch(function (err) { toast(err.message); });
        };
        if (typeof window.confirmDialog === 'function') {
            window.confirmDialog(deleteAllPrompt(n), run, { confirmLabel: 'Delete all' });
        } else if (window.confirm(deleteAllPrompt(n))) {
            run();
        }
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

    // ── Sorting the list on /alerts ─────────────────────────
    // The pick, from the menu or a header, is kept per device in
    // localStorage as "field:dir". The server lists newest first, which
    // also breaks every sort's ties.
    var SORT_KEY = 'alertsSort';
    var SORT_DEFAULT = 'created:desc';
    var SORT_FIELDS = ['created', 'name', 'now', 'fired', 'status', 'side'];
    // The way each field runs first, as the menu lists it.
    var SORT_FIRST_DIR = { created: 'desc', name: 'asc', now: 'desc', fired: 'desc', status: 'asc', side: 'asc' };
    var STATUS_RANK = { active: 0, paused: 1, over_allowance: 2, undeliverable: 3, unresolvable: 4 };

    // parseSort reads a "field:dir" value, falling back to the server's
    // order for one it does not know.
    function parseSort(value) {
        var parts = String(value || '').split(':');
        if (parts.length !== 2 || SORT_FIELDS.indexOf(parts[0]) < 0 || (parts[1] !== 'asc' && parts[1] !== 'desc')) {
            parts = SORT_DEFAULT.split(':');
        }
        return { field: parts[0], dir: parts[1] };
    }

    function loadSort() {
        try { return parseSort(window.localStorage.getItem(SORT_KEY)); } catch (e) { return parseSort(''); }
    }

    function saveSort(sort) {
        try { window.localStorage.setItem(SORT_KEY, sort.field + ':' + sort.dir); } catch (e) {}
    }

    // alertSortData is what a row's data-* attributes say it sorts by;
    // now and fired are null when the row has no offer or never fired.
    function alertSortData(tr) {
        var num = function (name) {
            var v = tr.getAttribute(name);
            return v === null || v === '' ? null : Number(v);
        };
        return {
            id: num('data-id'),
            name: tr.getAttribute('data-name') || '',
            side: tr.getAttribute('data-side') || '',
            status: tr.getAttribute('data-status') || '',
            now: num('data-now'),
            created: num('data-created') || 0,
            fired: num('data-fired'),
        };
    }

    function sortValue(row, field) {
        if (field === 'status') return row.status in STATUS_RANK ? STATUS_RANK[row.status] : 5;
        return row[field];
    }

    // sortAlerts returns rows in sort's order; a row without a value for
    // the field goes last whichever way it runs.
    function sortAlerts(rows, sort) {
        return rows.slice().sort(function (a, b) {
            var x = sortValue(a, sort.field), y = sortValue(b, sort.field);
            if (x === null && y !== null) return 1;
            if (y === null && x !== null) return -1;
            var c = 0;
            if (typeof x === 'string') c = x.localeCompare(y, undefined, { sensitivity: 'base', numeric: true });
            else if (x !== null) c = x - y;
            if (c) return sort.dir === 'desc' ? -c : c;
            return (b.created - a.created) || (b.id - a.id);
        });
    }

    // headerSort is what a click on field's header picks: the list the
    // other way round when it is already sorted by field.
    function headerSort(cur, field) {
        if (cur.field === field) return { field: field, dir: cur.dir === 'asc' ? 'desc' : 'asc' };
        return { field: field, dir: SORT_FIRST_DIR[field] };
    }

    // markSortHeaders puts the arrow on the sorted field's header, the
    // aria-sort main.css draws for the tablesort tables.
    function markSortHeaders(sort) {
        document.querySelectorAll('.alerts-table th[data-sort]').forEach(function (th) {
            if (th.getAttribute('data-sort') === sort.field) th.setAttribute('aria-sort', sort.dir === 'asc' ? 'ascending' : 'descending');
            else th.removeAttribute('aria-sort');
        });
    }

    function applySort(sort) {
        var body = document.querySelector('.alerts-table tbody');
        if (!body) return;
        var rows = Array.prototype.map.call(body.querySelectorAll('tr.alert-row'), function (tr) {
            var d = alertSortData(tr);
            d.tr = tr;
            return d;
        });
        sortAlerts(rows, sort).forEach(function (d) { body.appendChild(d.tr); });
    }

    function initSort() {
        var pick = document.getElementById('alerts-sort');
        if (!pick) return;
        var sort = loadSort();
        var show = function (picked) {
            sort = picked;
            pick.value = sort.field + ':' + sort.dir;
            markSortHeaders(sort);
            applySort(sort);
        };
        pick.closest('.alerts-sort').hidden = false;
        show(sort);
        pick.addEventListener('change', function () {
            show(parseSort(pick.value));
            saveSort(sort);
        });
        document.querySelectorAll('.alerts-table th[data-sort]').forEach(function (th) {
            var onPick = function () {
                show(headerSort(sort, th.getAttribute('data-sort')));
                saveSort(sort);
            };
            th.setAttribute('role', 'columnheader');
            th.tabIndex = 0;
            th.addEventListener('click', onPick);
            th.addEventListener('keydown', function (e) {
                if (e.key !== 'Enter' && e.key !== ' ') return;
                e.preventDefault();
                onPick();
            });
        });
    }

    window.alertsSort = { parseSort: parseSort, loadSort: loadSort, saveSort: saveSort, alertSortData: alertSortData, sortAlerts: sortAlerts, headerSort: headerSort };

    // ── Channels box (#alerts-channels on /alerts) ──────────

    var channelsRows = [];
    var channelsError = '';
    var channelsChanging = false;

    function channelsHost() { return document.getElementById('alerts-channels'); }

    function anyEmailVerified(rows) {
        return rows.some(function (r) { return r.kind === 'email' && r.state === 'verified'; });
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
        var note = channelNote(row);
        if (note) {
            noteNode = document.createElement('p');
            noteNode.className = 'alerts-channel-note';
            noteNode.textContent = note;
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
        var buttons = rowButtons(btn);
        setButtonsDisabled(buttons, true);
        showEmailError('');
        api('POST', '/api/alerts/channels/email', { address: address }).then(function (res) {
            channelsChanging = false;
            toast(res.state === 'verified' ? 'Email confirmed' : 'Confirmation mail sent');
            return loadChannelsBox();
        }).catch(function (err) {
            showEmailError(err.message);
        }).then(function () { setButtonsDisabled(buttons, false); });
    }

    function resendEmail(btn) {
        var buttons = rowButtons(btn);
        setButtonsDisabled(buttons, true);
        showEmailError('');
        api('POST', '/api/alerts/channels/email/resend').then(function () {
            toast('Confirmation mail sent');
            return loadChannelsBox();
        }).catch(function (err) {
            showEmailError(err.message);
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
            form.elements.reference_price.addEventListener('input', function () {
                state.referenceStore = 'custom';
                document.getElementById('alert-reference-pick').value = 'custom';
            });
            form.addEventListener('change', function (e) {
                if (e.target.id === 'alert-reference-pick') {
                    state.referenceStore = e.target.value;
                    renderReference();
                    if (state.referenceStore === 'custom') form.elements.reference_price.focus();
                } else if (e.target.name === 'stores') {
                    renderReference();
                }
            });
        }
        var table = document.querySelector('.alerts-table');
        if (table) table.addEventListener('click', onTableClick);
        var deleteAll = document.querySelector('.alerts-delete-all');
        if (deleteAll) deleteAll.addEventListener('click', onDeleteAllClick);
        initSort();
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
    window.alertsChannels = { channelState: channelState, allowedChannels: allowedChannels, channelButtons: channelButtons, channelNote: channelNote, emailLines: emailLines, deliveryOptions: deliveryOptions, deliveryAllowed: deliveryAllowed, alertsConfig: alertsConfig, deleteAllPrompt: deleteAllPrompt, deletedNote: deletedNote, existingForCard: existingForCard, bestPrice: bestPrice, storesNote: storesNote, referenceUsed: referenceUsed };
})();
