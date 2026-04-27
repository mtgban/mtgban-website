(function () {
    'use strict';

    // ============================================================
    // Page -> control bindings. Each page maps control types to
    // { elementId: cookieName } (or a list of cookie names for selects,
    // or a list of element ids for dynamic-cookie lists).
    //
    // Binders no-op when their element isn't present in the current
    // DOM, so all pages can live in one map. Add a new page here to
    // wire up its settings;
    // ============================================================
    const PAGE_BINDINGS = {
        search: {
            lists: {
                'settings-search-sellers': 'SearchSellersList',
                'settings-search-vendors': 'SearchVendorsList',
            },
            pills: {
                'settings-search-sort': 'SearchDefaultSort',
                'settings-search-listing': 'SearchListingPriority',
                'settings-search-buylist-secondary': 'SearchBuylistSecondary',
            },
            selects: ['SearchSellersPriority', 'SearchVendorsPriority'],
            misc: { 'settings-search-misc': 'SearchMiscOpts' },
        },
        arbit: {
            // Cookie name varies by route (ArbitVendorsList / GlobalVendorsList /
            // ReverseVendorsList) and is read from the container's data-cookie attr.
            dynamicLists: ['settings-arbit-vendors'],
        },
        sleep: {
            lists: {
                'settings-sleep-sellers': 'SleepersSellersList',
                'settings-sleep-vendors': 'SleepersVendorsList',
            },
            editions: { 'sleep-editions-picker': 'SleepersEditionList' },
        },
        news: {
            editions: { 'news-editions-picker': 'NewspaperList' },
        },
        upload: {
            misc: { 'settings-upload-checks': 'UploadOptimizerOpts' },
            miscDefaults: {
                'settings-upload-checks': ['lowval', 'lowvalabs', 'minmargin', 'customperc'],
            },
            selects: ['UploadSorting', 'UploadAltPrice', 'UploadPriceSource'],
            texts: {
                'opt-percspread': 'UploadPercSpread',
                'opt-percspreadmax': 'UploadPercSpreadMax',
                'opt-minval': 'UploadMinVal',
                'opt-maxval': 'UploadMaxVal',
                'opt-margin': 'UploadMargin',
                'opt-custompercmax': 'UploadCustomPercMax',
                'opt-multiplier': 'UploadMultiplier',
            },
        },
    };

    // ============================================================
    // Binding registry. Each binding is { load, save, serialize }.
    // ============================================================
    const bindings = [];
    function addBinding(b) { bindings.push(b); }
    function hasBindings() { return bindings.length > 0; }

    // ─── List (checkbox grid → comma-separated cookie) ───────────
    function readList(containerId) {
        const c = document.getElementById(containerId);
        if (!c) return '';
        const names = [];
        c.querySelectorAll('input[type="checkbox"]:checked').forEach(function (cb) {
            names.push(cb.name);
        });
        return names.join(',') + (names.length ? ',' : '');
    }
    function bindList(containerId, cookieName) {
        const c = document.getElementById(containerId);
        if (!c) return;
        addBinding({
            load: function () {
                const items = (getCookie(cookieName) || '').split(',').filter(Boolean);
                c.querySelectorAll('input[type="checkbox"]').forEach(function (cb) {
                    cb.checked = items.indexOf(cb.name) >= 0;
                });
            },
            save: function () { setCookie(cookieName, readList(containerId), 1000); },
            serialize: function () { return cookieName + '=' + readList(containerId); },
        });
    }
    function bindDynamicList(containerId) {
        const c = document.getElementById(containerId);
        if (!c || !c.dataset.cookie) return;
        bindList(containerId, c.dataset.cookie);
    }

    // ─── Pills (radio-like, one .active at a time) ───────────────
    function readPill(containerId) {
        const c = document.getElementById(containerId);
        const active = c && c.querySelector('.settings-pill.active');
        return active ? active.dataset.val : '';
    }
    function bindPills(containerId, cookieName) {
        const c = document.getElementById(containerId);
        if (!c) return;
        c.addEventListener('click', function (e) {
            const btn = e.target.closest('.settings-pill');
            if (!btn) return;
            c.querySelectorAll('.settings-pill').forEach(function (p) {
                p.classList.toggle('active', p === btn);
            });
            c.dispatchEvent(new Event('change', { bubbles: true }));
        });
        addBinding({
            load: function () {
                const val = getCookie(cookieName);
                c.querySelectorAll('.settings-pill').forEach(function (btn) {
                    btn.classList.toggle('active', btn.dataset.val === val);
                });
            },
            save: function () { setCookie(cookieName, readPill(containerId), 1000); },
            serialize: function () { return cookieName + '=' + readPill(containerId); },
        });
    }

    // ─── Native <select data-cookie="..."> ───────────────────────
    function bindSelect(cookieName) {
        const sel = document.querySelector('#settings-modal select[data-cookie="' + cookieName + '"]');
        if (!sel) return;
        addBinding({
            load: function () { sel.value = getCookie(cookieName); },
            save: function () { setCookie(cookieName, sel.value, 1000); },
            serialize: function () { return cookieName + '=' + sel.value; },
        });
    }

    // ─── Text input (single value → cookie) ──────────────────────
    function bindText(elementId, cookieName) {
        const el = document.getElementById(elementId);
        if (!el) return;
        addBinding({
            load: function () { el.value = getCookie(cookieName) || el.defaultValue || ''; },
            save: function () { setCookie(cookieName, el.value, 1000); },
            serialize: function () { return cookieName + '=' + el.value; },
        });
    }

    // ─── Misc bitmap (many [data-misc] checkboxes → CSV cookie) ──
    function readMisc(container) {
        const names = [];
        container.querySelectorAll('[data-misc]:checked').forEach(function (el) {
            names.push(el.dataset.misc);
        });
        return names.join(',') + (names.length ? ',' : '');
    }
    function bindMiscBitmap(containerId, cookieName, defaults) {
        const c = document.getElementById(containerId);
        if (!c) return;
        addBinding({
            load: function () {
                const raw = getCookie(cookieName);
                const items = (raw === null || raw === '')
                    ? (defaults || [])
                    : raw.split(',').filter(Boolean);
                c.querySelectorAll('[data-misc]').forEach(function (el) {
                    el.checked = items.indexOf(el.dataset.misc) >= 0;
                });
            },
            save: function () { setCookie(cookieName, readMisc(c), 1000); },
            serialize: function () { return cookieName + '=' + readMisc(c); },
        });
    }

    // ─── Editions picker (delegates to EditionsPicker component) ─
    function bindEditions(pickerId, cookieName) {
        const el = document.getElementById(pickerId);
        if (!el || !window.EditionsPicker) return;
        window.EditionsPicker.init(el);
        addBinding({
            load: function () { window.EditionsPicker.load(el, cookieName); },
            save: function () { window.EditionsPicker.save(el, cookieName); },
            serialize: function () {
                return cookieName + '=' + window.EditionsPicker.serialize(el);
            },
        });
    }

    // ─── Walk the config and wire everything present in the DOM ──
    function autoWire() {
        Object.values(PAGE_BINDINGS).forEach(function (page) {
            Object.entries(page.lists || {}).forEach(function (e) { bindList(e[0], e[1]); });
            Object.entries(page.pills || {}).forEach(function (e) { bindPills(e[0], e[1]); });
            (page.selects || []).forEach(bindSelect);
            Object.entries(page.texts || {}).forEach(function (e) { bindText(e[0], e[1]); });
            Object.entries(page.misc || {}).forEach(function (e) {
                const defaults = (page.miscDefaults || {})[e[0]];
                bindMiscBitmap(e[0], e[1], defaults);
            });
            (page.dynamicLists || []).forEach(bindDynamicList);
            Object.entries(page.editions || {}).forEach(function (e) { bindEditions(e[0], e[1]); });
        });
    }

    function loadAll() { bindings.forEach(function (b) { b.load(); }); }
    function saveAll() { bindings.forEach(function (b) { b.save(); }); }
    function serializeAll() {
        return bindings.map(function (b) { return b.serialize(); }).join('|');
    }

    // ============================================================
    // Modal controller
    // ============================================================
    let baseline = null;
    let modalEl = null;
    let backdropEl = null;

    function ensureEls() {
        if (modalEl && backdropEl) return true;
        modalEl = document.getElementById('settings-modal');
        backdropEl = document.getElementById('settings-backdrop');
        return !!(modalEl && backdropEl);
    }

    function updateDirtyUI() {
        if (!modalEl) return;
        const saveBtn = modalEl.querySelector('.settings-btn.primary[data-role="save"]');
        if (!saveBtn) return;
        const dirty = serializeAll() !== baseline;
        saveBtn.disabled = !dirty;
        modalEl.dataset.dirty = dirty ? '1' : '0';
    }

    function isDirty() { return modalEl && modalEl.dataset.dirty === '1'; }

    function openSettings() {
        if (!ensureEls() || !hasBindings()) return;
        loadAll();
        baseline = serializeAll();
        modalEl.dataset.dirty = '0';
        updateDirtyUI();
        backdropEl.classList.add('open');
        modalEl.classList.add('open');
        document.body.classList.add('settings-open');
        const body = modalEl.querySelector('.settings-modal-body');
        if (body) {
            body.setAttribute('tabindex', '-1');
            body.focus({ preventScroll: true });
        }
        if (window.lucide && lucide.createIcons) {
            lucide.createIcons({ nameAttr: 'data-lucide', attrs: {} });
        }
    }

    function closeModal() {
        if (!ensureEls()) return;
        modalEl.classList.remove('open', 'confirm-open');
        backdropEl.classList.remove('open');
        document.body.classList.remove('settings-open');
    }

    function requestClose() {
        if (!ensureEls()) return;
        if (isDirty()) {
            modalEl.classList.add('confirm-open');
            return;
        }
        closeModal();
    }

    function confirmDiscard() { closeModal(); }
    function confirmKeepEditing() { modalEl.classList.remove('confirm-open'); }

    function saveAndClose() {
        if (!hasBindings()) { closeModal(); return; }
        saveAll();
        try { sessionStorage.setItem('settingsSavedToast', '1'); } catch (e) {}
        window.location.reload();
    }

    function showSavedToast() {
        let toast = document.getElementById('settings-toast');
        if (!toast) {
            toast = document.createElement('div');
            toast.id = 'settings-toast';
            toast.className = 'settings-toast';
            document.body.appendChild(toast);
        }
        toast.textContent = 'Settings saved';
        // Force reflow so the show transition runs even if just appended
        void toast.offsetWidth;
        toast.classList.add('show');
        setTimeout(function () { toast.classList.remove('show'); }, 2000);
    }

    function consumeSavedToast() {
        try {
            if (sessionStorage.getItem('settingsSavedToast') === '1') {
                sessionStorage.removeItem('settingsSavedToast');
                showSavedToast();
            }
        } catch (e) {}
    }

    function onKeydown(e) {
        if (e.key === 'Escape' && ensureEls() && modalEl.classList.contains('open')) {
            if (modalEl.classList.contains('confirm-open')) confirmKeepEditing();
            else requestClose();
            e.preventDefault();
            return;
        }
        if ((e.ctrlKey || e.metaKey) && e.key === ',') {
            const tag = (document.activeElement && document.activeElement.tagName) || '';
            if (tag === 'INPUT' || tag === 'TEXTAREA') return;
            if (!hasBindings()) return;
            e.preventDefault();
            openSettings();
        }
    }

    function bindModalChrome() {
        if (!ensureEls()) return;
        backdropEl.addEventListener('click', requestClose);
        modalEl.querySelectorAll('[data-role="close"]').forEach(function (el) {
            el.addEventListener('click', requestClose);
        });
        const saveBtn = modalEl.querySelector('[data-role="save"]');
        if (saveBtn) saveBtn.addEventListener('click', saveAndClose);
        const cancelBtn = modalEl.querySelector('[data-role="cancel"]');
        if (cancelBtn) cancelBtn.addEventListener('click', requestClose);
        modalEl.querySelectorAll('[data-role="confirm-save"]').forEach(function (el) {
            el.addEventListener('click', saveAndClose);
        });
        modalEl.querySelectorAll('[data-role="confirm-discard"]').forEach(function (el) {
            el.addEventListener('click', confirmDiscard);
        });
        modalEl.querySelectorAll('[data-role="confirm-keep"]').forEach(function (el) {
            el.addEventListener('click', confirmKeepEditing);
        });
        modalEl.querySelectorAll('.settings-section-header[data-role="section-toggle"]').forEach(function (h) {
            h.addEventListener('click', function () {
                h.parentElement.classList.toggle('expanded');
            });
        });
        const body = modalEl.querySelector('.settings-modal-body');
        if (body) {
            body.addEventListener('change', updateDirtyUI);
            body.addEventListener('input', updateDirtyUI);
        }
    }

    function enableNavButton() {
        const navBtn = document.getElementById('nav-settings-btn');
        if (navBtn) {
            navBtn.classList.remove('is-disabled');
            navBtn.removeAttribute('aria-disabled');
            navBtn.removeAttribute('tabindex');
            navBtn.title = 'Settings (Ctrl+,)';
        }
        const params = new URLSearchParams(window.location.search);
        if (params.get('settings') === '1') {
            params.delete('settings');
            const q = params.toString();
            const cleaned = window.location.pathname + (q ? '?' + q : '') + window.location.hash;
            window.history.replaceState(null, '', cleaned);
            setTimeout(openSettings, 0);
        }
    }

    document.addEventListener('DOMContentLoaded', function () {
        bindModalChrome();
        autoWire();
        if (hasBindings()) enableNavButton();
        consumeSavedToast();
    });
    document.addEventListener('keydown', onKeydown);

    // Globals used by the nav gear's inline onclick fallback.
    window.openSettings = openSettings;
    window.closeSettings = closeModal;
})();
