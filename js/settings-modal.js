(function () {
    'use strict';

    let registry = null;   // { load, save, serialize } for the current page
    let baseline = null;   // snapshot of state on open, used for dirty diff
    let modalEl = null;
    let backdropEl = null;

    function ensureEls() {
        if (modalEl && backdropEl) return true;
        modalEl = document.getElementById('settings-modal');
        backdropEl = document.getElementById('settings-backdrop');
        return !!(modalEl && backdropEl);
    }

    function serializeState() {
        if (registry && typeof registry.serialize === 'function') {
            return registry.serialize();
        }
        return '';
    }

    function updateDirtyUI() {
        const saveBtn = modalEl.querySelector('.settings-btn.primary[data-role="save"]');
        if (!saveBtn) return;
        const dirty = serializeState() !== baseline;
        saveBtn.disabled = !dirty;
        modalEl.dataset.dirty = dirty ? '1' : '0';
    }

    function isDirty() {
        return modalEl && modalEl.dataset.dirty === '1';
    }

    function openSettings() {
        if (!ensureEls() || !registry) return;
        if (typeof registry.load === 'function') registry.load();
        baseline = serializeState();
        modalEl.dataset.dirty = '0';
        updateDirtyUI();
        backdropEl.classList.add('open');
        modalEl.classList.add('open');
        if (window.lucide && lucide.createIcons) {
            lucide.createIcons({ nameAttr: 'data-lucide', attrs: {} });
        }
    }

    function closeModal() {
        if (!ensureEls()) return;
        modalEl.classList.remove('open', 'confirm-open');
        backdropEl.classList.remove('open');
    }

    function requestClose() {
        if (!ensureEls()) return;
        if (isDirty()) {
            modalEl.classList.add('confirm-open');
            return;
        }
        closeModal();
    }

    function confirmDiscard() {
        closeModal();
    }

    function confirmKeepEditing() {
        modalEl.classList.remove('confirm-open');
    }

    function saveAndClose() {
        if (!registry || typeof registry.save !== 'function') {
            closeModal();
            return;
        }
        registry.save();
        window.location.reload();
    }

    function onBackdropClick() { requestClose(); }

    function onKeydown(e) {
        if (e.key === 'Escape' && ensureEls() && modalEl.classList.contains('open')) {
            if (modalEl.classList.contains('confirm-open')) {
                confirmKeepEditing();
            } else {
                requestClose();
            }
            e.preventDefault();
            return;
        }
        const isCmdOrCtrl = e.ctrlKey || e.metaKey;
        if (isCmdOrCtrl && e.key === ',') {
            const tag = (document.activeElement && document.activeElement.tagName) || '';
            if (tag === 'INPUT' || tag === 'TEXTAREA') return;
            if (!registry) return;
            e.preventDefault();
            openSettings();
        }
    }

    function registerPage(config) {
        registry = config;
        // Hook up the nav gear so it can show itself
        const navBtn = document.getElementById('nav-settings-btn');
        if (navBtn) navBtn.hidden = false;
        // Auto-open if requested via URL
        const params = new URLSearchParams(window.location.search);
        if (params.get('settings') === '1') {
            // Strip the param from the address bar so a refresh doesn't re-open
            params.delete('settings');
            const q = params.toString();
            const cleaned = window.location.pathname + (q ? '?' + q : '') + window.location.hash;
            window.history.replaceState(null, '', cleaned);
            // Defer to next tick so the rest of the page finishes initializing
            setTimeout(openSettings, 0);
        }
    }

    function bindModalElements() {
        if (!ensureEls()) return;
        backdropEl.addEventListener('click', onBackdropClick);
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
        // Any change inside the modal body flags dirty
        const body = modalEl.querySelector('.settings-modal-body');
        if (body) {
            body.addEventListener('change', updateDirtyUI);
            body.addEventListener('input', updateDirtyUI);
        }
    }

    document.addEventListener('DOMContentLoaded', bindModalElements);
    document.addEventListener('keydown', onKeydown);

    window.SettingsModal = {
        register: registerPage,
        open: openSettings,
        close: closeModal,
        markDirty: updateDirtyUI,
    };
    // Convenience globals for the gear button's inline onclick
    window.openSettings = openSettings;
    window.closeSettings = closeModal;
})();
