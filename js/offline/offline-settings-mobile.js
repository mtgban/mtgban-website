// Mobile settings drawer binder for offline mode opt-in.
(function () {
    'use strict';

    function paintStatus(text) {
        var el = document.getElementById('m-offline-status');
        if (el) el.textContent = text || '';
    }

    function paintUsage() {
        var el = document.getElementById('m-offline-usage');
        if (!el || !window.OfflineMode) return;
        if (!OfflineMode.enabled()) { el.textContent = ''; return; }
        el.textContent = OfflineMode.usageText(OfflineMode.status());
    }

    function paintAuthNotice() {
        var el = document.getElementById('m-offline-auth-notice');
        if (!el || !window.OfflineMode) return;
        el.hidden = !OfflineMode.status().authLapsed;
    }

    function paintToggle() {
        var toggle = document.getElementById('m-offline-toggle');
        if (!toggle || !window.OfflineMode) return;
        toggle.classList.toggle('on', OfflineMode.enabled());
    }

    function paintLive() {
        var row = document.getElementById('m-offline-live-row');
        var toggle = document.getElementById('m-offline-live-toggle');
        if (!row || !toggle || !window.OfflineMode) return;
        row.hidden = !OfflineMode.enabled();
        toggle.classList.toggle('on', OfflineLive.on('mobile'));
    }

    function repaint() {
        paintToggle();
        paintLive();
        paintAuthNotice();
        paintUsage();
    }

    // Called by the onclick in the HTML template.
    function handleToggle(el) {
        if (!window.OfflineMode) return;
        var enabling = !OfflineMode.enabled();
        if (!enabling && !OfflineMode.confirmDisable()) return;
        el.classList.add('m-toggle-busy');
        var op = enabling ? OfflineMode.enable() : OfflineMode.disable();
        paintStatus(enabling ? 'Enabling...' : 'Disabling...');
        op.then(function () {
            el.classList.remove('m-toggle-busy');
            repaint();
            paintStatus(OfflineMode.enabled() ? 'Sync started' : '');
        }).catch(function (err) {
            console.warn('offline:', err && err.message);
            el.classList.remove('m-toggle-busy');
            paintStatus('Error: ' + (err && err.message || 'unknown'));
        });
    }

    // Called by the onclick in the HTML template.
    function handleLive() {
        OfflineLive.set(!OfflineLive.on('mobile'));
        paintLive();
    }

    function init() {
        if (!window.OfflineMode || !OfflineMode.available()) return;
        var section = document.getElementById('m-offline-section');
        if (!section) return;
        section.style.display = '';
        repaint();
        // The first paint has no measurements yet, and reads as an empty store.
        if (OfflineMode.enabled()) OfflineMode.refreshUsage().then(repaint);

        // Sync progress: offline-mode.js dispatches this event on each worker message.
        document.addEventListener('offline:sync-message', function (e) {
            var m = e.detail || {};
            if (m.type === 'progress') {
                paintStatus('Syncing: ' + m.stage + ' ' + m.done + '/' + m.total);
            } else if (m.type === 'done') {
                paintStatus(OfflineMode.doneStatusText(m, OfflineMode.status()));
            } else if (m.type === 'error') {
                paintStatus('Sync error: ' + m.message);
                paintAuthNotice();
            }
        });

        // Fired once offline-mode.js has re-measured after a finished sync.
        document.addEventListener('offline:synced', paintUsage);

        // Keep toggle in sync when another tab changes the localStorage pref.
        window.addEventListener('storage', function (e) {
            if (e.key === 'offline_mode') repaint();
        });
    }

    self.OfflineSettingsMobile = { init: init, handleToggle: handleToggle, handleLive: handleLive };

    // Deferred ahead of offline-mode.js, which only exists by DOM ready.
    document.addEventListener('DOMContentLoaded', init);
})();
