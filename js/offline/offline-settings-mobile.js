// Mobile settings drawer binder for offline mode opt-in.
(function () {
    'use strict';

    function mFmtBytes(n) {
        if (!n) return '0 B';
        var units = ['B', 'KB', 'MB', 'GB'];
        var i = 0;
        while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
        return (i === 0 ? n : n.toFixed(1)) + ' ' + units[i];
    }

    function paintStatus(text) {
        var el = document.getElementById('m-offline-status');
        if (el) el.textContent = text || '';
    }

    function paintUsage() {
        var el = document.getElementById('m-offline-usage');
        if (!el || !window.OfflineMode) return;
        if (!OfflineMode.enabled()) { el.textContent = ''; return; }
        var s = OfflineMode.status();
        el.textContent = 'Using ' + mFmtBytes(s.bytes) +
            (s.lastSync ? ', last sync ' + new Date(s.lastSync).toLocaleString() : ', not synced yet');
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

    function repaint() {
        paintToggle();
        paintAuthNotice();
        paintUsage();
    }

    // Called by the onclick in the HTML template.
    function handleToggle(el) {
        if (!window.OfflineMode) return;
        el.classList.add('m-toggle-busy');
        var enabling = !OfflineMode.enabled();
        var op = enabling ? OfflineMode.enable() : OfflineMode.disable();
        paintStatus(enabling ? 'Enabling...' : 'Disabling...');
        op.then(function () {
            el.classList.remove('m-toggle-busy');
            repaint();
            if (OfflineMode.enabled()) paintStatus('Sync started');
        }).catch(function (err) {
            console.warn('offline:', err && err.message);
            el.classList.remove('m-toggle-busy');
            paintStatus('Error: ' + (err && err.message || 'unknown'));
        });
    }

    function init() {
        if (!window.OfflineMode || !OfflineMode.available()) return;
        var section = document.getElementById('m-offline-section');
        if (!section) return;
        section.style.display = '';
        repaint();

        // Sync progress: offline-mode.js dispatches this event on each worker message.
        document.addEventListener('offline:sync-message', function (e) {
            var m = e.detail || {};
            if (m.type === 'progress') {
                paintStatus('Syncing: ' + m.stage + ' ' + m.done + '/' + m.total);
            } else if (m.type === 'done') {
                paintStatus('Synced, ' + m.changedSets + ' sets updated');
                paintUsage();
            } else if (m.type === 'error') {
                paintStatus('Sync error: ' + m.message);
                paintAuthNotice();
            }
        });

        // Keep toggle in sync when another tab changes the localStorage pref.
        window.addEventListener('storage', function (e) {
            if (e.key === 'offline_mode') repaint();
        });
    }

    self.OfflineSettingsMobile = { init: init, handleToggle: handleToggle };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
