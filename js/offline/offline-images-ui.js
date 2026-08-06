// Image corpus picker UI in the offline settings section.
(function () {
    'use strict';

    var PREF_KEY = 'offline_img_editions';
    var root, estimateEl, storageEl, syncBtn, pauseBtn, progressEl, fillEl, labelEl;
    var imagesMap = null;
    var syncing = false;
    var pauseRequested = false;

    function $(id) { return document.getElementById(id); }
    function fmt(n) { return window.OfflineImages.formatBytes(n); }

    // Pure helpers, exported for tests.
    function parsePickerCsv(raw) { return (raw || '').split(',').filter(Boolean); }
    function progressPct(done, total) { return total ? Math.round(done / total * 100) : 100; }
    function quotaExceeded(totalBytes, quota, usage) {
        return totalBytes > ((quota || 0) - (usage || 0)) * 0.9;
    }
    function buildEstimateText(imagesMap, codes) {
        var est = window.OfflineImages.estimateSelection(imagesMap, codes);
        var text = codes.length
            ? 'Selected: ' + codes.length + ' editions, ' + est.count + ' images, ' + fmt(est.bytes)
            : 'No editions selected: no images will be downloaded.';
        if (est.missing.length) text += ' (' + est.missing.length + ' without bundles yet)';
        return text;
    }
    function buildStorageText(usage, quota) {
        return 'Storage: ' + fmt(usage || 0) + ' used of ' + fmt(quota || 0);
    }

    function selectedCodes() {
        return parsePickerCsv(window.EditionsPicker.serialize(root));
    }

    function loadSelection() {
        var codes = parsePickerCsv(localStorage.getItem(PREF_KEY));
        root.querySelectorAll('.editions-grid input[type="checkbox"]').forEach(function (cb) {
            cb.checked = codes.indexOf(cb.name) >= 0;
        });
        window.EditionsPicker.refresh(root);
    }

    function fetchManifest() {
        return window.OfflineDB.getMeta('manifest').then(function (m) {
            imagesMap = (m && m.images) || {};
            renderEstimates();
        }).catch(function () {
            imagesMap = {};
            renderEstimates();
        });
    }

    function groupSizeSpan(group) {
        var span = group.querySelector('.editions-group-size');
        if (!span) {
            span = document.createElement('span');
            span.className = 'editions-group-size';
            var header = group.querySelector('.editions-group-header');
            header.insertBefore(span, header.querySelector('.group-chevron'));
        }
        return span;
    }

    function renderEstimates() {
        if (!imagesMap) { fetchManifest(); return; }
        // If no manifest data, show placeholder
        if (Object.keys(imagesMap).length === 0) {
            estimateEl.textContent = 'Run a price sync first to see image size estimates.';
            root.querySelectorAll('.editions-group').forEach(function (group) {
                groupSizeSpan(group).textContent = '';
            });
            syncBtn.disabled = syncing || selectedCodes().length === 0;
            return;
        }
        root.querySelectorAll('.editions-group').forEach(function (group) {
            var codes = [];
            group.querySelectorAll('.editions-grid input[type="checkbox"]:checked').forEach(function (cb) {
                codes.push(cb.name);
            });
            var est = window.OfflineImages.estimateSelection(imagesMap, codes);
            groupSizeSpan(group).textContent = est.bytes ? fmt(est.bytes) : '';
        });
        var codes = selectedCodes();
        estimateEl.textContent = buildEstimateText(imagesMap, codes);
        syncBtn.disabled = syncing || codes.length === 0;
    }

    function renderStorage() {
        if (!(navigator.storage && navigator.storage.estimate)) return;
        navigator.storage.estimate().then(function (est) {
            storageEl.textContent = buildStorageText(est.usage, est.quota);
        });
    }

    function imgStates() {
        return window.OfflineDB.getAllRows('imgstate').then(function (rows) {
            var map = {};
            rows.forEach(function (r) { map[r.code] = r; });
            return map;
        });
    }

    function startSync() {
        if (syncing) return;
        if (!window.OfflineMode.enabled()) { labelEl.textContent = 'Enable offline mode first.'; return; }
        var codes = selectedCodes();
        if (!codes.length) return;
        // Explicit save: pref roams via userstate; the IDB mirror is what sync() reads before messaging the worker.
        localStorage.setItem(PREF_KEY, codes.join(','));
        Promise.all([
            window.OfflineDB.setMeta('imgEditionsSel', codes),
            imgStates(),
            fetchManifest(),
            navigator.storage && navigator.storage.estimate
                ? navigator.storage.estimate() : Promise.resolve(null),
        ]).then(function (res) {
            var plan = window.OfflineImages.computeWorkList(imagesMap || {}, codes, res[1]);
            var est = res[3];
            progressEl.hidden = false;
            if (est && quotaExceeded(plan.totalBytes, est.quota, est.usage)) {
                fillEl.style.width = '0%';
                labelEl.textContent = 'Not enough storage: this download needs ' + fmt(plan.totalBytes) +
                    ' but only ' + fmt((est.quota || 0) - (est.usage || 0)) +
                    ' is free. Narrow the selection.';
                return;
            }
            syncing = true;
            pauseRequested = false;
            syncBtn.disabled = true;
            pauseBtn.hidden = false;
            pauseBtn.disabled = false;
            fillEl.style.width = '0%';
            labelEl.textContent = plan.work.length
                ? 'Syncing ' + plan.work.length + ' bundles (' + fmt(plan.totalBytes) + ')...'
                : 'Images already up to date.';
            window.OfflineMode.sync();
        }).catch(function (err) {
            syncing = false;
            labelEl.textContent = 'Image sync failed: ' + (err && err.message || err);
            pauseBtn.hidden = true;
        });
    }

    function onSyncMessage(e) {
        var msg = e.detail;
        if (!msg) return;
        if (msg.type === 'progress' && msg.stage === 'images') {
            var pct = progressPct(msg.done, msg.total);
            fillEl.style.width = pct + '%';
            labelEl.textContent = msg.done + ' / ' + msg.total + ' bundles (' +
                fmt(msg.bytes || 0) + ') ' + (msg.code || '');
        } else if (msg.type === 'done' && syncing) {
            syncing = false;
            pauseBtn.hidden = true;
            labelEl.textContent = pauseRequested
                ? 'Paused. Sync Images Now resumes where it left off.'
                : 'Image sync finished.';
            pauseRequested = false;
            renderEstimates();
            renderStorage();
        } else if (msg.type === 'error' && syncing) {
            syncing = false;
            pauseBtn.hidden = true;
            pauseRequested = false;
            labelEl.textContent = 'Sync stopped: ' + msg.message +
                (msg.stage ? ' (' + msg.stage + ')' : '');
            renderEstimates();
            renderStorage();
        }
    }

    window.OfflineImagesUI = {
        parsePickerCsv: parsePickerCsv,
        progressPct: progressPct,
        quotaExceeded: quotaExceeded,
        buildEstimateText: buildEstimateText,
        buildStorageText: buildStorageText,
    };

    document.addEventListener('DOMContentLoaded', function () {
        root = $('offline-img-editions-picker');
        if (!root || !window.EditionsPicker || !window.OfflineImages || !window.OfflineDB) return;
        if (!(window.OfflineMode && window.OfflineMode.available && window.OfflineMode.available())) return;
        estimateEl = $('offline-img-estimate');
        storageEl = $('offline-img-storage');
        syncBtn = $('offline-img-sync-btn');
        pauseBtn = $('offline-img-pause-btn');
        progressEl = $('offline-img-progress');
        fillEl = progressEl.querySelector('.offline-img-progress-fill');
        labelEl = progressEl.querySelector('.offline-img-progress-label');

        window.EditionsPicker.init(root);
        loadSelection();
        root.addEventListener('change', renderEstimates);
        syncBtn.addEventListener('click', startSync);
        pauseBtn.addEventListener('click', function () {
            pauseRequested = true;
            pauseBtn.disabled = true;
            labelEl.textContent = 'Pausing after the current bundle...';
            window.OfflineMode.cancelSync();
        });
        document.addEventListener('offline:sync-message', onSyncMessage);

        var gear = $('nav-settings-btn');
        if (gear) {
            gear.addEventListener('click', function () {
                if (syncing) return;
                loadSelection();
                fetchManifest();
                renderEstimates();
                renderStorage();
            });
        }
        renderStorage();
    });
})();
