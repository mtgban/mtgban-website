// This device's choice of offline results that update as you type. Left out of
// the synced preferences, as the default differs between desktop and mobile.
(function (root) {
    'use strict';
    var KEY = 'offline_live_search';
    var DEFAULTS = {desktop: true, mobile: false};

    function on(surface) {
        var stored = null;
        try { stored = localStorage.getItem(KEY); } catch (e) {}
        return stored === null ? DEFAULTS[surface] : stored === 'true';
    }

    function set(value) {
        try { localStorage.setItem(KEY, value ? 'true' : 'false'); } catch (e) {}
        if (root.BAN && root.BAN.track) root.BAN.track('ui.offline.live', value ? 'on' : 'off');
    }

    root.OfflineLive = {on: on, set: set};
})(typeof self !== 'undefined' ? self : globalThis);
