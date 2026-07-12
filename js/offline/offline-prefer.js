// Device-local "prefer offline" flag: engage offline search on this device
// (e.g. bad venue wifi) without roaming to other devices.
(function () {
    'use strict';
    var KEY = 'offline_prefer';
    function get() {
        try { return localStorage.getItem(KEY) === 'true'; } catch (e) { return false; }
    }
    function set(on) {
        try {
            if (on) localStorage.setItem(KEY, 'true');
            else localStorage.removeItem(KEY);
        } catch (e) {}
    }
    self.OfflinePrefer = { KEY: KEY, get: get, set: set };
})();
