(function () {
    'use strict';

    function getContainer() { return document.getElementById('settings-arbit-vendors'); }

    function currentCookie() {
        const c = getContainer();
        return c ? c.dataset.cookie : '';
    }

    function setList() {
        const container = getContainer();
        const cookie = currentCookie();
        if (!container || !cookie) return;
        const list = getCookie(cookie);
        const items = list ? list.split(',').filter(Boolean) : [];
        container.querySelectorAll('input[type="checkbox"]').forEach(function (cb) {
            cb.checked = items.indexOf(cb.name) >= 0;
        });
    }

    function getListVal() {
        const container = getContainer();
        if (!container) return '';
        const names = [];
        container.querySelectorAll('input[type="checkbox"]:checked').forEach(function (cb) {
            names.push(cb.name);
        });
        return names.join(',') + (names.length ? ',' : '');
    }

    function load() { setList(); }
    function save() {
        const cookie = currentCookie();
        if (!cookie) return;
        setCookie(cookie, getListVal(), 1000);
    }
    function serialize() { return getListVal(); }

    document.addEventListener('DOMContentLoaded', function () {
        if (window.SettingsModal) {
            window.SettingsModal.register({ load: load, save: save, serialize: serialize });
        }
    });
})();
