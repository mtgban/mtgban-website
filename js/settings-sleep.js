(function () {
    'use strict';

    function pickerEl() { return document.getElementById('sleep-editions-picker'); }

    function setList(containerId, cookieName) {
        const list = getCookie(cookieName);
        const items = list ? list.split(',').filter(Boolean) : [];
        const container = document.getElementById(containerId);
        if (!container) return;
        container.querySelectorAll('input[type="checkbox"]').forEach(function (cb) {
            cb.checked = items.indexOf(cb.name) >= 0;
        });
    }
    function getList(containerId) {
        const container = document.getElementById(containerId);
        if (!container) return '';
        const names = [];
        container.querySelectorAll('input[type="checkbox"]:checked').forEach(function (cb) {
            names.push(cb.name);
        });
        return names.join(',') + (names.length ? ',' : '');
    }

    function load() {
        setList('settings-sleep-sellers', 'SleepersSellersList');
        setList('settings-sleep-vendors', 'SleepersVendorsList');
        const p = pickerEl();
        if (p && window.EditionsPicker) {
            window.EditionsPicker.load(p, 'SleepersEditionList');
        }
    }
    function save() {
        setCookie('SleepersSellersList', getList('settings-sleep-sellers'), 1000);
        setCookie('SleepersVendorsList', getList('settings-sleep-vendors'), 1000);
        const p = pickerEl();
        if (p && window.EditionsPicker) {
            window.EditionsPicker.save(p, 'SleepersEditionList');
        }
    }
    function serialize() {
        const p = pickerEl();
        return JSON.stringify({
            sellers: getList('settings-sleep-sellers'),
            vendors: getList('settings-sleep-vendors'),
            editions: p && window.EditionsPicker ? window.EditionsPicker.serialize(p) : '',
        });
    }

    document.addEventListener('DOMContentLoaded', function () {
        const p = pickerEl();
        if (p && window.EditionsPicker) window.EditionsPicker.init(p);
        if (window.SettingsModal) {
            window.SettingsModal.register({ load: load, save: save, serialize: serialize });
        }
    });
})();
