(function () {
    'use strict';

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

    function setPill(containerId, cookieName) {
        const val = getCookie(cookieName);
        const container = document.getElementById(containerId);
        if (!container) return;
        container.querySelectorAll('.settings-pill').forEach(function (btn) {
            btn.classList.toggle('active', btn.dataset.val === val);
        });
    }

    function getPill(containerId) {
        const container = document.getElementById(containerId);
        if (!container) return '';
        const active = container.querySelector('.settings-pill.active');
        return active ? active.dataset.val : '';
    }

    function setSelect(cookieName) {
        const val = getCookie(cookieName);
        const sel = document.querySelector('#settings-modal select[data-cookie="' + cookieName + '"]');
        if (!sel) return;
        sel.value = val;
    }

    function getSelect(cookieName) {
        const sel = document.querySelector('#settings-modal select[data-cookie="' + cookieName + '"]');
        return sel ? sel.value : '';
    }

    function setMiscOpts() {
        const list = getCookie('SearchMiscOpts');
        const items = list ? list.split(',').filter(Boolean) : [];
        document.querySelectorAll('#settings-modal [data-misc]').forEach(function (el) {
            el.checked = items.indexOf(el.dataset.misc) >= 0;
        });
    }

    function getMiscOpts() {
        const names = [];
        document.querySelectorAll('#settings-modal [data-misc]:checked').forEach(function (el) {
            names.push(el.dataset.misc);
        });
        return names.join(',') + (names.length ? ',' : '');
    }

    function bindPills() {
        document.querySelectorAll('#settings-modal .settings-pills').forEach(function (group) {
            group.addEventListener('click', function (e) {
                const btn = e.target.closest('.settings-pill');
                if (!btn) return;
                group.querySelectorAll('.settings-pill').forEach(function (p) {
                    p.classList.toggle('active', p === btn);
                });
                // Manually fire change so the modal marks dirty
                group.dispatchEvent(new Event('change', { bubbles: true }));
            });
        });
    }

    function load() {
        setList('settings-search-sellers', 'SearchSellersList');
        setList('settings-search-vendors', 'SearchVendorsList');
        setPill('settings-search-sort', 'SearchDefaultSort');
        setPill('settings-search-listing', 'SearchListingPriority');
        setPill('settings-search-buylist-secondary', 'SearchBuylistSecondary');
        setSelect('SearchSellersPriority');
        setSelect('SearchVendorsPriority');
        setMiscOpts();
    }

    function save() {
        setCookie('SearchSellersList', getList('settings-search-sellers'), 1000);
        setCookie('SearchVendorsList', getList('settings-search-vendors'), 1000);
        setCookie('SearchDefaultSort', getPill('settings-search-sort'), 1000);
        setCookie('SearchListingPriority', getPill('settings-search-listing'), 1000);
        setCookie('SearchBuylistSecondary', getPill('settings-search-buylist-secondary'), 1000);
        setCookie('SearchSellersPriority', getSelect('SearchSellersPriority'), 1000);
        setCookie('SearchVendorsPriority', getSelect('SearchVendorsPriority'), 1000);
        setCookie('SearchMiscOpts', getMiscOpts(), 1000);
    }

    function serialize() {
        return JSON.stringify({
            sellers: getList('settings-search-sellers'),
            vendors: getList('settings-search-vendors'),
            sort: getPill('settings-search-sort'),
            listing: getPill('settings-search-listing'),
            buylist2: getPill('settings-search-buylist-secondary'),
            sellersPriority: getSelect('SearchSellersPriority'),
            vendorsPriority: getSelect('SearchVendorsPriority'),
            misc: getMiscOpts(),
        });
    }

    document.addEventListener('DOMContentLoaded', function () {
        bindPills();
        if (window.SettingsModal) {
            window.SettingsModal.register({ load: load, save: save, serialize: serialize });
        }
    });
})();
