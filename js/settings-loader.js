/* Settings loader. The modal's scripts and stylesheets load the first time
   the modal is asked for (the gear, Ctrl+Comma, a ?settings= link or the
   toast after a save) rather than with every page; until then this holds
   window.openSettings and the shortcut, and settings.js takes them over
   once it runs. */
(function () {
    'use strict';

    // The same ?hash= cache-buster the templates give every asset
    var src = document.currentScript ? document.currentScript.src : '';
    var hash = (/[?&]hash=([^&]*)/.exec(src) || [])[1] || '';
    function url(path) { return path + '?hash=' + hash; }

    function stylesheet(path) {
        return new Promise(function (resolve, reject) {
            // The alert pages link the modal's sheet themselves
            if (document.querySelector('link[href^="' + path + '"]')) { resolve(); return; }
            var link = document.createElement('link');
            link.rel = 'stylesheet';
            link.type = 'text/css';
            link.href = url(path);
            link.onload = function () { resolve(); };
            link.onerror = function () {
                // Gone from the head, so the next open links it again
                link.remove();
                reject(new Error(path + ' did not load'));
            };
            document.head.appendChild(link);
        });
    }

    function preload(path) {
        var link = document.createElement('link');
        link.rel = 'preload';
        link.as = 'script';
        link.href = url(path);
        document.head.appendChild(link);
    }

    function script(path) {
        return new Promise(function (resolve, reject) {
            var s = document.createElement('script');
            s.src = url(path);
            s.async = false;
            s.onload = function () { resolve(); };
            s.onerror = function () { reject(new Error(path + ' did not load')); };
            document.head.appendChild(s);
        });
    }

    var loading = null;

    function load() {
        if (loading) return loading;
        // settings.js wires the picker and the shell as the body lands, so it goes last
        var scripts = ['/js/editions-picker.js', '/js/settings-shell.js', '/js/settings.js'];
        scripts.forEach(preload);
        // Sheets first: settings.js unhides the modal's shell as it runs
        loading = Promise.all([stylesheet('/css/settings-modal.css'), stylesheet('/css/editions-picker.css')])
            .then(function () { return Promise.all(scripts.map(script)); })
            .then(function () { document.removeEventListener('keydown', onKeydown); })
            .catch(function (err) {
                loading = null;
                throw err;
            });
        return loading;
    }

    function failed(err) {
        if (window.console) window.console.error('settings: ' + err.message);
    }

    function open(tab) {
        load().then(function () {
            if (window.openSettings !== open) window.openSettings(tab);
        }, failed);
    }

    function onKeydown(e) {
        if (!(e.ctrlKey || e.metaKey) || e.key !== ',') return;
        var tag = (document.activeElement && document.activeElement.tagName) || '';
        if (tag === 'INPUT' || tag === 'TEXTAREA') return;
        e.preventDefault();
        open();
    }

    // A ?settings= link and the toast after a save are settings.js's to act
    // on; it does so as it runs.
    function onReady() {
        var wanted = new URLSearchParams(window.location.search).has('settings');
        try { wanted = wanted || sessionStorage.getItem('settingsSavedToast') === '1'; } catch (e) {}
        if (wanted) load().catch(failed);
    }

    document.addEventListener('keydown', onKeydown);
    window.openSettings = open;
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', onReady);
    else onReady();
})();
