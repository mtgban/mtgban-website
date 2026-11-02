/* Command palette loader. The palette's files (command-palette.js, the
   chips, the guide data and its stylesheet) load on the first Ctrl/Cmd+K
   or "/" rather than with every page; until then this holds the shortcuts
   and, once the files are in, replays the keystroke that fetched them so
   the palette opens the way it would have. */
(function () {
    'use strict';

    if (!window.__BAN_PALETTE) return;

    // The same ?hash= cache-buster the templates give every asset
    var src = document.currentScript ? document.currentScript.src : '';
    var hash = (/[?&]hash=([^&]*)/.exec(src) || [])[1] || '';
    function url(path) { return path + '?hash=' + hash; }

    function stylesheet(path) {
        return new Promise(function (resolve, reject) {
            var link = document.createElement('link');
            link.rel = 'stylesheet';
            link.type = 'text/css';
            link.href = url(path);
            link.onload = function () { resolve(); };
            link.onerror = function () {
                // Gone from the head, so the next press links it again
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
        // command-palette.js reads the other two as it runs, so it goes last;
        // the guide page already carries its own guide-data.js.
        var scripts = ['/js/palette-chips.js'];
        if (!window.__BAN_GUIDE) scripts.push('/js/guide-data.js');
        scripts.push('/js/command-palette.js');
        scripts.forEach(preload);
        // The palette builds its overlay as its script runs, so the
        // stylesheet has to be in place before any script executes.
        loading = stylesheet('/css/command-palette.css').then(function () {
            return Promise.all(scripts.map(script));
        }).catch(function (err) {
            loading = null;
            throw err;
        });
        return loading;
    }

    // The palette's own shortcuts: Ctrl/Cmd+K anywhere, "/" outside a field.
    function wanted(e) {
        if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.keyCode === 75)) return true;
        if (e.key !== '/') return false;
        var el = document.activeElement;
        var tag = el ? el.tagName.toLowerCase() : '';
        if (tag === 'input' || tag === 'textarea' || tag === 'select') return false;
        return !(el && el.isContentEditable);
    }

    function onKeydown(e) {
        if (!wanted(e) || window.innerWidth < 768) return;
        e.preventDefault();
        document.removeEventListener('keydown', onKeydown);
        // A Ctrl+K matched by keyCode alone (a non-Latin layout) replays as 'k'
        var replay = new KeyboardEvent('keydown', {
            key: e.key === '/' ? '/' : 'k', keyCode: e.keyCode,
            ctrlKey: e.ctrlKey, metaKey: e.metaKey, bubbles: true, cancelable: true
        });
        load().then(function () {
            document.dispatchEvent(replay);
        }, function (err) {
            document.addEventListener('keydown', onKeydown);
            if (window.console) window.console.error('command palette: ' + err.message);
        });
    }

    document.addEventListener('keydown', onKeydown);
})();
