// Anonymous feature counts: what a reader clicks, merged in memory and posted to /api/metrics.
(function () {
    var BAN = window.BAN = window.BAN || {};
    var ENDPOINT = '/api/metrics';
    var WAIT_MS = 10000;
    var MAX_COUNT = 50;
    var MAX_KEYS = 500;
    var POST_ENTRIES = 50;
    var POST_CHARS = 7500;
    var PRINTABLE = /^[\x20-\x7e]*$/;
    var WIRE = { n: 1, s: 1, v: 1, c: 1 };
    var QUEUE_KEY = 'mtgban_metrics_queue';
    var QUEUE_MAX = 100;
    var QUEUE_DAYS = 7;
    var QUEUE_CHARS = 65536;
    var DAY_MS = 86400000;

    // Stubs first, so a caller never throws whatever happens below.
    BAN.track = function () {};
    BAN.metrics = { bump: function () { return false; } };

    var cfg;
    var off = true;
    try {
        cfg = window.BAN_METRICS;
        off = !cfg || cfg.on !== true || optedOut();
    } catch (e) {}
    if (off) {
        try {
            localStorage.removeItem(QUEUE_KEY);
            localStorage.removeItem('mtgban_metrics_snap');
        } catch (e) {}
        return;
    }

    // optedOut reads Do Not Track in each form browsers expose it, and Global Privacy Control.
    function optedOut() {
        var dnt = [navigator.doNotTrack, window.doNotTrack, navigator.msDoNotTrack];
        for (var i = 0; i < dnt.length; i++) {
            if (dnt[i] === '1' || dnt[i] === 'yes') return true;
        }
        return navigator.globalPrivacyControl === true;
    }

    var buf = {};
    var order = [];
    var timer = 0;

    // fits is the registry's rule for every string: 40 printable ASCII characters.
    function fits(s, max) {
        return typeof s === 'string' && s.length <= max && PRINTABLE.test(s);
    }

    function str(x) {
        return x === undefined || x === null ? '' : String(x);
    }

    // cleanExtra returns the kept fields, null when none are kept, or false to drop the call.
    function cleanExtra(extra) {
        if (Object.prototype.toString.call(extra) !== '[object Object]') return false;
        var names = [];
        for (var k in extra) {
            if (Object.prototype.hasOwnProperty.call(extra, k)) names.push(k);
        }
        if (names.length > 4) return false;
        var kept = null;
        for (var i = 0; i < names.length; i++) {
            var name = names[i];
            if (WIRE[name]) continue;
            var val = extra[name];
            var number = typeof val === 'number' && isFinite(val);
            if (!fits(name, 40) || !(number || fits(val, 80))) return false;
            kept = kept || {};
            kept[name] = val;
        }
        return kept;
    }

    // keyOf joins a count's parts; the printable rule keeps the newline out of each.
    function keyOf(n, s, v, x) {
        return n + '\n' + s + '\n' + v + (x ? '\n' + JSON.stringify(x) : '');
    }

    function arm() {
        if (timer) clearTimeout(timer);
        timer = setTimeout(flushTimer, WAIT_MS);
    }

    function bump(name, value, scope, extra) {
        try {
            if (typeof name !== 'string' || !name) return false;
            value = str(value);
            scope = str(scope);
            if (!fits(name, 40) || !fits(value, 40) || !fits(scope, 40)) return false;
            var x = null;
            if (extra !== undefined && extra !== null) {
                x = cleanExtra(extra);
                if (x === false) return false;
            }
            var key = keyOf(name, scope, value, x);
            var e = buf[key];
            if (e) {
                if (e.c < MAX_COUNT) e.c++;
            } else {
                if (order.length >= MAX_KEYS) return false;
                buf[key] = { n: name, s: scope, v: value, c: 1, x: x };
                order.push(key);
            }
            arm();
            return true;
        } catch (err) {
            return false;
        }
    }

    function track(name, value, scope) {
        bump(name, value, scope);
    }

    // wire turns a buffered or queued count into the entry a post carries.
    function wire(n, s, v, c, x) {
        var w = { n: n };
        if (s) w.s = s;
        if (v) w.v = v;
        w.c = c;
        if (x) {
            for (var k in x) {
                if (Object.prototype.hasOwnProperty.call(x, k)) w[k] = x[k];
            }
        }
        return w;
    }

    // silenced re-reads the privacy signals; when one is on, the stored queue goes too.
    function silenced() {
        var on = true;
        try {
            on = optedOut();
        } catch (e) {}
        if (on) {
            try {
                localStorage.removeItem(QUEUE_KEY);
            } catch (e) {}
        }
        return on;
    }

    // take empties the buffer into wire entries, none when a privacy signal came on.
    function take() {
        var out = [];
        for (var i = 0; i < order.length; i++) {
            var e = buf[order[i]];
            out.push(wire(e.n, e.s, e.v, e.c, e.x));
        }
        buf = {};
        order = [];
        if (timer) clearTimeout(timer);
        timer = 0;
        return silenced() ? [] : out;
    }

    // posts splits entries into request bodies: 50 entries or 7,500 characters each, in order.
    function posts(entries) {
        var out = [];
        var run = [];
        var size = 2;
        for (var i = 0; i < entries.length; i++) {
            var one = JSON.stringify(entries[i]);
            if (run.length && (run.length >= POST_ENTRIES || size + 1 + one.length > POST_CHARS)) {
                out.push('[' + run.join(',') + ']');
                run = [];
                size = 2;
            }
            size += one.length + (run.length ? 1 : 0);
            run.push(one);
        }
        if (run.length) out.push('[' + run.join(',') + ']');
        return out;
    }

    function today() {
        return Math.floor(Date.now() / DAY_MS);
    }

    // queued checks one stored element: [n, s, v, c] or [n, s, v, c, extra].
    function queued(x) {
        if (!Array.isArray(x) || (x.length !== 4 && x.length !== 5)) return false;
        if (!x[0] || !fits(x[0], 40) || !fits(x[1], 40) || !fits(x[2], 40)) return false;
        var c = x[3];
        if (typeof c !== 'number' || c % 1 !== 0 || c < 1 || c > MAX_COUNT) return false;
        if (x.length === 5) {
            var kept = cleanExtra(x[4]);
            if (!kept || JSON.stringify(kept) !== JSON.stringify(x[4])) return false;
        }
        return true;
    }

    // loadQueue returns the stored queue, null when there is none, or false when it is unusable.
    function loadQueue(now) {
        var raw = localStorage.getItem(QUEUE_KEY);
        if (raw === null || raw === undefined) return null;
        if (typeof raw !== 'string' || raw.length > QUEUE_CHARS) return false;
        var q;
        try {
            q = JSON.parse(raw);
        } catch (e) {
            return false;
        }
        if (!q || typeof q.d !== 'number' || q.d % 1 !== 0 || q.d > now || now - q.d > QUEUE_DAYS) return false;
        if (!Array.isArray(q.e) || q.e.length > QUEUE_MAX) return false;
        for (var i = 0; i < q.e.length; i++) {
            if (!queued(q.e[i])) return false;
        }
        return { d: q.d, e: q.e };
    }

    // extraOf returns a wire entry's fields beyond n, s, v and c, or null.
    function extraOf(w) {
        var x = null;
        for (var k in w) {
            if (Object.prototype.hasOwnProperty.call(w, k) && !WIRE[k]) {
                x = x || {};
                x[k] = w[k];
            }
        }
        return x;
    }

    // enqueue parks entries that could not be sent, merged into the one stored queue.
    function enqueue(entries, day) {
        try {
            if (!entries || !entries.length || silenced()) return;
            var now = today();
            if (typeof day !== 'number') day = now;
            var q = loadQueue(now);
            var list = q ? q.e : [];
            var at = {};
            var i;
            for (i = 0; i < list.length; i++) {
                at[keyOf(list[i][0], list[i][1], list[i][2], list[i][4])] = list[i];
            }
            for (i = 0; i < entries.length; i++) {
                var w = entries[i];
                var x = extraOf(w);
                var key = keyOf(w.n, w.s || '', w.v || '', x);
                var hit = at[key];
                if (hit) {
                    hit[3] = Math.min(MAX_COUNT, hit[3] + w.c);
                } else if (list.length < QUEUE_MAX) {
                    hit = [w.n, w.s || '', w.v || '', Math.min(MAX_COUNT, w.c)];
                    if (x) hit.push(x);
                    list.push(hit);
                    at[key] = hit;
                }
            }
            localStorage.setItem(QUEUE_KEY, JSON.stringify({ d: q ? Math.min(q.d, day) : day, e: list }));
        } catch (e) {}
    }

    // sendQueue posts a stored queue when the network is up; an unusable one is removed.
    function sendQueue() {
        try {
            if (silenced()) return;
            var q = loadQueue(today());
            if (q === null) return;
            if (q === false) {
                localStorage.removeItem(QUEUE_KEY);
                return;
            }
            if (offline()) return;
            localStorage.removeItem(QUEUE_KEY);
            var entries = [];
            for (var i = 0; i < q.e.length; i++) {
                var x = q.e[i];
                entries.push(wire(x[0], x[1], x[2], x[3], x[4]));
            }
            send(entries, q.d);
        } catch (e) {}
    }

    function offline() {
        return navigator.onLine === false;
    }

    // send posts each body by fetch; a rejected one is parked under day.
    function send(entries, day) {
        var bodies = posts(entries);
        for (var i = 0; i < bodies.length; i++) post(bodies[i], day);
    }

    function post(body, day) {
        var park = function () {
            try {
                enqueue(JSON.parse(body), day);
            } catch (e) {}
        };
        try {
            fetch(ENDPOINT, {
                method: 'POST',
                body: body,
                keepalive: true,
                credentials: 'same-origin',
                headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
            }).then(null, park);
        } catch (e) {
            park();
        }
    }

    function flushTimer() {
        try {
            timer = 0;
            var entries = take();
            if (!entries.length) return;
            if (offline()) {
                enqueue(entries);
                return;
            }
            send(entries);
        } catch (e) {}
    }

    function flushHidden() {
        try {
            finishPerf();
            var entries = take();
            if (!entries.length) return;
            if (offline()) {
                enqueue(entries);
                return;
            }
            var bodies = posts(entries);
            for (var i = 0; i < bodies.length; i++) {
                var sent = false;
                try {
                    sent = navigator.sendBeacon(ENDPOINT, bodies[i]);
                } catch (e) {}
                if (!sent) enqueue(JSON.parse(bodies[i]));
            }
        } catch (e) {}
    }

    function onVisibility() {
        try {
            if (document.visibilityState === 'hidden') flushHidden();
        } catch (e) {}
    }

    // attr reads one attribute, absent as ''.
    function attr(node, name) {
        var v = node.getAttribute(name);
        return v === null || v === undefined ? '' : v;
    }

    // controlOf returns a label's control, by the for attribute or a descendant where control is unsupported.
    function controlOf(lab) {
        if ('control' in lab) return lab.control;
        var id = lab.htmlFor || lab.getAttribute('for');
        if (id) return document.getElementById(id);
        var list = typeof lab.querySelectorAll === 'function' ? lab.querySelectorAll('button,input,select,textarea') : [];
        for (var i = 0; i < list.length; i++) {
            if (String(list[i].type).toLowerCase() !== 'hidden') return list[i];
        }
        return null;
    }

    // relayed reports a label's click that the browser repeats on its control under the same mark.
    function relayed(t, node) {
        try {
            var lab = t.closest('label');
            if (!lab) return false;
            var hit = t.closest('a[href],button,input,select,textarea');
            if (hit && lab.contains(hit)) return false;
            var c = controlOf(lab);
            if (!c || c === t || c.disabled || typeof c.closest !== 'function') return false;
            return c.closest('[data-track]') === node;
        } catch (e) {
            return false;
        }
    }

    // newTabLink returns the nearest link above t when it is marked and its href is not javascript:.
    function newTabLink(t) {
        var link = t.closest('a[href]');
        if (!link || link.getAttribute('data-track') === null) return null;
        if (/^\s*javascript:/i.test(attr(link, 'href'))) return null;
        return link;
    }

    // onAction counts a click, middle click or submit on the nearest marked element.
    function onAction(event) {
        try {
            var t = event && event.target;
            if (!t || typeof t.closest !== 'function') return;
            var node;
            if (event.type === 'submit') {
                node = t.closest('form[data-track]');
            } else {
                node = t.closest('[data-track]');
                // A middle click opens the nearest link, so it counts that link's own mark or nothing.
                if (event.type === 'auxclick') node = event.button === 1 ? newTabLink(t) : null;
                if (!node || String(node.tagName).toUpperCase() === 'FORM') return;
                // A label's click is counted on its control's click that follows.
                if (event.type === 'click' && relayed(t, node)) return;
            }
            if (!node || typeof node.getAttribute !== 'function') return;
            track(attr(node, 'data-track'), attr(node, 'data-track-value'), attr(node, 'data-track-scope'));
        } catch (e) {}
    }

    // countLoad counts the page load, held until a prerendered page is shown.
    function countLoad() {
        if (document.prerendering !== true) {
            BAN.track('ui.load', '', cfg.page);
            return;
        }
        var held = true;
        document.addEventListener('prerenderingchange', function () {
            if (!held) return;
            held = false;
            BAN.track('ui.load', '', cfg.page);
        });
    }

    // The settings snapshot: once a UTC day per path scope, the settings off their default.
    var SNAP = 'mtgban_metrics_snap';
    var SNAP_PATHS = ['root', 'upload', 'arbit', 'reverse', 'global', 'sleepers', 'newspaper'];
    var TRUE_LIKE = { '1': 1, 'true': 1, 't': 1, 'on': 1 };

    function has(o, k) {
        return Object.prototype.hasOwnProperty.call(o, k);
    }

    // scopes is root plus the page whose own cookies this path can read.
    function scopes(pathname) {
        var seg = str(pathname).split('/')[1] || '';
        return SNAP_PATHS.indexOf(seg) > 0 ? ['root', seg] : ['root'];
    }

    // cookies parses a cookie string; the first copy of a name wins, as the most specific path.
    function cookies(cookieString) {
        var jar = {};
        var parts = str(cookieString).split(';');
        for (var i = 0; i < parts.length; i++) {
            var part = parts[i];
            var at = part.indexOf('=');
            if (at < 0) continue;
            var name = part.slice(0, at).trim();
            if (!name || has(jar, name)) continue;
            var raw = part.slice(at + 1).trim();
            if (raw.length >= 2 && raw.charAt(0) === '"' && raw.charAt(raw.length - 1) === '"') raw = raw.slice(1, -1);
            try {
                raw = decodeURIComponent(raw);
            } catch (e) {}
            jar[name] = raw;
        }
        return jar;
    }

    // rawOf reads an entry's own value: the cookie first for both, the mirror never.
    function rawOf(s, read) {
        // uploadMode, the one flag kept in both, says buylist or retail in its local copy.
        if (s.storage === 'cookie' || (s.storage === 'both' && s.kind === 'flag')) return str(read.cookie(s.name));
        if (s.storage === 'local') return str(read.local(s.name));
        return str(read.cookie(s.name)) || str(read.local(s.name));
    }

    function flagOff(on, def) {
        if (on === (def === 'on')) return '';
        return on ? 'on' : 'off';
    }

    // listItems reads a JSON array's strings, or a comma or bar separated list.
    function listItems(raw) {
        var items;
        try {
            var parsed = JSON.parse(raw);
            if (Array.isArray(parsed)) items = parsed.filter(function (x) { return typeof x === 'string'; });
        } catch (e) {}
        if (!items) items = raw.split(/[,|]/);
        var out = [];
        for (var i = 0; i < items.length; i++) {
            var it = items[i].trim();
            if (it && out.indexOf(it) < 0) out.push(it);
        }
        return out.sort();
    }

    function canonical(raw) {
        try {
            return JSON.stringify(JSON.parse(raw));
        } catch (e) {
            return null;
        }
    }

    // blobLive reports a blob that holds something other than its default or an empty shape.
    function blobLive(raw, def) {
        if (!raw || raw === def) return false;
        var parsed;
        try {
            parsed = JSON.parse(raw);
        } catch (e) {
            return true;
        }
        if (def && canonical(def) !== null && canonical(raw) === canonical(def)) return false;
        if (parsed === null) return false;
        if (Array.isArray(parsed)) {
            for (var i = 0; i < parsed.length; i++) {
                if (!parsed[i] || !parsed[i].del) return true;
            }
            return false;
        }
        if (typeof parsed === 'object') {
            for (var k in parsed) {
                if (has(parsed, k)) return true;
            }
            return false;
        }
        return true;
    }

    function queryLive(raw) {
        var q = new URLSearchParams(raw);
        var live = false;
        q.forEach(function (v, k) {
            if (k !== 'f' && k !== 't' && v !== '') live = true;
        });
        return live;
    }

    // value is '' at the default, else on, off, set or a member of the entry's enum; never the stored text.
    function value(s, read) {
        try {
            if (!s || typeof s.name !== 'string') return '';
            var def = str(s.default);
            var dot = s.name.indexOf('.');
            if (s.kind === 'flag' && dot > 0) {
                var packed = str(read.cookie(s.name.slice(0, dot)));
                if (!packed) return '';
                return flagOff(packed.split(',').indexOf(s.name.slice(dot + 1)) >= 0, def);
            }
            var raw = rawOf(s, read);
            if (!raw) return '';
            switch (s.kind) {
                case 'flag':
                    return flagOff(has(TRUE_LIKE, raw.toLowerCase()), def);
                case 'enum':
                    var list = Array.isArray(s.enum) ? s.enum : [];
                    var at = list.indexOf(raw);
                    return at >= 0 && list[at] !== def ? list[at] : '';
                case 'number':
                    var n = parseFloat(raw);
                    return isFinite(n) && n !== parseFloat(def) ? 'set' : '';
                case 'list':
                    var items = listItems(raw);
                    if (!def) return items.length ? 'set' : '';
                    return items.join(',') !== listItems(def).join(',') ? 'set' : '';
                case 'blob':
                    return blobLive(raw, def) ? 'set' : '';
                case 'query':
                    return queryLive(raw) ? 'set' : '';
            }
        } catch (e) {}
        return '';
    }

    // entries is a reader row per scope, then that scope's settings off their default, in registry order.
    function entries(settings, read, scopeList) {
        var out = [];
        for (var i = 0; i < scopeList.length; i++) {
            out.push({ n: 'state.reader', s: scopeList[i], v: '' });
            for (var j = 0; j < settings.length; j++) {
                var s = settings[j];
                if (!s || s.path !== scopeList[i]) continue;
                var v = value(s, read);
                if (v) out.push({ n: 'state.set', s: s.name, v: v });
            }
        }
        return out;
    }

    // due is the scopes the mark has not sent today.
    function due(mark, scopeList, day) {
        var m = mark && typeof mark === 'object' ? mark : {};
        return scopeList.filter(function (s) { return !has(m, s) || m[s] !== day; });
    }

    // readMark returns the stored mark as a plain object; anything else reads as {}.
    function readMark() {
        var raw = localStorage.getItem(SNAP);
        try {
            var m = JSON.parse(raw);
            if (m && typeof m === 'object' && !Array.isArray(m)) return m;
        } catch (e) {}
        return {};
    }

    var running = null;

    // snap runs steps 1 to 3 in the call, up to the registry fetch.
    function snap() {
        var mark;
        try {
            mark = readMark();
        } catch (e) {
            return Promise.resolve();
        }
        var day = today();
        var todo = due(mark, scopes(location.pathname), day);
        if (!todo.length) return Promise.resolve();
        return fetch('/api/metrics/settings.json?hash=' + encodeURIComponent(str(cfg.build)), { credentials: 'same-origin' })
            .then(function (res) {
                return res && res.status === 200 ? res.json() : null;
            })
            .then(function (body) {
                if (!body || !Array.isArray(body.settings) || optedOut()) return;
                var now = readMark();
                todo = due(now, todo, day);
                if (!todo.length) return;
                var next = {};
                for (var i = 0; i < SNAP_PATHS.length; i++) {
                    var p = SNAP_PATHS[i];
                    if (todo.indexOf(p) >= 0) next[p] = day;
                    else if (typeof now[p] === 'number' && now[p] % 1 === 0) next[p] = now[p];
                }
                localStorage.setItem(SNAP, JSON.stringify(next));
                var jar = cookies(document.cookie);
                var read = {
                    cookie: function (n) { return has(jar, n) ? jar[n] : ''; },
                    local: function (n) {
                        try {
                            return localStorage.getItem(n);
                        } catch (e) {
                            return null;
                        }
                    }
                };
                var list = entries(body.settings, read, todo);
                for (var j = 0; j < list.length; j++) {
                    var e = list[j];
                    if (e.n === 'state.reader') bump('state.reader', '', e.s);
                    else bump('state.set', e.v, e.s);
                }
            })
            .then(null, function () {});
    }

    // run starts one snapshot; a call while one is in flight shares it.
    function run() {
        if (running) return running;
        try {
            running = snap();
        } catch (e) {
            running = Promise.resolve();
        }
        var done = function () { running = null; };
        running.then(done, done);
        return running;
    }

    // startSnapshot runs it once, after the load event of a page that is shown, outside any frame.
    function startSnapshot() {
        if (window.top !== window.self) return;
        var loaded = document.readyState === 'complete';
        var shown = document.prerendering !== true;
        var started = false;
        var go = function () {
            if (started || !loaded || !shown) return;
            started = true;
            setTimeout(run, 0);
        };
        window.addEventListener('load', function () {
            loaded = true;
            go();
        });
        if (!shown) {
            document.addEventListener('prerenderingchange', function () {
                shown = true;
                go();
            });
        }
        go();
    }

    // Script errors: a closed list of places and classes, never the message, stack or URL.
    var ERROR_CLASSES = ['Error', 'TypeError', 'ReferenceError', 'RangeError', 'SyntaxError', 'URIError', 'EvalError', 'AggregateError', 'AbortError', 'NetworkError', 'QuotaExceededError', 'NotAllowedError', 'SecurityError', 'InvalidStateError', 'NotFoundError', 'TimeoutError', 'ScriptError', 'other'];
    var SCRIPTS = ['admin-metrics.js', 'admin-people.js', 'alerts.js', 'api-plans.js', 'arbit-filters.js', 'arbit-presets.js', 'arbit-rows.js', 'autocomplete.js', 'backpack.js', 'ban-to-cart.js', 'card-art-fallback.js', 'card-row.js', 'cart-prompt.js', 'chart-range.js', 'chartopts.js', 'command-palette.js', 'confirm-dialog.js', 'cookies.js', 'copy2clip.js', 'edition-combobox.js', 'editions-picker.js', 'favorites-shared.js', 'favorites.js', 'fetchnames.js', 'fflate.min.js', 'filtering.js', 'followmouse.js', 'guide-data.js', 'guide.js', 'icons.js', 'list-storage.js', 'load-lists.js', 'metrics.js', 'mobile-chart.js', 'navbar.js', 'news-filters.js', 'nightmode.js', 'offline-age.js', 'offline-banner.js', 'offline-db.js', 'offline-format.js', 'offline-images-ui.js', 'offline-images.js', 'offline-live.js', 'offline-mode.js', 'offline-page-desktop.js', 'offline-page-mobile.js', 'offline-page.js', 'offline-prefer.js', 'offline-query.js', 'offline-render-mobile.js', 'offline-render-shared.js', 'offline-render.js', 'offline-search.js', 'offline-settings-mobile.js', 'offline-sync.js', 'offline-util.js', 'offline-watch.js', 'palette-chips.js', 'palette-loader.js', 'palette-providers.js', 'printings-panel.js', 'recent-searches.js', 'scope.js', 'screener.js', 'sealed.js', 'search-chart.js', 'search-modal.js', 'search-quick-icons.js', 'search-result-nav.js', 'search-sidebar.js', 'search-track.js', 'search-type-focus.js', 'section-fold.js', 'settings-changes.js', 'settings-loader.js', 'settings-shell.js', 'settings.js', 'store-factors.js', 'store-picker.js', 'tooltips.js', 'upload-exports.js', 'upload-form.js', 'upload-handoff.js', 'upload-optimizer.js', 'upload-options.js', 'upload-presets.js', 'upload-printings.js', 'upload-processing.js', 'upload-share.js', 'upload-sort.js', 'upload-store-prompt.js', 'upload-tabs.js', 'user-state.js', 'utils.js'];
    var MAX_ERRORS = 5;
    var MAX_LINE = 1000000;
    var SCRIPT_PATH = /^\/js\/(?:[a-z0-9-]+\/)*([a-z0-9.-]+\.js)$/;
    var FRAME_AT = /(https?:\/\/[^\s()]+?):(\d+):(\d+)\)?\s*$/;
    var BUILD_SHAPE = /^[0-9a-f]{40}(?:-[0-9]+)?$/;
    var reported = 0;

    function classOf(err) {
        var name = err && typeof err === 'object' ? err.name : undefined;
        return typeof name === 'string' && ERROR_CLASSES.indexOf(name) >= 0 ? name : 'other';
    }

    // scriptOf is a listed basename under /js/ on this origin, inline for this origin's pages, else other.
    function scriptOf(url) {
        if (typeof url !== 'string' || !url) return 'other';
        if (typeof location === 'undefined' || typeof URL === 'undefined') return 'other';
        var u;
        try {
            u = new URL(url, location.href);
        } catch (e) {
            return 'other';
        }
        if (u.origin !== location.origin) return 'other';
        var m = SCRIPT_PATH.exec(u.pathname);
        if (!m) return 'inline';
        return SCRIPTS.indexOf(m[1]) >= 0 ? m[1] : 'other';
    }

    function lineOf(script, n) {
        if (script === 'inline' || script === 'other') return 0;
        return typeof n === 'number' && n % 1 === 0 && n >= 1 && n <= MAX_LINE ? n : 0;
    }

    function textOf(v) {
        return typeof v === 'string' ? v : '';
    }

    function trimLeft(s) {
        return s.replace(/^\s+/, '');
    }

    // headerLines counts the lines of V8's "name: message" header, so no frame is read from the message.
    function headerLines(reason, stack, lines, v8) {
        var name = textOf(reason.name) || 'Error';
        var msg = textOf(reason.message);
        var head = msg ? name + ': ' + msg : name;
        if (stack === head || stack.indexOf(head + '\n') === 0) return head.split('\n').length;
        if (v8 && trimLeft(lines[0]).indexOf('at ') !== 0) return msg.split('\n').length;
        return 0;
    }

    // topFrame returns the url and line of the first frame in the engine's own format, never from the message.
    function topFrame(reason) {
        var stack = reason.stack;
        if (typeof stack !== 'string') return null;
        var lines = stack.split('\n');
        var v8 = false;
        for (var i = 0; i < lines.length; i++) {
            if (trimLeft(lines[i]).indexOf('at ') === 0) v8 = true;
        }
        for (i = headerLines(reason, stack, lines, v8); i < lines.length; i++) {
            var line = trimLeft(lines[i]);
            if (v8 ? line.indexOf('at ') !== 0 : line.indexOf('@') < 0) continue;
            var m = FRAME_AT.exec(line);
            return m ? { url: m[1], line: parseInt(m[2], 10) } : null;
        }
        return null;
    }

    function onError(e) {
        try {
            if (reported >= MAX_ERRORS || !e) return;
            if (e.target && e.target !== window) return;
            var script = scriptOf(e.filename);
            var cls = 'ScriptError';
            var line = 0;
            if (e.error || script !== 'other') {
                cls = classOf(e.error);
                line = lineOf(script, e.lineno);
            }
            reported++;
            bump('ui.js.error', cls, script, { l: line, b: cfg.build });
        } catch (err) {}
    }

    function onRejection(e) {
        try {
            if (reported >= MAX_ERRORS || !e) return;
            var reason = e.reason;
            var frame = reason && typeof reason === 'object' ? topFrame(reason) : null;
            var script = frame ? scriptOf(frame.url) : 'other';
            var line = frame ? lineOf(script, frame.line) : 0;
            reported++;
            bump('ui.js.rejection', classOf(reason), script, { l: line, b: cfg.build });
        } catch (err) {}
    }

    // startErrors listens only on a build with a commit hash, so every row can be placed.
    function startErrors() {
        if (typeof cfg.build !== 'string' || !BUILD_SHAPE.test(cfg.build)) return;
        window.addEventListener('error', onError);
        window.addEventListener('unhandledrejection', onRejection);
    }

    // Page timings: one load in ten, bucketed and scoped by page; a value below an edge takes its label.
    var PERF_SAMPLE = 0.1;
    var TTFB_BUCKETS = [[200, '<200ms'], [500, '<500ms'], [800, '<800ms'], [1800, '<1.8s'], [Infinity, '1.8s+']];
    var LCP_BUCKETS = [[1000, '<1s'], [2500, '<2.5s'], [4000, '<4s'], [8000, '<8s'], [Infinity, '8s+']];
    var DOM_READY_BUCKETS = [[500, '<500ms'], [1000, '<1s'], [2000, '<2s'], [4000, '<4s'], [8000, '<8s'], [Infinity, '8s+']];
    var perfOn = false;
    var lcpMs = 0;
    var lcpDone = false;
    var lcpObserver = null;

    function bucketOf(buckets, ms) {
        for (var i = 0; i < buckets.length - 1; i++) {
            if (ms < buckets[i][0]) return buckets[i][1];
        }
        return buckets[buckets.length - 1][1];
    }

    function measured(ms) {
        return typeof ms === 'number' && isFinite(ms) && ms > 0;
    }

    function navEntry() {
        try {
            var list = performance.getEntriesByType('navigation');
            return list && list[0] ? list[0] : null;
        } catch (e) {
            return null;
        }
    }

    // timing is a navigation field in ms from the start, from the old timing object when there is no entry.
    function timing(field) {
        var n = navEntry();
        if (n) return n[field];
        try {
            var t = performance.timing;
            return t ? t[field] - t.navigationStart : NaN;
        } catch (e) {
            return NaN;
        }
    }

    // prerendered says the times were taken before the reader saw the page.
    function prerendered() {
        if (document.prerendering === true) return true;
        var n = navEntry();
        return !!n && n.activationStart > 0;
    }

    function readTimings() {
        try {
            if (document.visibilityState === 'hidden') return; // hidden before load: background timings are throttled
            if (prerendered()) return;
            var ttfb = timing('responseStart');
            if (measured(ttfb)) bump('ui.perf.ttfb', bucketOf(TTFB_BUCKETS, ttfb), cfg.page);
            var dom = timing('domContentLoadedEventEnd');
            if (measured(dom)) bump('ui.perf.dom_ready', bucketOf(DOM_READY_BUCKETS, dom), cfg.page);
        } catch (e) {}
    }

    // finishPerf adds the paint time once, before the first hidden flush takes the buffer.
    function finishPerf() {
        try {
            if (!perfOn || lcpDone) return;
            lcpDone = true;
            try {
                if (lcpObserver) lcpObserver.disconnect();
            } catch (e) {}
            if (measured(lcpMs) && !prerendered()) bump('ui.perf.lcp', bucketOf(LCP_BUCKETS, lcpMs), cfg.page);
        } catch (e) {}
    }

    function observePaint() {
        try {
            if (typeof PerformanceObserver === 'undefined' || !PerformanceObserver) return;
            var types = PerformanceObserver.supportedEntryTypes;
            if (!types || types.indexOf('largest-contentful-paint') < 0) return;
            lcpObserver = new PerformanceObserver(function (list) {
                try {
                    var got = list.getEntries();
                    if (got.length) lcpMs = got[got.length - 1].startTime;
                } catch (e) {}
            });
            lcpObserver.observe({ type: 'largest-contentful-paint', buffered: true });
        } catch (e) {}
    }

    // startPerf decides the sample once; a page with no label, in the background or prerendered is left out.
    function startPerf() {
        if (!cfg.page || !(Math.random() < PERF_SAMPLE)) return;
        if (document.visibilityState === 'hidden' || prerendered()) return;
        perfOn = true;
        observePaint();
        if (document.readyState === 'complete') readTimings();
        else window.addEventListener('load', readTimings);
    }

    BAN.track = track;
    BAN.metrics = { bump: bump };
    BAN.snapshot = { MARK: SNAP, scopes: scopes, cookies: cookies, value: value, entries: entries, due: due, run: run };

    try {
        document.addEventListener('click', onAction, true);
        document.addEventListener('auxclick', onAction, true);
        document.addEventListener('submit', onAction, true);
        document.addEventListener('visibilitychange', onVisibility);
        window.addEventListener('pagehide', flushHidden);
        window.addEventListener('online', sendQueue);
        sendQueue();
        if (cfg.page) countLoad();
    } catch (e) {}
    try {
        startErrors();
    } catch (e) {}
    try {
        startPerf();
    } catch (e) {}
    try {
        startSnapshot();
    } catch (e) {}
})();
