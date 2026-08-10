// MTGBAN offline mode service worker. The server injects self.__BUILD as
// the first line, so deploys change the bytes and trigger the update check.
'use strict';

// URLs must match the page's ?hash= exactly, even when the build id is empty.
var BUILD = self.__BUILD || '';
var SHELL_CACHE = 'mtgban-shell-' + (BUILD || 'dev');
var IMAGE_CACHE = 'mtgban-images-v2';

// Same-origin chrome needed to render the /offline shell with no network.
var SHELL_URLS = [
    '/offline',
    '/css/main.css?hash=' + BUILD,
    '/css/navbar.css?hash=' + BUILD,
    '/css/command-palette.css?hash=' + BUILD,
    '/css/settings-modal.css?hash=' + BUILD,
    '/css/editions-picker.css?hash=' + BUILD,
    '/js/utils.js?hash=' + BUILD,
    '/js/fetchnames.js?hash=' + BUILD,
    '/js/autocomplete.js?hash=' + BUILD,
    '/js/navbar.js?hash=' + BUILD,
    '/js/palette-chips.js?hash=' + BUILD,
    '/js/palette-providers.js?hash=' + BUILD,
    '/js/guide-data.js?hash=' + BUILD,
    '/js/command-palette.js?hash=' + BUILD,
    '/js/cookies.js?hash=' + BUILD,
    '/js/editions-picker.js?hash=' + BUILD,
    '/js/settings.js?hash=' + BUILD,
    '/css/search.css?hash=' + BUILD,
    '/css/offline.css?hash=' + BUILD,
    '/js/offline/offline-db.js?hash=' + BUILD,
    '/js/offline/offline-mode.js?hash=' + BUILD,
    '/js/offline/offline-format.js?hash=' + BUILD,
    '/js/offline/offline-util.js?hash=' + BUILD,
    '/js/offline/offline-query.js?hash=' + BUILD,
    '/js/offline/offline-render.js?hash=' + BUILD,
    '/css/mobile.css?hash=' + BUILD,
    '/css/search-mobile.css?hash=' + BUILD,
    '/js/offline/offline-render-mobile.js?hash=' + BUILD,
    '/js/offline/offline-settings-mobile.js?hash=' + BUILD,
    '/js/offline/offline-search.js?hash=' + BUILD,
    '/js/offline/offline-age.js?hash=' + BUILD,
    '/js/offline/offline-banner.js?hash=' + BUILD,
    '/js/offline/offline-watch.js?hash=' + BUILD,
    '/img/logo/ban-stroop.png',
    '/img/favicon/favicon-32x32.png',
    '/img/favicon/site.webmanifest'
];
// Keyrune ships from a CDN so its ~460 KB of font and stylesheet stay out of
// the repo, and stays on @latest so new set symbols arrive without a deploy.
var KEYRUNE_PREFIX = 'https://cdn.jsdelivr.net/npm/keyrune@';
var KEYRUNE_CSS = KEYRUNE_PREFIX + 'latest/css/keyrune.css';

function isKeyrune(url) {
    return url.href.indexOf(KEYRUNE_PREFIX) === 0;
}

// Caches the stylesheet plus the font files it actually names. The font URLs
// carry a ?v= matching the published version, so they are read back out of the
// stylesheet rather than hardcoded: a fixed version would stop matching the
// moment @latest moves, and the glyphs would break offline only.
function cacheKeyrune(c) {
    return fetch(new Request(KEYRUNE_CSS, { cache: 'reload', mode: 'cors' })).then(function (res) {
        if (!res.ok) return;
        return res.clone().text().then(function (css) {
            return c.put(KEYRUNE_CSS, res).then(function () {
                var urls = [];
                var re = /url\(['"]?([^'")]+\.woff2?(?:\?[^'")]*)?)['"]?\)/g;
                var m;
                while ((m = re.exec(css)) !== null) {
                    urls.push(new URL(m[1], KEYRUNE_CSS).href);
                }
                return Promise.all(urls.map(function (u) {
                    return fetch(new Request(u, { cache: 'reload', mode: 'cors' })).then(function (r) {
                        if (r.ok) return c.put(u, r);
                    }).catch(function () {});
                }));
            });
        });
    }).catch(function () {});
}

self.addEventListener('install', function (e) {
    // cache: 'reload' bypasses HTTP caches so precache never picks up a stale edge/browser hit.
    e.waitUntil(caches.open(SHELL_CACHE).then(function (c) {
        return Promise.all(SHELL_URLS.map(function (url) {
            return fetch(new Request(url, { cache: 'reload' })).then(function (res) {
                if (!res.ok) throw new Error('precache fetch failed: ' + url);
                return c.put(url, res);
            });
        })).then(function () {
            // Best effort, unlike the shell above: a CDN outage should cost set
            // symbols, not fail the install and take offline mode down with it.
            // Fetched cors so the entry is a real response rather than an opaque
            // one, which would be unreadable and padded against the quota.
            return cacheKeyrune(c);
        });
    }).then(function () { return self.skipWaiting(); }));
});

self.addEventListener('activate', function (e) {
    e.waitUntil(caches.keys().then(function (names) {
        return Promise.all(names.filter(function (n) {
            return (n.indexOf('mtgban-shell-') === 0 && n !== SHELL_CACHE) || n === 'mtgban-images-v1';
        }).map(function (n) { return caches.delete(n); }));
    }).then(function () { return self.clients.claim(); }));
});

self.addEventListener('fetch', function (e) {
    var req = e.request;
    if (req.method !== 'GET') return;
    var url = new URL(req.url);
    if (url.origin !== self.location.origin) {
        // Network first, so @latest keeps delivering new set symbols; the cache
        // is only the offline fallback. ignoreVary because the CDN varies on
        // Accept-Encoding, which would otherwise stop the stylesheet's own font
        // request from matching what was cached.
        if (isKeyrune(url)) {
            e.respondWith(fetch(req).catch(function () {
                return caches.match(req, { cacheName: SHELL_CACHE, ignoreVary: true }).then(function (hit) {
                    return hit || Response.error();
                });
            }));
        }
        return;
    }

    // Health probes must always hit the network.
    if (url.pathname === '/healthz') return;

    // Card images: cache-first with network fallback (the image sync fills the cache).
    if (url.pathname.indexOf('/api/offline/images/') === 0) {
        e.respondWith(caches.open(IMAGE_CACHE).then(function (c) {
            return c.match(req).then(function (hit) { return hit || fetch(req); });
        }));
        return;
    }

    // Never intercept any other API traffic.
    if (url.pathname.indexOf('/api/') === 0) return;

    // Navigations fall back to the cached offline shell on network failure.
    if (req.mode === 'navigate') {
        e.respondWith(fetch(req).catch(function () {
            return caches.match('/offline', { cacheName: SHELL_CACHE }).then(function (hit) {
                return hit || Response.error();
            });
        }));
        return;
    }

    // Shell assets: cache-first; hash-keyed URLs make cache and server agree.
    e.respondWith(caches.match(req, { cacheName: SHELL_CACHE }).then(function (hit) {
        return hit || fetch(req);
    }));
});
