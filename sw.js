// MTGBAN offline mode service worker. The server injects self.__BUILD as
// the first line, so deploys change the bytes and trigger the update check.
'use strict';

// URLs must match the page's ?hash= exactly, even when the build id is empty.
var BUILD = self.__BUILD || '';
var SHELL_CACHE = 'mtgban-shell-' + (BUILD || 'dev');
var IMAGE_CACHE = 'mtgban-images-v1';

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
// keyrune CDN is cross-origin and uncacheable; mobile renderer degrades to set-code span offline

self.addEventListener('install', function (e) {
    // No skipWaiting: new shells activate after the old session's pages go away.
    e.waitUntil(caches.open(SHELL_CACHE).then(function (c) {
        return c.addAll(SHELL_URLS);
    }));
});

self.addEventListener('activate', function (e) {
    e.waitUntil(caches.keys().then(function (names) {
        return Promise.all(names.filter(function (n) {
            return n.indexOf('mtgban-shell-') === 0 && n !== SHELL_CACHE;
        }).map(function (n) { return caches.delete(n); }));
    }).then(function () { return self.clients.claim(); }));
});

self.addEventListener('fetch', function (e) {
    var req = e.request;
    if (req.method !== 'GET') return;
    var url = new URL(req.url);
    if (url.origin !== self.location.origin) return;

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
