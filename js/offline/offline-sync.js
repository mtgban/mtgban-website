// Offline price sync worker: manifest diff, catalog rebuild, encrypted set blobs, image bundles.
importScripts('/js/offline/offline-util.js', '/js/offline/offline-db.js', '/js/offline/offline-format.js');
importScripts('/js/vendor/fflate.min.js', '/js/offline/offline-images.js');

var cancelled = false;

self.onmessage = function(ev) {
    var msg = ev.data || {};
    if (msg.type === 'cancel') {
        cancelled = true;
    } else if (msg.type === 'sync') {
        cancelled = false;
        runSync(msg);
    }
};

function post(m) { self.postMessage(m); }

function forbidden(stage) {
    var err = new Error('forbidden');
    err.stage = stage;
    return err;
}

// Same-origin credentials carry the MTGBAN cookie; 403 means lapsed access.
function fetchChecked(url, stage) {
    return fetch(url, { credentials: 'same-origin' }).then(function(resp) {
        if (resp.status === 403) throw forbidden(stage);
        if (!resp.ok) {
            var err = new Error('http ' + resp.status);
            err.stage = stage;
            throw err;
        }
        return resp;
    });
}

// Images stage: runs after prices within the same sync message.
async function runImagesStage(manifest, imgEditions, isCancelled) {
    var sel = Array.isArray(imgEditions) ? imgEditions : [];
    // Deselected editions release their cached images before new work starts.
    await OfflineImages.evictImages({
        sel: sel,
        getImgStates: function () { return OfflineDB.getAllRows('imgstate'); },
        deleteImgState: function (code) { return OfflineDB.deleteRow('imgstate', code); },
    });
    if (sel.length === 0) {
        await OfflineDB.setMeta('imgCount', 0);
        return 0;
    }
    var rows = await OfflineDB.getAllRows('imgstate');
    var states = {};
    rows.forEach(function (r) { states[r.code] = r; });
    var res = await OfflineImages.syncImages({
        images: (manifest && manifest.images) || {},
        sel: sel,
        states: states,
        cancelled: isCancelled,
        putImgState: function (row) { return OfflineDB.putRow('imgstate', row); },
        post: function (msg) { self.postMessage(msg); },
    });
    // Refresh the status snapshot: imgCount is per-image, summed from manifest.
    var after = await OfflineDB.getAllRows('imgstate');
    var imgMap = (manifest && manifest.images) || {};
    var imgCount = after.filter(function (r) { return r.done; }).reduce(function (sum, r) {
        return sum + (imgMap[r.code] ? imgMap[r.code].n : 1);
    }, 0);
    await OfflineDB.setMeta('imgCount', imgCount);
    return res.bytes;
}

async function runSync(msg) {
    var stage = 'manifest';
    try {
        post({ type: 'progress', stage: 'manifest', done: 0, total: 1 });
        var manifest = await fetchChecked('/api/offline/manifest.json', 'manifest')
            .then(function(r) { return r.json(); });
        post({ type: 'progress', stage: 'manifest', done: 1, total: 1 });

        // Opt-in provisions the key; regenerate defensively if it is missing.
        var fullResync = false;
        var key = await self.OfflineDB.getMeta('aesKey');
        if (!key) {
            key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
            await self.OfflineDB.setMeta('aesKey', key);
            fullResync = true; // Regenerated key cannot decrypt existing blobs.
        }

        stage = 'catalog';
        var catalogVersion = await self.OfflineDB.getMeta('catalogVersion');
        if (manifest.catalog && manifest.catalog !== catalogVersion) {
            post({ type: 'progress', stage: 'catalog', done: 0, total: 1 });
            var catalog = await fetchChecked('/api/offline/catalog.json', 'catalog')
                .then(function(r) { return r.json(); });
            await rebuildCatalog(catalog);
            await self.OfflineDB.setMeta('catalogVersion', catalog.version);
            post({ type: 'progress', stage: 'catalog', done: 1, total: 1 });
        }

        stage = 'prices';
        var stores = msg.stores || [];
        var editions = msg.editions || [];
        // A different store subset changes payload content: resync everything.
        var storesKey = stores.slice().sort().join(',');
        fullResync = fullResync || storesKey !== await self.OfflineDB.getMeta('storesKey');

        var have = {};
        (await self.OfflineDB.listSetVersions()).forEach(function(row) { have[row.code] = row.version; });

        var changed = Object.keys(manifest.sets || {}).filter(function(code) {
            if (editions.length > 0 && editions.indexOf(code) < 0) return false;
            return fullResync || have[code] !== manifest.sets[code];
        }).sort();

        var state = { done: 0, bytes: 0, idx: 0 };
        var errored = false;
        var pump = async function() {
            for (;;) {
                if (cancelled || errored) return;
                var i = state.idx++;
                if (i >= changed.length) return;
                var code = changed[i];
                try {
                    state.bytes += await syncSet(code, manifest.sets[code], stores, key);
                } catch (e) {
                    errored = true;
                    throw e;
                }
                if (errored) return;
                state.done++;
                post({ type: 'progress', stage: 'prices', done: state.done, total: changed.length, code: code });
            }
        };
        // Two lanes: modest parallelism without hammering the server.
        await Promise.all([pump(), pump()]);

        if (!cancelled) {
            // Edition-filtered runs must not record storesKey as fully resynced.
            if (editions.length === 0) await self.OfflineDB.setMeta('storesKey', storesKey);
            await self.OfflineDB.setMeta('manifest', manifest);
            await self.OfflineDB.setMeta('authLapsed', false);
        }
        try {
            state.bytes += await runImagesStage(manifest, msg.imgEditions, function() { return cancelled; });
        } catch (err) {
            if (err && err.message === 'forbidden') {
                try { await self.OfflineDB.setMeta('authLapsed', true); } catch (e) {}
            }
            post({ type: 'error', stage: 'images', message: err.message });
            return;
        }
        post({ type: 'done', changedSets: state.done, bytes: state.bytes });
    } catch (err) {
        if (err && err.message === 'forbidden') await self.OfflineDB.setMeta('authLapsed', true);
        post({ type: 'error', stage: (err && err.stage) || stage, message: (err && err.message) || String(err) });
    }
}

// Download, re-gzip, encrypt, and store one set payload; returns stored bytes.
async function syncSet(code, version, stores, key) {
    var url = '/api/offline/prices/' + encodeURIComponent(code) + '.bin';
    if (stores.length > 0) url += '?stores=' + encodeURIComponent(stores.join(','));
    var resp = await fetchChecked(url, 'prices');
    // fetch already undid the transport Content-Encoding: this is raw OFP1.
    var raw = await resp.arrayBuffer();
    var gz = await self.OfflineUtil.gzipCompress(raw);
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var blob = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, gz);
    await self.OfflineDB.putSet({ code: code, version: version, iv: iv.buffer, blob: blob });
    return blob.byteLength;
}

// Swap the cards and names stores to a new catalog version.
async function rebuildCatalog(catalog) {
    var cards = [];
    var names = {};
    Object.keys(catalog.cards || {}).forEach(function(uuid) {
        var c = catalog.cards[uuid];
        cards.push({ uuid: uuid, n: c.n, num: c.num, r: c.r, set: c.set, f: c.f, e: c.e, s: c.s, p: c.p, i: c.i });
        var k = self.OfflineUtil.normName(c.n || '');
        if (!k) return;
        if (!names[k]) names[k] = [];
        names[k].push(uuid);
    });
    var nameRows = Object.keys(names).map(function(k) { return { key: k, uuids: names[k] }; });

    await self.OfflineDB.clearCatalog();
    var CHUNK = 2000;
    for (var i = 0; i < cards.length; i += CHUNK) {
        await self.OfflineDB.putCards({ cards: cards.slice(i, i + CHUNK), names: [] });
    }
    for (var j = 0; j < nameRows.length; j += CHUNK) {
        await self.OfflineDB.putCards({ cards: [], names: nameRows.slice(j, j + CHUNK) });
    }

    // Display dictionaries for the offline shell (OfflineUtil.loadCatalogDicts reads these).
    await self.OfflineDB.setMeta('catalogSets', catalog.sets || {});
    await self.OfflineDB.setMeta('catalogStores', catalog.stores || {});
}
