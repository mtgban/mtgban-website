// OFP1 binary price payload decoder, mirror of internal/offline/format.go.
// Plain script: attaches to self so pages and workers can both load it.
(function() {
    'use strict';

    var utf8 = new TextDecoder('utf-8');

    var F_REGULAR = 1, F_FOIL = 2, F_ETCHED = 4, F_SEALED = 8;
    var F_COND = 16, F_CONDMAP = 32, F_QTYMAP = 64, F_BASEQTY = 128;

    function Reader(buf) {
        this.bytes = new Uint8Array(buf);
        this.pos = 0;
    }

    Reader.prototype.u8 = function() {
        if (this.pos >= this.bytes.length) throw new Error('truncated payload');
        return this.bytes[this.pos++];
    };

    // Multiply instead of shift so values past 32 bits stay exact.
    Reader.prototype.uv = function() {
        var value = 0, scale = 1;
        for (var i = 0; i < 10; i++) {
            var b = this.u8();
            value += (b & 0x7f) * scale;
            if ((b & 0x80) === 0) {
                if (!Number.isSafeInteger(value)) throw new Error('uvarint overflow');
                return value;
            }
            scale *= 128;
        }
        throw new Error('uvarint too long');
    };

    Reader.prototype.str = function() {
        var n = this.uv();
        if (this.pos + n > this.bytes.length) throw new Error('string past end of buffer');
        var s = utf8.decode(this.bytes.subarray(this.pos, this.pos + n));
        this.pos += n;
        return s;
    };

    function readDict(r) {
        var n = r.uv();
        var out = new Array(n);
        for (var i = 0; i < n; i++) out[i] = r.str();
        return out;
    }

    function tagAt(tags, idx) {
        if (idx >= tags.length) throw new Error('tag index out of range');
        return tags[idx];
    }

    function readF64Map(r, tags) {
        var n = r.uv();
        var m = {};
        for (var i = 0; i < n; i++) {
            var tag = tagAt(tags, r.uv());
            m[tag] = r.uv() / 100;
        }
        return m;
    }

    function readIntMap(r, tags) {
        var n = r.uv();
        var m = {};
        for (var i = 0; i < n; i++) {
            var tag = tagAt(tags, r.uv());
            m[tag] = r.uv();
        }
        return m;
    }

    function readSection(r, stores, tags) {
        var nUUID = r.uv();
        var section = {};
        for (var i = 0; i < nUUID; i++) {
            var uuid = r.str();
            var nEntry = r.uv();
            var byStore = {};
            for (var j = 0; j < nEntry; j++) {
                var sIdx = r.uv();
                if (sIdx >= stores.length) throw new Error('store index out of range');
                var flags = r.u8();
                var e = {};
                // Field order mirrors the Go encoder: prices, baseqty, cond, maps.
                if (flags & F_REGULAR) e.regular = r.uv() / 100;
                if (flags & F_FOIL) e.foil = r.uv() / 100;
                if (flags & F_ETCHED) e.etched = r.uv() / 100;
                if (flags & F_SEALED) e.sealed = r.uv() / 100;
                if (flags & F_BASEQTY) {
                    e.qty = r.uv();
                    e.qtyFoil = r.uv();
                    e.qtyEtched = r.uv();
                    e.qtySealed = r.uv();
                }
                if (flags & F_COND) e.cond = tagAt(tags, r.uv());
                if (flags & F_CONDMAP) e.conditions = readF64Map(r, tags);
                if (flags & F_QTYMAP) e.quantities = readIntMap(r, tags);
                byStore[stores[sIdx]] = e;
            }
            section[uuid] = byStore;
        }
        return section;
    }

    // decode parses one full-set OFP1 payload from an ArrayBuffer.
    function decode(buf) {
        var head = new Uint8Array(buf);
        if (head.length < 6 || head[0] !== 0x4F || head[1] !== 0x46 || head[2] !== 0x50 || head[3] !== 0x31) {
            throw new Error('bad magic');
        }
        if (head[4] !== 1) throw new Error('unsupported format version ' + head[4]);
        if (head[5] !== 1) throw new Error('unsupported message type ' + head[5]);

        var r = new Reader(buf);
        r.pos = 6;
        var setCode = r.str();
        var snapshot = new Date(r.uv() * 1000);
        var stores = readDict(r);
        var tags = readDict(r);
        var retail = readSection(r, stores, tags);
        var buylist = readSection(r, stores, tags);
        return { setCode: setCode, snapshot: snapshot, retail: retail, buylist: buylist };
    }

    self.OfflineFormat = { decode: decode };
})();
