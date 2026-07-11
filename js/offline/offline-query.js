// Offline search query mini-parser and executor (contract sec 12).
(function (root) {
    'use strict';

    var FINISH = {
        foil: 'foil', f: 'foil',
        nonfoil: 'nonfoil', nf: 'nonfoil',
        etched: 'etched', e: 'etched'
    };
    var RARITY = {
        common: 'common', c: 'common',
        uncommon: 'uncommon', u: 'uncommon',
        rare: 'rare', r: 'rare',
        mythic: 'mythic', m: 'mythic'
    };

    // tokenize splits on whitespace honoring double-quoted phrases.
    function tokenize(str) {
        var tokens = [];
        var re = /"([^"]*)"|(\S+)/g;
        var m;
        while ((m = re.exec(str)) !== null) {
            if (m[1] !== undefined) {
                tokens.push({text: m[1], quoted: true});
            } else {
                tokens.push({text: m[2], quoted: false});
            }
        }
        return tokens;
    }

    function parse(str) {
        var out = {names: [], set: '', number: '', finish: '', rarity: '', unsupported: []};
        var tokens = tokenize(String(str || ''));
        for (var i = 0; i < tokens.length; i++) {
            var tok = tokens[i];
            if (tok.quoted) {
                if (tok.text.trim() !== '') {
                    out.names.push(tok.text);
                }
                continue;
            }
            var colon = tok.text.indexOf(':');
            var operatorish = colon > 0 || /[<>=]/.test(tok.text);
            if (!operatorish) {
                if (/^\d+$/.test(tok.text)) {
                    out.number = tok.text;
                } else {
                    out.names.push(tok.text);
                }
                continue;
            }
            if (colon <= 0) {
                out.unsupported.push(tok.text);
                continue;
            }
            var key = tok.text.slice(0, colon).toLowerCase();
            var val = tok.text.slice(colon + 1).replace(/^"|"$/g, '');
            switch (key) {
            case 's':
                out.set = val.toUpperCase();
                break;
            case 'cn':
                out.number = val;
                break;
            case 'f':
                if (FINISH[val.toLowerCase()]) {
                    out.finish = FINISH[val.toLowerCase()];
                } else {
                    out.unsupported.push(tok.text);
                }
                break;
            case 'r':
                if (RARITY[val.toLowerCase()]) {
                    out.rarity = RARITY[val.toLowerCase()];
                } else {
                    out.unsupported.push(tok.text);
                }
                break;
            default:
                out.unsupported.push(tok.text);
            }
        }
        return out;
    }

    root.OfflineQuery = {parse: parse};
})(typeof self !== 'undefined' ? self : globalThis);
