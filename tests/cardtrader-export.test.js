import { test, expect, describe } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/cardtrader-export.js', import.meta.url), 'utf8');

// loadScript runs the page script against a stand-in page and returns what
// the test can reach: the helpers it exposes and the downloads it started.
function loadScript(exportData) {
    const downloads = [];
    const clicks = {};
    const anchors = [];
    const document = {
        getElementById: (id) => {
            if (id !== 'ct-download-raw' && id !== 'ct-download-ban') return null;
            return {addEventListener: (ev, fn) => { clicks[id] = fn; }};
        },
        createElement: () => {
            const a = {click() { downloads.push({href: a.href, download: a.download}); }, remove() {}};
            anchors.push(a);
            return a;
        },
        body: {appendChild() {}},
    };
    const window = {BAN_CT_EXPORT: exportData};
    const URL = {createObjectURL: (blob) => 'blob:' + blob.parts.join(''), revokeObjectURL: () => {}};
    class Blob { constructor(parts) { this.parts = parts; } }
    new Function('window', 'document', 'URL', 'Blob', 'setTimeout', source)(window, document, URL, Blob, (fn) => fn());
    return {CTExport: window.CTExport, downloads, clicks};
}

const sample = {
    raw: [['product_id', 'name', 'description'], ['1', 'Black Lotus', 'pack fresh, "really"\nmint']],
    ban: [['id', 'name', 'quantity'], ['abc', 'Black Lotus', '2']],
};

describe('csv', () => {
    test('quotes a field holding a comma, a quote or a newline and leaves the rest bare', () => {
        const {CTExport} = loadScript(sample);
        expect(CTExport.csv([['a', 'b,c', 'say "hi"', 'two\nlines']]))
            .toBe('a,"b,c","say ""hi""","two\nlines"\r\n');
    });

    test('raw and ban write the header and every row', () => {
        const {CTExport} = loadScript(sample);
        expect(CTExport.raw(sample)).toBe('product_id,name,description\r\n1,Black Lotus,"pack fresh, ""really""\nmint"\r\n');
        expect(CTExport.ban(sample)).toBe('id,name,quantity\r\nabc,Black Lotus,2\r\n');
    });
});

describe('buttons', () => {
    test('each button downloads its file under its name', () => {
        const {clicks, downloads} = loadScript(sample);
        clicks['ct-download-raw']();
        clicks['ct-download-ban']();
        expect(downloads.map((d) => d.download)).toEqual(['cardtrader-raw.csv', 'cardtrader-ban.csv']);
        expect(downloads[1].href).toBe('blob:id,name,quantity\r\nabc,Black Lotus,2\r\n');
    });

    test('does nothing without an export on the page', () => {
        const {clicks, CTExport} = loadScript(undefined);
        expect(Object.keys(clicks)).toEqual([]);
        expect(typeof CTExport.csv).toBe('function');
    });
});
