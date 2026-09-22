import { test, expect, describe } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/upload-handoff.js', import.meta.url), 'utf8');

const SENDER = 'https://www.cardmarket.com';
const READY = 'mtgban-handoff-ready';
const ROWS = 'mtgban-handoff-rows';

// loadHandoff runs the script against a stand-in for the page it ships with,
// and hands back what the test needs to drive it: the opener it talks to, the
// listener it attached, and the elements it writes to.
function loadHandoff({origins = [SENDER], opener = {closed: false}, missingRoot = false, canUpload = true} = {}) {
    const sent = [];
    if (opener) {
        opener.postMessage = (message, target) => sent.push({message, target});
    }

    const submitted = [];
    const elements = {
        handoff: {
            getAttribute: (name) =>
                name === 'data-can-upload' ? String(canUpload) : JSON.stringify(origins),
        },
        'handoff-status': {textContent: ''},
        'handoff-hint': {hidden: true},
        'handoff-form': {submit: () => submitted.push(true)},
        'handoff-rows': {value: ''},
        'handoff-source': {value: ''},
    };

    // A page that cannot upload does not render the status line or the
    // form, so neither is here to be written to. The script has to notice
    // before it reaches for them, which is the same thing as noticing
    // before it announces itself.
    if (!canUpload) {
        delete elements['handoff-status'];
        delete elements['handoff-hint'];
        delete elements['handoff-form'];
        delete elements['handoff-rows'];
        delete elements['handoff-source'];
    }

    let onMessage;
    const window = {
        opener,
        addEventListener: (type, handler) => {
            if (type === 'message') onMessage = handler;
        },
    };
    const document = {
        getElementById: (id) => (missingRoot && id === 'handoff' ? null : elements[id] || null),
    };

    new Function('window', 'document', source)(window, document);
    return {sent, submitted, elements, deliver: (event) => onMessage && onMessage(event)};
}

// A message as the opener really sends it, with each part overridable so a
// test can spoil exactly one of them.
function rowsMessage(opener, over = {}) {
    return Object.assign(
        {origin: SENDER, source: opener, data: {type: ROWS, csv: 'a,b\n1,2\n'}},
        over
    );
}

describe('asking for the rows', () => {
    test('it announces itself to every allowed origin, and only those', () => {
        const opener = {closed: false};
        const {sent} = loadHandoff({opener, origins: [SENDER, 'https://example.test']});

        expect(sent.map((s) => s.target)).toEqual([SENDER, 'https://example.test']);
        expect(sent.every((s) => s.message.type === READY)).toBe(true);
    });

    test('it says nothing when no origin is allowed', () => {
        const opener = {closed: false};
        expect(loadHandoff({opener, origins: []}).sent).toEqual([]);
    });

    test('opened by hand it explains itself instead of waiting', () => {
        const {elements, sent} = loadHandoff({opener: null});

        expect(elements['handoff-status'].textContent).toBe('Nothing was handed to this page.');
        expect(elements['handoff-hint'].hidden).toBe(false);
        expect(sent).toEqual([]);
    });

    test('an opener that has since gone is the same as none', () => {
        const {elements} = loadHandoff({opener: {closed: true}});
        expect(elements['handoff-status'].textContent).toBe('Nothing was handed to this page.');
    });

    test('it says nothing at all when the page cannot upload', () => {
        // The page has already said why. What matters here is the silence:
        // an extension that heard this one announce itself would hand over
        // a list nothing can price, and gathering that list is minutes of
        // somebody's afternoon.
        const opener = {closed: false};
        const {sent, submitted, deliver} = loadHandoff({opener, canUpload: false});

        expect(sent).toEqual([]);
        deliver(rowsMessage(opener));
        expect(submitted).toEqual([]);
    });
});

describe('taking the rows', () => {
    test('rows from an allowed origin are put in the form and sent', () => {
        const opener = {closed: false};
        const {deliver, elements, submitted} = loadHandoff({opener});

        deliver(rowsMessage(opener));

        expect(elements['handoff-rows'].value).toBe('a,b\n1,2\n');
        expect(submitted).toEqual([true]);
    });

    test('the sender says how many rows, since text cannot say', () => {
        // The page only sees text, and text does not say whether its first
        // line is a header or a card.
        const opener = {closed: false};
        const {deliver, elements} = loadHandoff({opener});

        deliver(rowsMessage(opener, {data: {type: ROWS, csv: 'a\n1\n', rows: 12}}));
        expect(elements['handoff-status'].textContent).toBe('Pricing 12 rows…');
    });

    test('one row is not one rows', () => {
        const opener = {closed: false};
        const {deliver, elements} = loadHandoff({opener});

        deliver(rowsMessage(opener, {data: {type: ROWS, csv: 'a\n1\n', rows: 1}}));
        expect(elements['handoff-status'].textContent).toBe('Pricing 1 row…');
    });

    test('no count given is no count claimed', () => {
        const opener = {closed: false};
        const {deliver, elements} = loadHandoff({opener});

        deliver(rowsMessage(opener));
        expect(elements['handoff-status'].textContent).toBe('Pricing your list…');
    });

    test('a second message is not a second upload', () => {
        const opener = {closed: false};
        const {deliver, submitted} = loadHandoff({opener});

        deliver(rowsMessage(opener));
        deliver(rowsMessage(opener));
        expect(submitted).toEqual([true]);
    });
});

describe('refusing the rest', () => {
    const opener = {closed: false};

    for (const [desc, over] of [
        ['another origin', {origin: 'https://evil.test'}],
        ['another window on an allowed origin', {source: {}}],
        ['a message that is not ours', {data: {type: 'something-else', csv: 'a\n1\n'}}],
        ['rows that are not a string', {data: {type: ROWS, csv: ['a', 'b']}}],
        ['no data at all', {data: null}],
        ['an empty list', {data: {type: ROWS, csv: ''}}],
        // Refused for the same reason the empty one is: there is nothing in
        // it to price, and submitting says otherwise.
        ['a list of nothing but whitespace', {data: {type: ROWS, csv: '   \n\t\n'}}],
    ]) {
        test(desc + ' is ignored', () => {
            const {deliver, submitted, elements} = loadHandoff({opener});
            deliver(rowsMessage(opener, over));
            expect(submitted).toEqual([]);
            expect(elements['handoff-rows'].value).toBe('');
        });
    }
});

describe('on any other page', () => {
    test('it does nothing at all', () => {
        // The script ships in the site's own bundle; a page without the
        // handoff markup is not one it has anything to do with.
        const opener = {closed: false};
        const {sent} = loadHandoff({opener, missingRoot: true});
        expect(sent).toEqual([]);
    });
});

describe('where the rows were read', () => {
    // Carried so the results can say "Cardmarket" rather than "pasted
    // text". What it is called is decided on the server; what crosses here
    // is a URL, and only one belonging to the origin that sent it.
    const opener = () => ({closed: false});

    test('a page on the sending origin is carried', () => {
        const op = opener();
        const {deliver, elements} = loadHandoff({opener: op});
        const url = SENDER + '/en/Magic/Users/Seller/Offers/Singles';

        deliver(rowsMessage(op, {data: {type: ROWS, csv: 'a\n1\n', source: url}}));

        expect(elements['handoff-source'].value).toBe(url);
    });

    test('a page somewhere else is not', () => {
        // The origin check on the message says who is talking; this says
        // the page they name is one of their own.
        const op = opener();
        const {deliver, elements, submitted} = loadHandoff({opener: op});

        deliver(rowsMessage(op, {
            data: {type: ROWS, csv: 'a\n1\n', source: 'https://example.test/somewhere'},
        }));

        expect(elements['handoff-source'].value).toBe('');
        // The rows are still good; only the label was refused.
        expect(submitted).toEqual([true]);
    });

    test('something that is not a URL is not', () => {
        const op = opener();
        const {deliver, elements, submitted} = loadHandoff({opener: op});

        deliver(rowsMessage(op, {data: {type: ROWS, csv: 'a\n1\n', source: 'not a url'}}));

        expect(elements['handoff-source'].value).toBe('');
        expect(submitted).toEqual([true]);
    });

    test('rows sent without one are taken as they always were', () => {
        const op = opener();
        const {deliver, elements, submitted} = loadHandoff({opener: op});

        deliver(rowsMessage(op));

        expect(elements['handoff-source'].value).toBe('');
        expect(submitted).toEqual([true]);
    });
});
