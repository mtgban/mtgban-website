import { test, expect, describe } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/upload-handoff.js', import.meta.url), 'utf8');

const SENDER = 'https://www.cardmarket.com';
const READY = 'mtgban-handoff-ready';
const ROWS = 'mtgban-handoff-rows';

// loadHandoff runs the script against a stand-in for the page it ships with,
// and hands back what the test needs to drive it: the opener it talks to, the
// listener it attached, and the elements it writes to.
function loadHandoff({origins = [SENDER], opener = {closed: false}, missingRoot = false} = {}) {
    const sent = [];
    if (opener) {
        opener.postMessage = (message, target) => sent.push({message, target});
    }

    const submitted = [];
    const elements = {
        handoff: {getAttribute: () => JSON.stringify(origins)},
        'handoff-status': {textContent: ''},
        'handoff-hint': {hidden: true},
        'handoff-form': {submit: () => submitted.push(true)},
        'handoff-rows': {value: ''},
    };

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
