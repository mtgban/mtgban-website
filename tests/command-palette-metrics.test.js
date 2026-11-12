import { test, expect } from 'bun:test';
import { palette } from './palette-harness.js';

const open = (opts) => { const p = palette(opts); p.doc({ key: '/' }); return p; };

test('each way in is counted once, in the palette and not the loader', () => {
    const p = palette();
    p.doc({ key: 'k', ctrlKey: true });
    p.doc({ key: 'k', ctrlKey: true }); // closes
    p.doc({ key: '/' });
    p.doc({ key: '/' }); // already open
    expect(p.named('ui.palette.open')).toEqual([['ctrl_k'], ['slash']]);
});

test('a palette closed with nothing picked is dismissed', () => {
    const p = open();
    p.type('>news');
    p.key({ key: 'Escape' });
    expect(p.named('ui.palette.close')).toEqual([['dismissed']]);
    p.key({ key: 'Escape' }); // closed already
    expect(p.named('ui.palette.close')).toHaveLength(1);
});

test('a mode is counted once an open however many keys are typed in it', () => {
    const p = open();
    p.type('>');
    p.type('>n');
    p.type('>ne');
    p.type('');
    p.type('>');
    expect(p.named('ui.palette.mode')).toEqual([['nav', 'prefix']]);
    p.key({ key: 'Escape' });
    p.doc({ key: '/' });
    p.type('>');
    expect(p.named('ui.palette.mode')).toEqual([['nav', 'prefix'], ['nav', 'prefix']]);
});

test('a mode entered from its tile says so', () => {
    const p = open();
    p.click(1); // Help & syntax
    expect(p.named('ui.palette.mode')).toEqual([['help', 'tile']]);
    p.type('*');
    expect(p.named('ui.palette.mode')).toEqual([['help', 'tile'], ['saved', 'prefix']]);
});

test('every context has a mode value and a scope', () => {
    const p = open();
    p.type('bolt');
    p.type('s:');
    p.type('>news');
    p.key({ key: 'Tab' }); // locks Newspaper: its sub-views
    expect(p.named('ui.palette.mode')).toEqual([
        ['search', 'typed'], ['provider', 'prefix'], ['nav', 'prefix'], ['subview', 'chip'],
    ]);
});

test('a sealed chip opens the sealed actions', async () => {
    const p = open({ sealed: ['Alpha Booster Box'] });
    p.type('$');
    await p.settle();
    p.type('$alp');
    p.key({ key: 'Tab' });
    expect(p.named('ui.palette.mode')).toEqual([['sealed', 'prefix'], ['sealed_actions', 'chip']]);
});

test('typing after the palette closed counts no mode', () => {
    const p = open();
    p.key({ key: 'Escape' });
    p.type('>');
    expect(p.named('ui.palette.mode')).toEqual([]);
});

test('with no BAN on the page the palette still works', () => {
    const p = palette({ noBAN: true });
    p.doc({ key: '/' });
    p.type('>news');
    p.key({ key: 'Enter' });
    expect(p.location.href).toBe('/newspaper');
});

test('a pick that leaves the page closes as acted, once, with no close call', () => {
    const p = open();
    p.type('>news');
    p.key({ key: 'Enter' });
    expect(p.location.href).toBe('/newspaper');
    expect(p.named('ui.palette.close')).toEqual([['acted']]);
    p.key({ key: 'Escape' });
    expect(p.named('ui.palette.close')).toEqual([['acted']]);
});

test('a step that keeps the palette open is not acting; the flag resets on the next open', () => {
    const p = open();
    p.click(0); // the Pages tile
    expect(p.named('ui.palette.pick')).toEqual([['click', 'shortcut']]);
    p.key({ key: 'Escape' });
    expect(p.named('ui.palette.close')).toEqual([['dismissed']]);
    p.doc({ key: '/' });
    p.type('>sear');
    p.key({ key: 'Enter' });
    expect(p.named('ui.palette.close')).toEqual([['dismissed'], ['acted']]);
});

test('Enter, click and Shift+Enter name how the row was picked', () => {
    const saved = [{ id: 'cmd_1', name: 'mine', query: 'bolt', chips: [] }];
    let p = open({ stored: { mtgban_saved_commands: saved } });
    p.type('*');
    p.key({ key: 'Enter' });
    expect(p.named('ui.palette.pick')).toEqual([['enter', 'saved']]);

    p = open({ stored: { mtgban_saved_commands: saved } });
    p.type('*');
    p.click(0);
    expect(p.named('ui.palette.pick')).toEqual([['click', 'saved']]);

    p = open({ stored: { mtgban_saved_commands: saved } });
    p.type('*');
    p.key({ key: 'Enter', shiftKey: true });
    expect(p.named('ui.palette.pick')).toEqual([['shift_enter', 'saved']]);
    expect(p.named('ui.palette.close')).toEqual([]);
});

test('Ctrl+Enter is its own pick where the row has one, and plain Enter where it has none', async () => {
    const p = open({ sealed: ['Alpha Booster Box'] });
    p.type('$');
    await p.settle();
    p.type('$alp');
    p.key({ key: 'Enter', ctrlKey: true });
    expect(p.location.href).toContain('unpack');
    expect(p.named('ui.palette.pick')).toEqual([['ctrl_enter', 'sealed_suggestion']]);
    expect(p.named('ui.palette.close')).toEqual([['acted']]);

    const q = open();
    q.type('>sear');
    q.key({ key: 'Enter', ctrlKey: true });
    expect(q.named('ui.palette.pick')).toEqual([['enter', 'nav']]);
});

test('Tab on a card locks a chip and is a pick that keeps the palette open', async () => {
    const p = open({ cards: ['Lightning Bolt'] });
    await p.settle();
    p.type('lightn');
    p.key({ key: 'ArrowDown' }); // past the Search row
    p.key({ key: 'Tab' });
    expect(p.named('ui.palette.pick')).toEqual([['tab', 'card']]);
    expect(p.named('ui.palette.close')).toEqual([]);
});

test('Tab on a leaf page navigates, so it ends the session', () => {
    const p = open();
    p.type('>sear');
    p.key({ key: 'Tab' });
    expect(p.location.href).toBe('/search');
    expect(p.named('ui.palette.pick')).toEqual([['tab', 'nav']]);
    expect(p.named('ui.palette.close')).toEqual([['acted']]);
});

test('Enter with chips and an empty input is a composed run, not a pick', () => {
    const p = open();
    p.type('cond:n');
    p.key({ key: 'Tab' });
    p.key({ key: 'Enter' });
    expect(p.location.href).toBe('/search?q=cond%3ANM');
    expect(p.named('ui.palette.composed_run')).toEqual([['search']]);
    expect(p.named('ui.palette.pick')).toEqual([['tab', 'filter_candidate']]);
    expect(p.named('ui.palette.close')).toEqual([['acted']]);
});

test('a locked page and its sub-view run as a nav composition', () => {
    const p = open();
    p.type('>news');
    p.key({ key: 'Tab' });
    p.key({ key: 'ArrowDown' });
    p.key({ key: 'Tab' });
    p.key({ key: 'Enter' });
    expect(p.location.href).toBe('/newspaper?page=syp');
    expect(p.named('ui.palette.composed_run')).toEqual([['nav']]);
});

test('Enter on a filter row is a pick; the run it starts is not counted again', () => {
    const p = open();
    p.type('cond:n');
    p.key({ key: 'Enter' });
    expect(p.location.href).toBe('/search?q=cond%3ANM');
    expect(p.named('ui.palette.pick')).toEqual([['enter', 'filter_candidate']]);
    expect(p.named('ui.palette.composed_run')).toEqual([]);
});

test('Enter in the chip box picks the highlighted row, or runs the composition', () => {
    const p = open();
    p.type('cond:n');
    p.key({ key: 'Tab' });
    p.type('>sear');
    p.input.selectionStart = 0; p.input.selectionEnd = 0;
    p.key({ key: 'ArrowLeft' }); // activates the chip
    p.chipKey({ key: 'Enter' });
    expect(p.named('ui.palette.pick').pop()).toEqual(['enter', 'nav']);

    const q = open();
    q.type('cond:n');
    q.key({ key: 'Tab' });
    q.key({ key: 'Backspace' }); // activates the chip
    q.chipKey({ key: 'Enter' });
    expect(q.named('ui.palette.composed_run')).toEqual([['search']]);
});

test('a disabled row is never a pick', () => {
    const p = open();
    p.type('+ ');
    p.key({ key: 'Enter' }); // the hint row
    p.key({ key: 'Tab' });
    expect(p.named('ui.palette.pick')).toEqual([]);
});

test('a filter row counts its prefix, negated when it was', () => {
    const p = open();
    p.type('-is:');
    p.key({ key: 'Tab' });
    p.type('cond:n');
    p.key({ key: 'Enter' });
    expect(p.named('ui.palette.filter')).toEqual([['-is'], ['cond']]);
});

test('a page row counts the page by its slug: leaf, parent or sub-view', () => {
    const nav = [{ name: 'Search', link: '/search' }, { name: 'Newspaper', link: '/newspaper' },
        { name: 'TCG Syp List', link: '/newspaper?page=syp' }, { name: 'Admin', link: '/admin' }, { name: 'Brand New', link: '/new' }];
    const pick = (text, key) => { const p = open({ nav }); p.type(text); p.key(key || { key: 'Enter' }); return p.named('ui.palette.nav'); };
    expect(pick('>sear')).toEqual([['search', 'leaf']]);
    expect(pick('>sear', { key: 'Tab' })).toEqual([['search', 'leaf']]);
    expect(pick('>news')).toEqual([['newspaper', 'parent']]);
    expect(pick('>news', { key: 'Tab' })).toEqual([]);
    expect(pick('>tcg')).toEqual([['syp', 'leaf']]);
    expect(pick('>brand')).toEqual([['other', 'leaf']]);
    expect(pick('>admin')).toEqual([]);

    const p = open({ nav });
    p.type('>news');
    p.key({ key: 'Tab' });
    p.key({ key: 'ArrowDown' });
    p.key({ key: 'Enter' });
    expect(p.named('ui.palette.nav')).toEqual([['newspaper', 'sub']]);
});

test('each command has a fixed slug, and Ctrl+S is the save command by hotkey', () => {
    const closes = {};
    for (const [text, slug] of [['toggle theme', 'toggle_theme'], ['random card', 'random_card'], ['random sealed', 'random_sealed'],
        ['open guide', 'open_guide'], ['copy page', 'copy_url'], ['save current', 'save_search']]) {
        const p = open();
        p.type('cond:n');
        p.key({ key: 'Tab' }); // something to save
        p.type(text);
        p.key({ key: 'ArrowDown' }); // past the Search row
        p.key({ key: 'Enter' });
        expect(p.named('ui.palette.command')).toEqual([[slug, 'row']]);
        closes[slug] = p.named('ui.palette.close');
    }
    expect(closes.save_search).toEqual([]);
    expect(closes.random_card).toEqual([['acted']]);
    expect(closes.toggle_theme).toEqual([['acted']]); // it calls closePalette itself

    const p = open();
    p.key({ key: 's', ctrlKey: true }); // nothing to save: no modal, no count
    expect(p.named('ui.palette.command')).toEqual([]);
    p.type('cond:n');
    p.key({ key: 'Tab' });
    p.key({ key: 's', ctrlKey: true });
    expect(p.named('ui.palette.command')).toEqual([['save_search', 'hotkey']]);
});

test('a held Enter, Ctrl+Enter or Tab counts its pick once', async () => {
    const p = open();
    p.type('>sear');
    p.key({ key: 'Enter' });
    p.key({ key: 'Enter', repeat: true });
    expect(p.location.href).toBe('/search');
    expect(p.named('ui.palette.pick')).toEqual([['enter', 'nav']]);
    expect(p.named('ui.palette.nav')).toEqual([['search', 'leaf']]);

    const q = open({ sealed: ['Alpha Booster Box'] });
    q.type('$');
    await q.settle();
    q.type('$alp');
    q.key({ key: 'Enter', ctrlKey: true });
    q.key({ key: 'Enter', ctrlKey: true, repeat: true });
    expect(q.named('ui.palette.pick')).toEqual([['ctrl_enter', 'sealed_suggestion']]);
    expect(q.named('ui.palette.sealed')).toEqual([['unpack']]);

    const r = open();
    r.type('>sear');
    r.key({ key: 'Tab' });
    r.key({ key: 'Tab', repeat: true });
    expect(r.named('ui.palette.pick')).toEqual([['tab', 'nav']]);

    const c = open();
    c.type('cond:n');
    c.key({ key: 'Tab' });
    c.type('>sear');
    c.input.selectionStart = 0; c.input.selectionEnd = 0;
    c.key({ key: 'ArrowLeft' }); // activates the chip
    c.chipKey({ key: 'Enter', repeat: true });
    expect(c.named('ui.palette.pick')).toEqual([['tab', 'filter_candidate']]);
    expect(c.location.href).toBe('/search');
});

test('a help row copies or opens the guide, and Shift+Enter with nowhere to go is no pick', () => {
    const guide = [
        { id: 'sets', title: 'Set filter', category: 'Search Syntax', snippets: ['s:lea'] },
        { id: 'tiers', title: 'Tiers explained', category: 'Account' },
    ];
    const run = (text, shiftKey) => { const p = open({ guide }); p.type(text); p.key({ key: 'Enter', shiftKey }); return p; };
    expect(run('?set').named('ui.palette.help')).toEqual([['copy']]);
    expect(run('?set', true).named('ui.palette.help')).toEqual([['open_guide']]);
    expect(run('?tiers').named('ui.palette.help')).toEqual([['open_guide']]);
    const p = run('?tiers', true);
    expect(p.tracked.filter(t => t[0] !== 'ui.palette.open' && t[0] !== 'ui.palette.mode')).toEqual([]);
});

test('a recent or saved search run from its row', () => {
    const p = open({ stored: { mtgban_recent_searches: [{ q: 'bolt', t: 1 }] } });
    p.type('<');
    p.key({ key: 'Enter' });
    expect(p.named('ui.palette.recent')).toEqual([['run']]);

    const saved = [{ id: 'cmd_1', name: 'mine', query: 'bolt', chips: [] }];
    const q = open({ stored: { mtgban_saved_commands: saved } });
    q.type('*');
    q.key({ key: 'Enter', shiftKey: true });
    q.type('*');
    q.key({ key: 'Enter' });
    expect(q.named('ui.palette.saved')).toEqual([['restore'], ['run']]);
});

test('a sealed product opened three ways', async () => {
    const act = async (key, lock) => {
        const p = open({ sealed: ['Alpha Booster Box'] });
        p.type('$');
        await p.settle();
        p.type('$alp');
        if (lock) { p.key({ key: 'Tab' }); p.key({ key: 'ArrowDown' }); }
        p.key(key);
        return p.named('ui.palette.sealed');
    };
    expect(await act({ key: 'Enter' })).toEqual([['search']]);
    expect(await act({ key: 'Enter', shiftKey: true })).toEqual([['contents']]);
    expect(await act({ key: 'Enter', ctrlKey: true })).toEqual([['unpack']]);
    expect(await act({ key: 'Enter' }, true)).toEqual([['search']]); // the Search action of a locked product
});

test('upload rows: the host of a url, the file picker, the page results, an export field', () => {
    let p = open({ hashes: 3 });
    p.type('+https://www.moxfield.com/decks/abc');
    p.key({ key: 'Enter' });
    expect(p.named('ui.palette.upload')).toEqual([['url', 'moxfield']]);

    p = open({ hashes: 3 });
    p.type('+ ');
    p.key({ key: 'ArrowDown' });
    p.key({ key: 'Enter' });
    p.key({ key: 'ArrowDown' });
    p.key({ key: 'Enter' });
    expect(p.named('ui.palette.upload')).toEqual([['file', 'picker'], ['page_results', 'page']]);
    expect(p.named('ui.palette.pick')).toEqual([['enter', 'upload_file'], ['enter', 'upload_page_results']]);

    p = open({ path: '/upload', exports: ['download', 'deckbox'] });
    p.type('+ ');
    p.key({ key: 'ArrowDown' });
    p.key({ key: 'ArrowDown' });
    p.key({ key: 'ArrowDown' });
    p.key({ key: 'Enter' });
    expect(p.named('ui.palette.upload')).toEqual([['export', 'deckbox']]);
    expect(p.named('ui.palette.close')).toEqual([['acted']]);
});

test('nothing the reader typed or stored is sent', () => {
    const saved = [{ id: 'cmd_1', name: 'My Secret List', query: 'private query', chips: [] }];
    const p = open({ cards: ['Lightning Bolt'], stored: { mtgban_saved_commands: saved } });
    p.type('some secret query');
    p.type('*');
    p.key({ key: 'Enter' });
    for (const call of p.tracked) {
        expect(call.length).toBeLessThanOrEqual(3);
        for (const part of call) expect(part).toMatch(/^-?[a-z0-9_.]+$/);
    }
});

// Every value and scope the palette's names can send, as registered.
const SENDABLE = {
    'ui.palette.open': 'ctrl_k slash',
    'ui.palette.close': 'acted dismissed',
    'ui.palette.mode': 'nav help saved recent sealed upload provider subview sealed_actions search prefix tile chip typed',
    'ui.palette.pick': 'enter shift_enter ctrl_enter tab click shortcut nav nav_sub card filter_candidate recent saved help command search sealed_suggestion sealed_fallback sealed_action upload_url upload_file upload_page_results upload_export',
    'ui.palette.composed_run': 'search nav',
    'ui.palette.command': 'toggle_theme random_card random_sealed open_guide copy_url save_search row hotkey',
    'ui.palette.filter': 'r f cond sm sort on format is not skip region c ci s e in store seller vendor -r -f -cond -sm -sort -on -format -is -not -skip -region -c -ci -s -e -in -store -seller -vendor',
    'ui.palette.chip': 'lock remove edit card filter sealed nav nav_sub',
    'ui.palette.saved': 'new updated overwrite cap run restore delete delete_silent',
    'ui.palette.recent': 'run delete',
    'ui.palette.help': 'copy open_guide',
    'ui.palette.sealed': 'search contents unpack',
    'ui.palette.upload': 'url file page_results export tcgplayer moxfield manabox archidekt cubecobra mythictools sheets picker page download estimate deckbox tcgplayer_csv',
    'ui.palette.nav': 'home changelog account search sets sealed newspaper syp screener sleepers upload global arbitrage reverse alerts api other leaf parent sub',
};

test('no reader text and no inherited name is sent, on any pick path', async () => {
    const M = 'zzmarker';
    const nav = [{ name: 'Search', link: '/search' }, { name: 'Newspaper', link: '/newspaper' },
        { name: 'constructor', link: '/constructor' }, { name: M + ' Page', link: '/' + M }];
    const hostile = [{ type: 'constructor', value: M, label: M }, { type: '__proto__', value: M, label: M }];
    const saved = [
        { id: 'cmd_1', name: M + ' saved', query: M + ' query', chips: [{ type: 'filter', value: 'cond:NM', label: M + ' label' }] },
        { id: 'cmd_2', name: M + ' hostile', query: M, chips: hostile },
        { id: 'cmd_3', name: M + ' nav', query: M, chips: [{ type: 'nav', navName: 'toString', value: M, label: M }] },
    ];
    const opts = {
        nav, cards: [M + ' Bolt'], sealed: [M + ' Booster Box'], hashes: 2,
        guide: [{ id: M, title: M + ' guide', category: 'Search Syntax', snippets: [M] }],
        stored: { mtgban_saved_commands: saved, mtgban_recent_searches: [{ q: M + ' recent', t: 1 }] },
    };
    const sent = [];
    const run = async (steps) => { const p = open(opts); await p.settle(); steps(p); sent.push(...p.tracked); return p; };
    const keys = (...list) => (p) => list.forEach((k) => (typeof k === 'string' ? p.type(k) : p.key(k)));
    const enter = { key: 'Enter' }, shift = { key: 'Enter', shiftKey: true }, ctrl = { key: 'Enter', ctrlKey: true };
    const down = { key: 'ArrowDown' }, tab = { key: 'Tab' }, back = { key: 'Backspace' }, del = { key: 'Delete' };
    const restore = (p, at) => { p.type('*'); for (let i = 0; i < at; i++) p.key(down); p.key(shift); p.type(''); };

    // Typed text, a card, a recent and a saved search, a product, a guide entry, pages and uploads, picked every way.
    for (const how of [enter, shift, ctrl, tab]) {
        for (const text of [M + ' query', '<', '*', '$' + M, '?' + M, '>constructor', '>' + M,
            '+https://www.moxfield.com/decks/' + M, '+https://' + M + '.example/' + M]) {
            await run(keys(text, how));
            await run(keys(text, down, how));
            await run(keys(text, down, down, how));
        }
        await run(keys('+ ', down, how));
        await run(keys('+ ', down, down, how));
    }
    await run((p) => { p.type(M + ' query'); p.click(0); });
    await run((p) => { p.type(M); p.click(1); });
    await run((p) => { p.type('*'); p.click(1); });
    await run((p) => { p.type('>constructor'); p.click(0); });
    // Each restored saved search's chips removed, edited, run, and run from the chip box.
    for (const at of [0, 1, 2]) {
        await run((p) => { restore(p, at); p.key(back); p.chipKey(del); p.chipKey(back); });
        await run((p) => { restore(p, at); p.key(back); p.chipKey(tab); });
        await run((p) => { restore(p, at); p.key(enter); });
        await run((p) => { p.type('*'); for (let i = 0; i < at; i++) p.key(down); p.key(shift); p.key(enter); });
        await run((p) => { restore(p, at); p.key(back); p.chipKey(enter); });
    }
    // A card chip locked, removed and edited, a composed run, deletes and a save.
    await run((p) => { p.type(M); p.key(down); p.key(tab); p.key(back); p.chipKey(del); });
    await run((p) => { p.type(M); p.key(down); p.key(tab); p.key(back); p.chipKey(tab); });
    await run(keys('cond:n', tab, '', enter));
    await run(keys('*', { key: 'Delete', shiftKey: true }));
    await run(keys('<', { key: 'Delete', shiftKey: true }));
    await run((p) => {
        p.type('cond:n'); p.key(tab); p.key({ key: 's', ctrlKey: true });
        const f = p.made.map((el) => el.querySelector('#cp-save-modal-input')).filter((x) => x.handlers.keydown).pop();
        f.value = M + ' name';
        f.handlers.keydown({ key: 'Enter', preventDefault() {}, stopPropagation() {} });
    });

    expect(sent.length).toBeGreaterThan(200);
    for (const call of sent) {
        expect(Object.keys(SENDABLE)).toContain(call[0]);
        for (const part of call.slice(1)) {
            expect(typeof part).toBe('string');
            expect(part).not.toContain(M);
            expect(SENDABLE[call[0]].split(' ')).toContain(part);
        }
    }
    // The page named constructor is a leaf with no slug; the restored chips of no known type count nothing.
    const p = await run(keys('>constructor', enter));
    expect(p.named('ui.palette.nav')).toEqual([['other', 'leaf']]);
    const h = await run((q) => { restore(q, 1); q.key(back); q.chipKey(del); q.chipKey(back); });
    expect(h.made.filter((el) => typeof el.className === 'string' && el.className.split(' ')[0] === 'cp-chip').length).toBeGreaterThan(1);
    expect(h.named('ui.palette.chip')).toEqual([]);
});

test('chips: locked, removed three ways, edited', () => {
    const p = open();
    const lock = () => { p.type('cond:n'); p.key({ key: 'Tab' }); };
    lock();
    p.made.filter(el => el.className === 'cp-chip-delete').pop().handlers.click({ stopPropagation() {} });
    lock();
    p.key({ key: 'Backspace' }); // on an empty input: activates the chip
    p.chipKey({ key: 'Delete' });
    lock();
    p.key({ key: 'Backspace' });
    p.chipKey({ key: 'Backspace' });
    lock();
    p.key({ key: 'Backspace' });
    p.chipKey({ key: 'Tab' });
    expect(p.input.value).toBe('cond:NM');
    expect(p.named('ui.palette.chip')).toEqual([
        ['lock', 'filter'], ['remove', 'filter'], ['lock', 'filter'], ['remove', 'filter'],
        ['lock', 'filter'], ['remove', 'filter'], ['lock', 'filter'], ['edit', 'filter'],
    ]);
});

test('each kind of chip has its scope, and a replaced sub-view is not a remove', async () => {
    const p = open({
        cards: ['Lightning Bolt'], sealed: ['Alpha Booster Box'],
        nav: [{ name: 'Newspaper', link: '/newspaper' }],
    });
    await p.settle();
    p.type('lightn');
    p.key({ key: 'ArrowDown' });
    p.key({ key: 'Tab' });
    p.type('>news');
    p.key({ key: 'Tab' });
    p.key({ key: 'ArrowDown' });
    p.key({ key: 'Tab' });
    p.key({ key: 'ArrowDown' });
    p.key({ key: 'Tab' }); // the same sub-view again: replaces the first
    expect(p.named('ui.palette.chip')).toEqual([['lock', 'card'], ['lock', 'nav'], ['lock', 'nav_sub'], ['lock', 'nav_sub']]);
});

test('a restored chip of no known type is not counted', () => {
    const saved = [{ id: 'cmd_1', name: 'odd', query: 'x', chips: [{ type: '<img>', value: 'x', label: 'x' }] }];
    const p = open({ stored: { mtgban_saved_commands: saved } });
    p.type('*');
    p.key({ key: 'Enter', shiftKey: true });
    p.type('');
    p.key({ key: 'Backspace' });
    p.chipKey({ key: 'Delete' });
    expect(p.made.filter((el) => el.className === 'cp-chip-delete').length).toBeGreaterThan(0); // the chip was drawn
    expect(p.named('ui.palette.chip')).toEqual([]);
});

test('saving a search counts its outcome', () => {
    const field = p => p.made.map(el => el.querySelector('#cp-save-modal-input')).filter(f => f.handlers.keydown).pop();
    const enter = (p, text) => { const f = field(p); f.value = text; f.handlers.keydown({ key: 'Enter', preventDefault() {}, stopPropagation() {} }); };
    const save = (p, name) => { p.key({ key: 's', ctrlKey: true }); enter(p, name); };
    const chip = (p, text) => { p.type(text); p.key({ key: 'Tab' }); };

    const p = open();
    chip(p, 'cond:n');
    save(p, 'mine');     // new
    save(p, 'renamed');  // the same query: updated
    chip(p, 'sm:exact');
    save(p, 'renamed');  // the same name, another query: the modal asks
    expect(p.named('ui.palette.saved')).toEqual([['new'], ['updated']]);
    enter(p, 'y');
    expect(p.named('ui.palette.saved')).toEqual([['new'], ['updated'], ['overwrite']]);

    const full = Array.from({ length: 50 }, (_, i) => ({ id: 'cmd_' + i, name: 'n' + i, query: 'q' + i }));
    const q = open({ stored: { mtgban_saved_commands: full } });
    chip(q, 'cond:n');
    save(q, 'one more');
    expect(q.named('ui.palette.saved')).toEqual([['cap']]);
});

test('deleting a saved search: by Shift+Delete, by the button, and not when the confirm is refused', () => {
    const saved = [{ id: 'cmd_1', name: 'a', query: 'bolt' }, { id: 'cmd_2', name: 'b', query: 'opt' }];
    const p = open({ stored: { mtgban_saved_commands: saved } });
    p.type('*');
    p.key({ key: 'Delete', shiftKey: true });
    p.clickDelete(0, 'cmd_2');
    expect(p.named('ui.palette.saved')).toEqual([['delete_silent'], ['delete']]);
    expect(p.named('ui.palette.pick')).toEqual([]);

    const q = open({ stored: { mtgban_saved_commands: saved }, confirm: false });
    q.type('*');
    q.clickDelete(0, 'cmd_1');
    expect(q.named('ui.palette.saved')).toEqual([]);
});

test('removing a recent search from the palette', () => {
    const p = open({ stored: { mtgban_recent_searches: [{ q: 'bolt', t: 1 }] } });
    p.type('<');
    p.key({ key: 'Delete', shiftKey: true });
    expect(p.named('ui.palette.recent')).toEqual([['delete']]);
});
