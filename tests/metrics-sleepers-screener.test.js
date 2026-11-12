import { test, expect } from 'bun:test';
import { read, tagsWith, expectTrack, fakeBAN } from './metrics-helpers.js';
import { trackProblems } from './track-registry.js';

const desktop = read('templates/sleep.html');
const mobile = read('templates/mobile/sleep.html');
const screener = read('templates/screener.html');
const files = { desktop, mobile, screener };

test.each([
    ['desktop', 'id="sleepers-comp-go"', 'ui.sleepers.gap', 'compare', undefined],
    ['mobile', 'id="sleepers-comp-go"', 'ui.sleepers.gap', 'compare', undefined],
    ['desktop', '<a href="{{$card.SearchURL}}"', 'ui.sleepers.card', undefined, undefined],
    ['mobile', 'class="m-sleep-card"', 'ui.sleepers.card', undefined, undefined],
    ['screener', 'class="screener-reset"', 'ui.screener.control', 'reset', undefined],
    ['screener', 'class="screener-apply"', 'ui.screener.control', 'apply', undefined],
    ['screener', '&index={{.PrevIndex}}"', 'ui.screener.pager', 'prev', undefined],
    ['screener', '&index={{.NextIndex}}"', 'ui.screener.pager', 'next', undefined],
    ['screener', 'class="news-upload-btn"', 'ui.screener.upload_page', undefined, undefined],
    ['screener', 'class="card-name" href="{{$card.SearchURL}}"', 'ui.screener.card', undefined, undefined],
])('%s: the tag with %s tracks %s:%s', (file, marker, name, value, scope) => {
    const found = tagsWith(files[file], marker);
    expect(found.length).toBe(1);
    expectTrack(found[0], name, value, scope);
});

test.each([
    ['desktop', 'class="card sleepers-tool"'], ['mobile', 'class="m-sleep-tool"'],
])('%s: four tool cards, each counting the tool its href names', (file, marker) => {
    const found = tagsWith(files[file], marker);
    expect(found.length).toBe(4);
    for (const tag of found) {
        const page = tag.match(/href="\?page=(\w+)"/)[1];
        expectTrack(tag, 'ui.sleepers.tool', page, undefined);
    }
    expect(found.map((t) => t.match(/data-track-value="(\w+)"/)[1])).toEqual(['reprint', 'mismatch', 'hotlist', 'velocity']);
});

test.each([
    ['desktop', 'class="sleepers-comp-preset"'], ['mobile', 'class="m-sleep-gap-preset"'],
])('%s: five gap presets count preset', (file, marker) => {
    const found = tagsWith(files[file], marker);
    expect(found.length).toBe(5);
    found.forEach((t) => expectTrack(t, 'ui.sleepers.gap', 'preset', undefined));
});

test('the two screener sort anchors carry desc then asc, as their dir= gives', () => {
    const found = tagsWith(screener, '&sort={{.Field}}&dir=');
    expect(found.length).toBe(2);
    expect(found[0]).toContain('&dir=desc"');
    expectTrack(found[0], 'ui.screener.sort', '{{.Field}}', 'desc');
    expect(found[1]).toContain('&dir=asc"');
    expectTrack(found[1], 'ui.screener.sort', '{{.Field}}', 'asc');
});

test('every sort field the screener template passes is a registered value', () => {
    const fields = [...screener.matchAll(/template "screener-sort" \(dict "Field" "(\w+)"/g)].map((m) => m[1]);
    expect(fields).toEqual(['current', 'prior', 'pct', 'abs']);
    const marks = fields.map((f) => '<a data-track="ui.screener.sort" data-track-value="' + f + '" data-track-scope="asc">');
    expect(trackProblems(marks.join(''))).toEqual([]);
});

test('the back links, the settings link and the noscript link carry no mark', () => {
    expect(tagsWith(desktop, 'class="sleepers-back-link"')[0]).not.toContain('data-track');
    expect(tagsWith(mobile, 'class="m-sleep-back"')[0]).not.toContain('data-track');
    expect(tagsWith(mobile, 'class="m-sleep-settings-link"')[0]).not.toContain('data-track');
    expect(tagsWith(screener, '&rows=1"')[0]).not.toContain('data-track');
});

test('every literal mark on the sleepers and screener pages is in the registry', () => {
    for (const src of [desktop, mobile, screener]) {
        expect(trackProblems(src).filter((p) => !p.includes('{{'))).toEqual([]);
    }
});

test('the page loads js/screener.js', () => {
    expect(screener).toContain('src="/js/screener.js?hash={{.Hash}}" defer');
});

// js/screener.js on a document that keeps its listeners.
function loadScreener(ban = true) {
    const f = fakeBAN();
    const window = ban ? { BAN: f.BAN } : {};
    const listeners = {};
    const document = { addEventListener: (ev, fn) => { (listeners[ev] = listeners[ev] || []).push(fn); } };
    new Function('window', 'document', read('js/screener.js'))(window, document);
    const fire = (target) => (listeners.change || []).forEach((fn) => fn({ target }));
    return { ScreenerTrack: window.ScreenerTrack, fire, calls: f.calls };
}
const form = {};
const field = (name, inForm = true) => ({ name, closest: (sel) => (sel === 'form[action="/screener"]' && inForm ? form : null) });

test('each filter control maps to its registry value', () => {
    const { ScreenerTrack } = loadScreener();
    for (const [name, want] of [['provider', 'provider'], ['window', 'window'], ['kind', 'kind'], ['move', 'move'], ['size', 'size'], ['edition', 'editions'], ['min_price', ''], ['sort', ''], ['constructor', ''], ['toString', ''], ['__proto__', '']]) {
        expect(ScreenerTrack.control(name)).toBe(want);
    }
});

test('a change inside the screener form counts its control', () => {
    const { fire, calls } = loadScreener();
    fire(field('window'));
    fire(field('edition'));
    expect(calls).toEqual([['ui.screener.control', 'window', undefined], ['ui.screener.control', 'editions', undefined]]);
});

test('a text box change, and a change outside the form, count nothing', () => {
    const { fire, calls } = loadScreener();
    fire(field('min_price'));
    fire(field('max_pct'));
    fire(field('window', false));
    fire({ name: 'window' });
    expect(calls).toEqual([]);
});

test('with no BAN a change does nothing and does not throw', () => {
    const { fire, ScreenerTrack } = loadScreener(false);
    expect(() => fire(field('window'))).not.toThrow();
    expect(ScreenerTrack.control('kind')).toBe('kind');
});
