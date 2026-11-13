import { test, expect } from 'bun:test';
import { read, tagsWith, expectTrack, fakeBAN } from './metrics-helpers.js';
import { trackProblems } from './track-registry.js';

const desktop = read('templates/news.html');
const mobile = read('templates/mobile/news.html');
const syp = read('templates/syp.html');

test.each([
    ['desktop', 'class="card news-toc-card"', 'ui.news.report', '{{$page.Option}}', 'card'],
    ['desktop', 'href="newspaper?page={{.Option}}"', 'ui.news.report', '{{.Option}}', 'tab'],
    ['mobile', 'class="m-news-toc-item"', 'ui.news.report', '{{$page.Option}}', 'card'],
    ['mobile', 'class="m-news-nav-pill', 'ui.news.report', '{{.Option}}', 'pill'],
    ['desktop', '&dir=desc&', 'ui.news.sort', '{{$head.Field}}', 'desc'],
    ['desktop', '&dir=asc&', 'ui.news.sort', '{{$head.Field}}', 'asc'],
    ['desktop', 'class="news-upload-btn"', 'ui.news.upload_page', undefined, undefined],
    ['desktop', 'href="{{$card.SearchURL}}" lang="{{$card.LangTag}}"', 'ui.news.card', undefined, undefined],
    ['mobile', 'class="m-news-detail-search"', 'ui.news.card', undefined, undefined],
    ['syp', 'class="arb-load-btn csv"', 'ui.news.syp', 'csv', undefined],
    ['syp', 'class="arb-qlink buy"', 'ui.news.syp', 'buy_link', undefined],
    ['syp', 'href="{{$card.SearchURL}}" lang="{{$card.LangTag}}"', 'ui.news.syp', 'card', undefined],
])('%s: the tag with %s tracks %s:%s', (file, marker, name, value, scope) => {
    const found = tagsWith({ desktop, mobile, syp }[file], marker);
    expect(found.length).toBe(1);
    expectTrack(found[0], name, value, scope);
});

test.each([
    ['desktop', desktop], ['mobile', mobile],
])('%s: the four pager links count first, prev, next and last', (_, src) => {
    for (const [marker, value] of [['&index=&', 'first'], ['&index={{.PrevIndex}}&', 'prev'], ['&index={{.NextIndex}}&', 'next'], ['&index={{.TotalIndex}}&', 'last']]) {
        const found = tagsWith(src, marker);
        expect(found.length).toBe(1);
        expectTrack(found[0], 'ui.news.pager', value, undefined);
    }
});

test('the 3-day switch names the edition it switches to through a closed choice', () => {
    const tag = tagsWith(desktop, 'href="newspaper?force3day={{.IsOneDay}}"')[0];
    expect(tag).toContain('data-track="ui.news.three_day" {{if .IsOneDay}}data-track-value="on"{{else}}data-track-value="off"{{end}}>');
});

test('the SYP sorts and pager links count sort and page', () => {
    const sorts = tagsWith(syp, 'href="?page=syp&sort=');
    expect(sorts.length).toBe(4);
    sorts.forEach((t) => expectTrack(t, 'ui.news.syp', 'sort', undefined));
    const pages = tagsWith(syp, 'href="?page=syp&p=');
    expect(pages.length).toBe(4);
    pages.forEach((t) => expectTrack(t, 'ui.news.syp', 'page', undefined));
});

test('the mobile filter toggle and settings link carry no mark', () => {
    expect(tagsWith(mobile, 'class="m-news-settings-link"')[0]).not.toContain('data-track');
});

test('every literal mark on the newspaper pages is in the registry', () => {
    for (const src of [desktop, mobile, syp]) {
        expect(trackProblems(src).filter((p) => !p.includes('{{'))).toEqual([]);
    }
});

// news-filters.js, as tests/news-filters.test.js loads it, with window.BAN added.
const filtersSource = read('js/news-filters.js');
function fakeStorage(initial = {}) {
    const m = Object.assign({}, initial);
    return {
        getItem: (k) => (k in m ? m[k] : null),
        setItem: (k, v) => { m[k] = String(v); },
        removeItem: (k) => { delete m[k]; },
    };
}
function fakeForm(pairs) {
    const listeners = {};
    const page = pairs.find(([k]) => k === 'page');
    return { pairs, dataset: {}, elements: page ? { page: { value: page[1] } } : {}, addEventListener: (ev, fn) => { listeners[ev] = fn; }, listeners };
}
function fakeLink(search) {
    const listeners = {};
    return { search, addEventListener: (ev, fn) => { listeners[ev] = fn; }, listeners };
}
function loadFilters({ form = null, links = [], search = '', local = fakeStorage(), ban = true } = {}) {
    const f = fakeBAN();
    const replaced = [];
    const window = { location: { search, pathname: '/newspaper', replace: (u) => replaced.push(u) } };
    if (ban) window.BAN = f.BAN;
    const document = {
        getElementById: (id) => (id === 'newsFilters' ? form : null),
        querySelectorAll: (sel) => (sel === '#newsTable .sort-links a' ? links : []),
        body: { getAttribute: (a) => (a === 'data-game' ? 'magic' : null) },
    };
    class FormData {
        constructor(x) { this.pairs = (x && x.pairs) || []; }
        [Symbol.iterator]() { return this.pairs[Symbol.iterator](); }
    }
    new Function('window', 'document', 'FormData', 'localStorage', filtersSource)(window, document, FormData, local);
    return { replaced, calls: f.calls };
}
const savedFor = (report, q) => fakeStorage({ mtgban_news_filters: JSON.stringify({ ['magic:' + report]: { q, t: 1 } }) });

test('a submit counts manual', () => {
    const form = fakeForm([['page', 'spike_score'], ['rarity', 'mythic']]);
    const { calls } = loadFilters({ form, search: '?page=spike_score&rarity=mythic' });
    form.listeners.submit();
    expect(calls).toEqual([['ui.news.filter_submit', 'manual', undefined]]);
});

test('a bare link with saved filters is replayed and counts auto_applied', () => {
    const form = fakeForm([['page', 'spike_score']]);
    const { replaced, calls } = loadFilters({ form, search: '?page=spike_score', local: savedFor('spike_score', 'rarity=mythic') });
    expect(replaced.length).toBe(1);
    expect(replaced[0].endsWith('&rarity=mythic')).toBe(true);
    expect(calls).toEqual([['ui.news.filter_submit', 'auto_applied', undefined]]);
});

test('a bare link with nothing saved, and a link with choices of its own, count nothing', () => {
    const form = fakeForm([['page', 'spike_score']]);
    expect(loadFilters({ form, search: '?page=spike_score' }).calls).toEqual([]);
    const own = loadFilters({ form, search: '?page=spike_score&rarity=rare', local: savedFor('spike_score', 'rarity=mythic') });
    expect(own.replaced).toEqual([]);
    expect(own.calls).toEqual([]);
});

test('a sort link saves its choices and makes no filter call', () => {
    const form = fakeForm([['page', 'spike_score']]);
    const link = fakeLink('?page=spike_score&sort=ranking&dir=asc');
    const local = fakeStorage();
    const { calls } = loadFilters({ form, links: [link], search: '?page=spike_score&sort=ranking', local });
    link.listeners.click();
    expect(JSON.parse(local.getItem('mtgban_news_filters'))['magic:spike_score'].q).toBe('sort=ranking&dir=asc');
    expect(calls).toEqual([]);
});

// edition-combobox.js over one stub combobox.
function loadCombobox(window) {
    const on = (target) => (ev, fn) => { target['on' + ev] = fn; };
    const display = { value: '', addEventListener: null };
    display.addEventListener = on(display);
    const hidden = { value: '' };
    const clearBtn = { hidden: true };
    clearBtn.addEventListener = on(clearBtn);
    const item = { dataset: { name: 'Modern Horizons' }, style: {}, classList: { add() {}, remove() {} } };
    const items = { querySelectorAll: () => [item] };
    items.addEventListener = on(items);
    let submits = 0;
    const form = { requestSubmit: () => { submits++; } };
    const combobox = {
        classList: { add() {}, remove() {}, contains: () => false }, setAttribute() {},
        querySelector: (sel) => ({ '[data-role="display"]': display, '[data-role="hidden"]': hidden, '[data-role="clear"]': clearBtn, '.autocomplete-items': items })[sel],
        closest: () => form,
    };
    let ready = null;
    const document = {
        addEventListener: (ev, fn) => { if (ev === 'DOMContentLoaded') ready = fn; },
        querySelectorAll: () => [combobox],
    };
    new Function('window', 'document', read('js/edition-combobox.js'))(window, document);
    ready();
    return { pick: () => items.onclick({ target: { closest: () => item } }), clearBtn, hidden, submits: () => submits };
}

test('the edition box counts pick and clear', () => {
    const { BAN, calls } = fakeBAN();
    const c = loadCombobox({ BAN });
    const ev = { preventDefault() {} };
    c.pick();
    expect(c.hidden.value).toBe('Modern Horizons');
    c.clearBtn.onclick(ev);
    expect(c.hidden.value).toBe('');
    expect(c.submits()).toBe(2);
    expect(calls).toEqual([['ui.news.edition', 'pick', undefined], ['ui.news.edition', 'clear', undefined]]);
});

test('with no window.BAN the filters and the edition box still work', () => {
    const form = fakeForm([['page', 'spike_score']]);
    const { replaced } = loadFilters({ form, search: '?page=spike_score', local: savedFor('spike_score', 'rarity=mythic'), ban: false });
    expect(replaced.length).toBe(1);
    expect(() => form.listeners.submit()).not.toThrow();
    const c = loadCombobox({});
    c.clearBtn.onclick({ preventDefault() {} });
    expect(c.submits()).toBe(1);
});
