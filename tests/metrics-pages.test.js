import { test, expect } from 'bun:test';
import { read, tagsWith, expectTrack, fakeBAN } from './metrics-helpers.js';
import { registry, trackProblems } from './track-registry.js';

const user = read('templates/user.html');
const home = read('templates/home.html');
const mobileHome = read('templates/mobile/home.html');
const plans = read('templates/api-plans.html');
const guide = read('templates/guide.html');
const changelog = read('templates/changelog.html');
const files = { user, home, mobileHome, plans, guide, changelog };
const GATE = '{{if and $.MetricsPage (not (or $.ModalMode $.ErrorMessage))}}';

test.each([
    ['user', 'href="/?errmsg=logout"', 'ui.account', 'logout'],
    ['user', '<a class="page-action user-login"', 'ui.account', 'login'],
    ['user', 'class="user-manage"', 'ui.account', 'manage_patreon'],
    ['user', 'title="Ask Patreon again', 'ui.account', 'refresh'],
    ['user', 'title="End your sign-in', 'ui.account', 'logout_everywhere'],
    ['user', 'class="card user-feature"', 'ui.account', 'feature_card'],
    ['user', 'href="https://www.patreon.com/mtgban"', 'ui.account', 'join_tier'],
    ['plans', 'href="/api-trial?return_to=', 'ui.apiplans', 'trial'],
    ['plans', '<button type="submit" class="api-btn"', 'ui.apiplans', 'checkout'],
    ['home', '<a href="/sets"', 'ui.home', 'sets'],
    ['home', '<a href="/sealed"', 'ui.home', 'sealed'],
    ['home', '<a href="/random"', 'ui.home', 'random'],
])('%s: the tag with %s tracks %s:%s', (file, marker, name, value) => {
    const found = tagsWith(files[file], marker);
    expect(found.length).toBe(1);
    expectTrack(found[0], name, value, undefined);
});

test('the disabled log in buttons carry no mark', () => {
    for (const src of [user, home, mobileHome]) {
        const disabled = tagsWith(src, 'type="button" disabled title="Login is unavailable');
        expect(disabled.length).toBe(1);
        expect(disabled[0]).not.toContain('data-track');
    }
});

test('both Manage your API access links count manage', () => {
    const found = tagsWith(plans, 'class="page-action"');
    expect(found.length).toBe(2);
    found.forEach((t) => expectTrack(t, 'ui.apiplans', 'manage', undefined));
});

test('the home footers count log in, log out, account, guide and Discord behind the page gate', () => {
    const marks = [
        ['patreon" href="javascript:', 'ui.account', 'login', 2],
        ['patreon" href="/?errmsg=logout"', 'ui.account', 'logout', 2],
        ['title="Account"', 'ui.nav.link', 'account', 2],
        ['title="Guide"', 'ui.nav.link', 'guide', 2],
        ['discord" href="/discord"', 'ui.nav.link', 'discord', 2],
    ];
    for (const [marker, name, value, n] of marks) {
        const found = tagsWith(home, marker).concat(tagsWith(mobileHome, marker));
        expect(found.length).toBe(n);
        for (const tag of found) {
            expect(tag).toContain(GATE + ' data-track="' + name + '" data-track-value="' + value + '"{{end}}>');
        }
    }
});

test('the noscript log in carries no mark: no script runs to count it', () => {
    const found = tagsWith(home, 'patreon" href="http://www.patreon.com/oauth2/authorize');
    expect(found.length).toBe(1);
    expect(found[0]).not.toContain('data-track');
});

test('the home blurb links sit behind the page gate', () => {
    for (const v of ['sets', 'sealed', 'random']) {
        expect(home).toContain(GATE + ' data-track="ui.home" data-track-value="' + v + '"{{end}}>');
    }
});

test('the five guide tabs each count their own tab', () => {
    const found = tagsWith(guide, 'class="guide-tab"');
    expect(found.length).toBe(5);
    for (const tag of found) {
        const tab = tag.match(/data-tab="(\w+)"/)[1];
        expectTrack(tag, 'ui.guide.tab', tab, undefined);
    }
    expect(found.map((t) => t.match(/data-tab="(\w+)"/)[1])).toEqual(registry['ui.guide.tab'].enum);
});

test('the changelog pager and its three image previews are counted', () => {
    const pager = tagsWith(changelog, 'href="/changelog?page=');
    expect(pager.length).toBe(2);
    pager.forEach((t) => expectTrack(t, 'ui.changelog', 'page', undefined));
    const lightbox = tagsWith(changelog, 'changelog-lightbox-trigger" href=');
    expect(lightbox.length).toBe(3);
    lightbox.forEach((t) => expectTrack(t, 'ui.changelog', 'lightbox', undefined));
    expect(tagsWith(changelog, 'class="changelog-source"')[0]).not.toContain('data-track');
    expect(tagsWith(changelog, 'class="changelog-attachment"')[0]).not.toContain('data-track');
});

test('every literal mark on these pages is in the registry', () => {
    for (const src of Object.values(files)) {
        expect(trackProblems(src.split(GATE).join('').split('{{end}}>').join('>')).filter((p) => !p.includes('{{'))).toEqual([]);
    }
});

const guideSource = read('js/guide.js');

test('the guide marks its sidebar links and example queries where it builds them', () => {
    expect(guideSource).toContain(`'" data-track="ui.guide" data-track-value="example_link">'`);
    expect(guideSource).toContain(`link.setAttribute('data-track', 'ui.guide');`);
    expect(guideSource).toContain(`link.setAttribute('data-track-value', 'section_link');`);
});

// A stand-in element: it keeps listeners and answers queries with empty lists.
function element() {
    const listeners = {};
    const el = {
        listeners, value: '', dataset: {}, innerHTML: '', textContent: '', className: '', style: {},
        classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
        getAttribute: () => null, setAttribute() {}, removeAttribute() {},
        querySelector: () => null, querySelectorAll: () => [],
        appendChild: (c) => c, insertBefore: (c) => c, closest: () => null,
        addEventListener: (type, fn) => { (listeners[type] = listeners[type] || []).push(fn); },
        dispatchEvent: (ev) => { (listeners[ev.type] || []).forEach((fn) => fn.call(el, ev)); return true; },
    };
    return el;
}

// js/guide.js on a page with no sections, its filter and tab buttons kept.
function loadGuide(ban = true) {
    const f = fakeBAN();
    const filter = element();
    const tab = element();
    tab.dataset.tab = 'syntax';
    const byId = { 'guide-filter': filter, 'guide-sidebar-nav': element(), 'guide-sections': element() };
    const document = {
        getElementById: (id) => byId[id] || null,
        querySelectorAll: (sel) => (sel === '.guide-tab' ? [tab] : []),
        querySelector: () => null,
        createElement: () => element(),
        createTextNode: (t) => ({ textContent: t }),
        body: Object.assign(element(), { dataset: {} }),
    };
    const window = { __BAN_GUIDE: { sections: [] }, location: { search: '', hash: '', origin: '' }, addEventListener() {} };
    if (ban) window.BAN = f.BAN;
    const fetch = () => new Promise(() => {});
    class IntersectionObserver { observe() {} }
    new Function('window', 'document', 'fetch', 'IntersectionObserver', guideSource)(window, document, fetch, IntersectionObserver);
    const type = (value) => { filter.value = value; filter.dispatchEvent({ type: 'input', isTrusted: true }); };
    return { type, filter, tab, calls: f.calls };
}

test('the guide filter counts once, and not for the event a tab switch dispatches', () => {
    const g = loadGuide();
    g.filter.value = 'store';
    g.tab.listeners.click[0]();
    expect(g.filter.value).toBe('');
    expect(g.calls).toEqual([]);
    g.type('');
    expect(g.calls).toEqual([]);
    g.type('sto');
    g.type('store');
    g.type('');
    g.type('price');
    expect(g.calls).toEqual([['ui.guide', 'search_used', undefined]]);
});

test('with no BAN the guide filter still filters', () => {
    const g = loadGuide(false);
    expect(() => g.type('store')).not.toThrow();
});

// copySnippet is a page global: run it with a clipboard that takes the text, and one that refuses.
function loadCopy(clipboard, ban = true) {
    const f = fakeBAN();
    const window = ban ? { BAN: f.BAN } : {};
    const document = { createElement: () => Object.assign(element(), { select() {} }), body: { appendChild() {}, removeChild() {} }, execCommand: () => false, getElementById: () => null };
    const navigator = { clipboard };
    const fn = new Function('window', 'document', 'navigator', 'IntersectionObserver', guideSource.replace(/^\(function\(\) \{[\s\S]*?\n\}\)\(\);\n/m, '') + '\nreturn copySnippet;');
    return { copy: fn(window, document, navigator, undefined), calls: f.calls };
}

test('a copy counts whether or not the clipboard took it', async () => {
    const ok = loadCopy({ writeText: () => Promise.resolve() });
    ok.copy({}, 'text');
    const refused = loadCopy({ writeText: () => Promise.reject(new Error('denied')) });
    refused.copy({}, 'text');
    const none = loadCopy(undefined);
    none.copy({}, 'text');
    for (const c of [ok, refused, none]) expect(c.calls).toEqual([['ui.guide', 'copy', undefined]]);
    expect(() => loadCopy(undefined, false).copy({}, 'text')).not.toThrow();
});

// js/api-plans.js over a form of stand-ins, as the page renders it.
const plansSource = read('js/api-plans.js');
const PLANS = {
    packages: [
        { key: 'starter', name: 'Starter', monthly: 19900, explicit: true, includedStores: 1 },
        { key: 'all_stores', name: 'All stores', monthly: 49900, explicit: false, includedStores: 0 },
        { key: 'history', name: 'History', monthly: 9900, explicit: false, includedStores: 0 },
    ],
    addons: {}, intervals: [{ key: 'monthly', count: 1 }], includedGames: 0,
};
function loadPlans(ban = true) {
    const f = fakeBAN();
    const radios = PLANS.packages.map((p) => ({ name: 'package', value: p.key, checked: p.key === 'starter' }));
    const cta = Object.assign(element(), { getAttribute: (k) => (k === 'data-package' ? 'all_stores' : 'x') });
    const card = element();
    card.querySelector = () => radios[2];
    const form = element();
    form.querySelectorAll = (sel) => {
        if (sel === '.api-cta') return [cta];
        if (sel === '.api-card') return [card];
        if (sel === 'input[name="package"]') return radios;
        return [];
    };
    form.querySelector = (sel) => {
        const m = sel.match(/input\[name="package"\]\[value="(\w+)"\]/);
        return m ? radios.find((r) => r.value === m[1]) || null : null;
    };
    const byId = { 'api-config-form': form, 'api-total': element(), 'api-total-period': element(), 'api-total-package': element() };
    const document = { getElementById: (id) => byId[id] || null };
    const window = { __BAN_API_PLANS: PLANS, location: { search: '' } };
    if (ban) window.BAN = f.BAN;
    new Function('window', 'document', plansSource)(window, document);
    const change = (name, value = 'x') => form.listeners.change.forEach((fn) => fn({ target: { name, value, checked: true } }));
    const clickCard = () => card.listeners.click.forEach((fn) => fn.call(card));
    const clickCta = () => cta.listeners.click.forEach((fn) => fn.call(cta, { stopPropagation() {} }));
    return { change, clickCard, clickCta, radios, calls: f.calls };
}

test('a package button counts the package it names', () => {
    const p = loadPlans();
    p.clickCta();
    expect(p.calls).toEqual([['ui.apiplans.choose', 'all_stores', undefined]]);
    expect(p.radios[1].checked).toBe(true);
});

test('a card click counts only when it changes the choice', () => {
    const p = loadPlans();
    p.clickCard();
    p.clickCard();
    expect(p.calls).toEqual([['ui.apiplans.choose', 'history', undefined]]);
});

test('a change to an add-on, the stores, the games and the interval are four values', () => {
    const p = loadPlans();
    ['addons', 'stores', 'games', 'interval'].forEach(p.change);
    expect(p.calls).toEqual([['ui.apiplans', 'addon', undefined], ['ui.apiplans', 'stores', undefined], ['ui.apiplans', 'games', undefined], ['ui.apiplans', 'interval', undefined]]);
});

test('a change to a field the form does not name counts nothing', () => {
    const p = loadPlans();
    ['package', 'return_to', 'constructor', 'toString', '__proto__'].forEach(p.change);
    expect(p.calls).toEqual([]);
});

test('a package picked on its radio or by keyboard counts from the change, closed to the packages', () => {
    const p = loadPlans();
    p.change('package', 'all_data');
    p.change('package', 'constructor');
    p.change('package', '__proto__');
    expect(p.calls).toEqual([['ui.apiplans.choose', 'all_data', undefined]]);
});

test('with no BAN the plans form still picks', () => {
    const p = loadPlans(false);
    expect(() => { p.clickCta(); p.change('stores'); }).not.toThrow();
    expect(p.radios[1].checked).toBe(true);
});

test('the script counts only registered package and field values', () => {
    const chosen = plansSource.match(/var CHOSEN = \{([^}]*)\}/)[1].match(/\w+(?=:)/g);
    expect(chosen).toEqual(registry['ui.apiplans.choose'].enum);
    const fields = [...plansSource.match(/var FIELDS = \{([^}]*)\}/)[1].matchAll(/: '(\w+)'/g)].map((m) => m[1]);
    for (const v of fields) expect(registry['ui.apiplans'].enum).toContain(v);
});
