import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/api-plans.js', import.meta.url), 'utf8');

function load() {
    const window = {};
    new Function('window', 'document', source)(window, undefined);
    return window.BanApiPlans;
}

// Mirrors products.json on the api-products-page branch.
const data = {
    packages: [
        {key: 'starter', monthly: 19900, explicit: true, includedStores: 1},
        {key: 'all_stores', monthly: 49900, explicit: false, includedStores: 0},
        {key: 'all_data', monthly: 79900, explicit: false, includedStores: 0},
    ],
    addons: {extra_store: 5000, extra_game: 10000},
    addons_first: {extra_store: 15000, extra_game: 25000},
    intervals: [{key: 'monthly', count: 1}, {key: 'quarterly', count: 3}],
    includedGames: 1,
};

test('starter with one store and magic is the base amount', () => {
    const {computeTotal} = load();
    expect(computeTotal(data, {package: 'starter', interval: 'monthly', stores: 1, games: 1}).cents).toBe(19900);
});

test('extra stores and games step down, quarterly multiplies', () => {
    const {computeTotal} = load();
    expect(computeTotal(data, {package: 'starter', interval: 'monthly', stores: 3, games: 2}).cents).toBe(19900 + 15000 + 5000 + 25000);
    expect(computeTotal(data, {package: 'all_data', interval: 'quarterly', stores: 5, games: 3}).cents).toBe(344700);
    expect(computeTotal(data, {package: 'all_data', interval: 'quarterly', stores: 5, games: 1}).cents).toBe(3 * 79900);
});

test('the first extra unit costs more than the ones after it', () => {
    const {computeTotal} = load();
    expect(computeTotal(data, {package: 'starter', interval: 'monthly', stores: 2, games: 1}).cents).toBe(34900);
    expect(computeTotal(data, {package: 'starter', interval: 'monthly', stores: 4, games: 1}).cents).toBe(44900);
    expect(computeTotal(data, {package: 'starter', interval: 'monthly', stores: 1, games: 2}).cents).toBe(44900);
    expect(computeTotal(data, {package: 'starter', interval: 'monthly', stores: 1, games: 3}).cents).toBe(54900);
});

test('a flat add-on (no addons_first) still multiplies', () => {
    const {computeTotal} = load();
    const flat = Object.assign({}, data, {addons_first: undefined});
    expect(computeTotal(flat, {package: 'starter', interval: 'monthly', stores: 3, games: 1}).cents).toBe(19900 + 2 * 5000);
});

test('non-explicit packages ignore stores', () => {
    const {computeTotal} = load();
    expect(computeTotal(data, {package: 'all_stores', interval: 'monthly', stores: 4, games: 1}).cents).toBe(49900);
});

test('formatUSD matches the Go helper', () => {
    const {formatUSD} = load();
    expect(formatUSD(20000)).toBe('$200');
    expect(formatUSD(150000)).toBe('$1,500');
    expect(formatUSD(1250)).toBe('$12.50');
});

test('a checked mode add-on adds its monthly once; an unlisted key adds nothing', () => {
    const {computeTotal} = load();
    const withNews = Object.assign({}, data, {addons: Object.assign({}, data.addons, {newspaper: 100}), mode_addons: ['newspaper'], addon_applies: {newspaper: ['all_data']}});
    expect(computeTotal(withNews, {package: 'all_data', interval: 'monthly', stores: 0, games: 1, modeAddons: ['newspaper']}).cents).toBe(80000);
    expect(computeTotal(withNews, {package: 'all_data', interval: 'quarterly', stores: 0, games: 1, modeAddons: ['newspaper']}).cents).toBe(3 * 80000);
    expect(computeTotal(withNews, {package: 'all_data', interval: 'monthly', stores: 0, games: 1, modeAddons: ['extra_game']}).cents).toBe(79900);
    expect(computeTotal(data, {package: 'all_data', interval: 'monthly', stores: 0, games: 1, modeAddons: ['newspaper']}).cents).toBe(79900);
    expect(computeTotal(withNews, {package: 'all_data', interval: 'monthly', stores: 0, games: 1}).cents).toBe(79900);
});

test('computeTotal counts a mode add-on once however many boxes carry it', () => {
    const {computeTotal} = load();
    const withNews = Object.assign({}, data, {addons: Object.assign({}, data.addons, {newspaper: 20000}), mode_addons: ['newspaper'], addon_applies: {newspaper: ['starter', 'all_stores']}});
    expect(computeTotal(withNews, {package: 'starter', interval: 'monthly', stores: 1, games: 1, modeAddons: ['newspaper', 'newspaper']}).cents).toBe(39900);
});

// Minimal fake DOM so the configurator's non-pure wiring code runs under
// `new Function`. Only the pieces api-plans.js actually touches are modeled.
function fakeInput(name, value, checked) {
    return {name: name, value: value, checked: !!checked, disabled: false, dataset: {}};
}

// A classList kept in a Set, with toggle's force argument.
function fakeClassList() {
    const names = new Set();
    return {
        add: function (n) { names.add(n); },
        remove: function (n) { names.delete(n); },
        contains: function (n) { return names.has(n); },
        toggle: function (n, force) {
            const on = force === undefined ? !names.has(n) : !!force;
            if (on) names.add(n); else names.delete(n);
            return on;
        },
    };
}

// Puts an input inside a label row that closest('.api-choice') returns.
function inRow(input, dataset) {
    input.row = {dataset: dataset, classList: fakeClassList()};
    input.closest = function (sel) { return sel === '.api-choice' ? this.row : null; };
    return input;
}

function isOff(input) { return input.row.classList.contains('api-choice-off'); }

// A radio group the way the browser keeps one: checking a member clears the rest.
function fakeRadioGroup(name, values, checkedIndex) {
    checkedIndex = checkedIndex || 0;
    const group = values.map(function (value, index) {
        const input = {name: name, value: value, disabled: false, _checked: index === checkedIndex};
        Object.defineProperty(input, 'checked', {
            get: function () { return this._checked; },
            set: function (on) {
                this._checked = !!on;
                if (on) {
                    group.forEach(function (other) { if (other !== input) other._checked = false; });
                }
            },
        });
        return input;
    });
    return group;
}

function fakeCta(packageKey, label) {
    return {
        textContent: label,
        attrs: {'data-package': packageKey, 'data-label': label, 'data-selected': 'Selected'},
        getAttribute: function (name) { return this.attrs[name]; },
        addEventListener: function (evt, handler) { this.handler = handler; },
        click: function () { this.handler.call(this, {stopPropagation: function () {}}); },
    };
}

function fakeCard(radio) {
    return {
        querySelector: function (sel) { return sel === 'input[name="package"]' ? radio : null; },
        addEventListener: function (evt, handler) { this.handler = handler; },
        click: function () { this.handler.call(this); },
    };
}

const packageKeys = ['starter', 'all_stores', 'all_data'];

// opts.defaultPackage is the package checked at load (starter otherwise);
// opts.addonApplies, when present, replaces the newspaper's applies list.
function buildFakeForm(storesChecked, gameChecked, search, storeKeys, opts) {
    opts = opts || {};
    storesChecked = storesChecked || [true, true, false];
    if (gameChecked === undefined) gameChecked = true;
    const packages = fakeRadioGroup('package', packageKeys, Math.max(0, packageKeys.indexOf(opts.defaultPackage)));
    const ctas = [fakeCta('starter', 'Choose Starter'), fakeCta('all_stores', 'Choose Base Access'), fakeCta('all_data', 'Choose All Access')];
    const cards = packages.map(fakeCard);
    const stores = [
        inRow(fakeInput('stores', 'cardkingdom', storesChecked[0]), {family: 'cardkingdom', base: 'true'}),
        inRow(fakeInput('stores', 'starcitygames', storesChecked[1]), {family: 'starcitygames', base: 'true'}),
        inRow(fakeInput('stores', 'magiccorner', storesChecked[2]), {family: 'magiccorner', base: 'false'}),
    ];
    const sealed = [
        inRow(fakeInput(undefined, 'on', false), {family: 'tcg_sealed'}),
        inRow(fakeInput(undefined, 'on', false), {family: 'ck_sealed'}),
    ];
    sealed.forEach(function (s) { s.disabled = true; });
    const notes = [{dataset: {when: 'explicit'}, hidden: false}, {dataset: {when: 'preset'}, hidden: true}];
    const games = [fakeInput('games', 'magic', gameChecked)];
    const intervals = [fakeInput('interval', 'monthly', true)];
    const addons = [fakeInput('addons', 'newspaper', false), fakeInput('addons', 'newspaper', false)];
    addons[0].dataset.package = 'starter';
    addons[1].dataset.package = 'all_stores';
    const all = packages.concat(stores, games, intervals, addons);
    const submitButton = {disabled: false};

    let changeHandler = null;
    const form = {
        querySelectorAll: function (sel) {
            if (sel === 'input[name="games"]:checked') return games.filter(function (g) { return g.checked; });
            if (sel === '.api-cta') return ctas;
            if (sel === '.api-card') return cards;
            const m = /^input\[name="(\w+)"\]$/.exec(sel);
            if (m) return all.filter(function (i) { return i.name === m[1]; });
            return [];
        },
        querySelector: function (sel) {
            if (sel === 'button[type="submit"]') return submitButton;
            const picked = /^input\[name="package"\]\[value="(\w+)"\]$/.exec(sel);
            if (picked) return packages.filter(function (i) { return i.value === picked[1]; })[0] || null;
            return null;
        },
        addEventListener: function (evt, handler) { changeHandler = handler; },
    };

    const storesFieldset = {
        hidden: false,
        querySelectorAll: function (sel) {
            if (sel === 'input[name="stores"]') return stores;
            if (sel === '[data-when]') return notes;
            return [];
        },
    };

    const elements = {
        'api-config-form': form,
        'api-stores': storesFieldset,
        'api-stores-sealed': {querySelectorAll: function (sel) { return sel === 'input' ? sealed : []; }},
        'api-total-package': {textContent: ''},
        'api-total': {textContent: ''},
        'api-total-period': {textContent: ''},
    };

    const planData = {
        packages: [
            {key: 'starter', name: 'Starter', monthly: 19900, explicit: true, includedStores: 1, scope: 'explicit', sealed: false},
            {key: 'all_stores', name: 'Base Access', monthly: 49900, explicit: false, includedStores: 0, scope: 'BASE_ACCESS', sealed: false},
            {key: 'all_data', name: 'All Access', monthly: 79900, explicit: false, includedStores: 0, scope: 'ALL_ACCESS', sealed: true},
        ],
        addons: {extra_store: 5000, extra_game: 10000, newspaper: 20000},
        addons_first: {extra_store: 15000, extra_game: 25000},
        mode_addons: ['newspaper'],
        addon_applies: {newspaper: 'addonApplies' in opts ? opts.addonApplies : ['starter', 'all_stores']},
        intervals: [{key: 'monthly', count: 1}],
        includedGames: 1,
        storeKeys: storeKeys,
    };
    const document = {getElementById: function (id) { return elements[id]; }};
    const window = {__BAN_API_PLANS: planData, location: {search: search || ''}};

    // Running the source also fires the initial update() synchronously.
    new Function('window', 'document', source)(window, document);
    return {
        planData: planData,
        packages: packages,
        stores: stores,
        sealed: sealed,
        notes: notes,
        addons: addons,
        storesFieldset: storesFieldset,
        submitButton: submitButton,
        ctas: ctas,
        cards: cards,
        totalPackage: elements['api-total-package'],
        total: elements['api-total'],
        // The browser fires change on the form with the changed input as target.
        change: function (input) { changeHandler({target: input}); },
        pick: function (key) {
            const radio = packages[packageKeys.indexOf(key)];
            radio.checked = true;
            changeHandler({target: radio});
        },
    };
}

test('switching off an explicit package disables the stale store checkboxes', () => {
    const {stores, storesFieldset, pick} = buildFakeForm();
    expect(stores[0].disabled).toBe(false);

    pick('all_data');

    expect(storesFieldset.hidden).toBe(false);
    expect(stores.every(function (s) { return s.disabled; })).toBe(true);
});

test('a preset package disables every store box and lights what it includes', () => {
    const {stores, sealed, pick} = buildFakeForm(null, true, '', undefined, {defaultPackage: 'all_data'});
    expect(stores.every(function (s) { return s.checked && s.disabled && !isOff(s); })).toBe(true);
    expect(sealed.every(function (s) { return s.checked && !isOff(s); })).toBe(true);

    pick('all_stores');

    expect(stores.every(function (s) { return s.disabled; })).toBe(true);
    expect(stores.map(function (s) { return s.checked; })).toEqual([true, true, false]);
    expect(stores.map(isOff)).toEqual([false, false, true]);
    expect(sealed.every(function (s) { return !s.checked && isOff(s); })).toBe(true);
});

test('a scope the script does not know lights nothing', () => {
    const {planData, stores, sealed, pick} = buildFakeForm();
    planData.packages[1].scope = '';

    pick('all_stores');

    expect(stores.every(function (s) { return !s.checked && s.disabled && isOff(s); })).toBe(true);
    expect(sealed.every(function (s) { return !s.checked && isOff(s); })).toBe(true);
});

test('an explicit package restores the user picks and enables the boxes', () => {
    const {stores, sealed, pick} = buildFakeForm([true, false, false]);
    expect(sealed.every(function (s) { return !s.checked && isOff(s); })).toBe(true);

    pick('all_data');
    expect(stores.every(function (s) { return s.checked; })).toBe(true);

    pick('starter');
    expect(stores.map(function (s) { return s.checked; })).toEqual([true, false, false]);
    expect(stores.every(function (s) { return !s.disabled && !isOff(s); })).toBe(true);
});

test('a store picked on an explicit package survives a trip to a preset one', () => {
    const {stores, change, pick} = buildFakeForm([true, false, false]);
    stores[2].checked = true;
    change(stores[2]);

    pick('all_stores');
    pick('starter');

    expect(stores.map(function (s) { return s.checked; })).toEqual([true, false, true]);
});

test('a preset default seeds no picks from its lit boxes', () => {
    const {stores, pick} = buildFakeForm([true, true, true], true, '', undefined, {defaultPackage: 'all_stores'});

    pick('starter');

    // Only the first store, never the lit boxes the preset left checked.
    expect(stores.map(function (s) { return s.checked; })).toEqual([true, false, false]);
    expect(stores.every(function (s) { return !s.disabled; })).toBe(true);
});

test('switching to an explicit package with no picks checks the first store', () => {
    const {stores, submitButton, pick} = buildFakeForm([false, false, false], true, '', undefined, {defaultPackage: 'all_data'});
    expect(submitButton.disabled).toBe(false);

    pick('starter');

    expect(stores.map(function (s) { return s.checked; })).toEqual([true, false, false]);
    expect(submitButton.disabled).toBe(false);
});

test('the legend note follows the package', () => {
    const {notes, pick} = buildFakeForm();
    expect(notes.map(function (n) { return n.hidden; })).toEqual([false, true]);

    pick('all_data');
    expect(notes.map(function (n) { return n.hidden; })).toEqual([true, false]);

    pick('starter');
    expect(notes.map(function (n) { return n.hidden; })).toEqual([false, true]);
});

test('the newspaper boxes stay in step and only the chosen card submits', () => {
    const {addons, total, change} = buildFakeForm();
    expect(addons.map(function (a) { return a.disabled; })).toEqual([false, true]);

    addons[0].checked = true;
    change(addons[0]);

    expect(addons[1].checked).toBe(true);
    expect(addons[1].disabled).toBe(true);
    expect(total.textContent).toBe('$549');
});

test('switching to a package the add-on does not apply to disables its box and drops it from the total', () => {
    const {addons, total, change, pick} = buildFakeForm();
    addons[0].checked = true;
    change(addons[0]);

    pick('all_data');

    expect(addons.every(function (a) { return a.disabled; })).toBe(true);
    expect(addons.every(function (a) { return a.checked; })).toBe(true);
    expect(total.textContent).toBe('$799');

    pick('all_stores');

    expect(addons.map(function (a) { return a.disabled; })).toEqual([true, false]);
    expect(total.textContent).toBe('$699');
});

// A nil applies_to on the backend serializes as null, not an empty array.
test('an add-on with a missing or null applies list stays disabled and adds nothing', () => {
    [null, undefined].forEach(function (applies) {
        const {addons, total, change} = buildFakeForm(null, true, '', undefined, {addonApplies: applies});
        expect(addons.every(function (a) { return a.disabled; })).toBe(true);

        addons[0].checked = true;
        change(addons[0]);

        expect(addons.every(function (a) { return a.disabled; })).toBe(true);
        expect(total.textContent).toBe('$349');
    });
});

test('submit is disabled on an explicit package until enough stores are checked', () => {
    const zeroChecked = buildFakeForm([false, false, false]);
    expect(zeroChecked.submitButton.disabled).toBe(true);

    const oneChecked = buildFakeForm([true, false, false]);
    expect(oneChecked.submitButton.disabled).toBe(false);
});

test('submit is disabled until at least the included games are checked', () => {
    const none = buildFakeForm([true, true], false);
    expect(none.submitButton.disabled).toBe(true);

    const one = buildFakeForm([true, true], true);
    expect(one.submitButton.disabled).toBe(false);
});

test('a CTA click selects its package radio', () => {
    const {packages, ctas} = buildFakeForm();
    expect(packages[0].checked).toBe(true);

    ctas[2].click();

    expect(packages[2].checked).toBe(true);
    expect(packages[0].checked).toBe(false);
});

test('a card click selects its package', () => {
    const {packages, cards, totalPackage} = buildFakeForm();

    cards[1].click();

    expect(packages[1].checked).toBe(true);
    expect(totalPackage.textContent).toBe('Base Access');
});

test('the selected CTA reads its data-selected label and the others their data-label', () => {
    const {ctas} = buildFakeForm();
    expect(ctas[0].textContent).toBe('Selected');
    expect(ctas[2].textContent).toBe('Choose All Access');

    ctas[2].click();

    expect(ctas[0].textContent).toBe('Choose Starter');
    expect(ctas[2].textContent).toBe('Selected');
});

test('the total row names the selected package', () => {
    const {ctas, totalPackage} = buildFakeForm();
    expect(totalPackage.textContent).toBe('Starter');

    ctas[2].click();

    expect(totalPackage.textContent).toBe('All Access');
});

test('a change link prefills the store boxes from comma-joined family keys', () => {
    const joined = buildFakeForm([false, false], true, '?change=1&package=starter&stores=cardkingdom,starcitygames');
    expect(joined.stores[0].checked).toBe(true);
    expect(joined.stores[1].checked).toBe(true);

    const one = buildFakeForm([true, false], true, '?change=1&package=starter&stores=starcitygames');
    expect(one.stores[0].checked).toBe(false);
    expect(one.stores[1].checked).toBe(true);
});

test('store prefill matches family keys whatever their case', () => {
    const {stores} = buildFakeForm([false, false], true, '?change=1&package=starter&stores=CardKingdom,STARCITYGAMES');
    expect(stores[0].checked).toBe(true);
    expect(stores[1].checked).toBe(true);
});

test('store prefill prefers the keys the server resolved from legacy shorthands', () => {
    const {stores} = buildFakeForm([false, true], true, '?change=1&package=starter&stores=CK', ['cardkingdom']);
    expect(stores[0].checked).toBe(true);
    expect(stores[1].checked).toBe(false);
});

test('checking the newspaper box adds its monthly to the total', () => {
    const {addons, total, change} = buildFakeForm();
    expect(total.textContent).toBe('$349');

    addons[0].checked = true;
    change(addons[0]);

    expect(total.textContent).toBe('$549');
});

test('a change link prefills the add-on box', () => {
    const {addons, total} = buildFakeForm([true, true], true, '?change=1&package=starter&addons=newspaper');
    expect(addons.map(function (a) { return a.checked; })).toEqual([true, true]);
    expect(total.textContent).toBe('$549');
});
