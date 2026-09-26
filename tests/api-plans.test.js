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
        {key: 'starter', monthly: 20000, explicit: true, includedStores: 1},
        {key: 'all_stores', monthly: 50000, explicit: false, includedStores: 0},
        {key: 'all_data', monthly: 80000, explicit: false, includedStores: 0},
    ],
    addons: {extra_store: 15000, extra_game: 15000},
    intervals: [{key: 'monthly', count: 1}, {key: 'quarterly', count: 3}],
    includedGames: 1,
};

test('starter with one store and magic is the base amount', () => {
    const {computeTotal} = load();
    expect(computeTotal(data, {package: 'starter', interval: 'monthly', stores: 1, games: 1}).cents).toBe(20000);
});

test('extra stores and games add on, quarterly multiplies', () => {
    const {computeTotal} = load();
    expect(computeTotal(data, {package: 'starter', interval: 'monthly', stores: 3, games: 2}).cents).toBe(20000 + 2 * 15000 + 15000);
    expect(computeTotal(data, {package: 'all_data', interval: 'quarterly', stores: 5, games: 1}).cents).toBe(3 * 80000);
});

test('non-explicit packages ignore stores', () => {
    const {computeTotal} = load();
    expect(computeTotal(data, {package: 'all_stores', interval: 'monthly', stores: 4, games: 1}).cents).toBe(50000);
});

test('formatUSD matches the Go helper', () => {
    const {formatUSD} = load();
    expect(formatUSD(20000)).toBe('$200');
    expect(formatUSD(150000)).toBe('$1,500');
    expect(formatUSD(1250)).toBe('$12.50');
});

// Minimal fake DOM so the configurator's non-pure wiring code runs under
// `new Function`. Only the pieces api-plans.js actually touches are modeled.
function fakeInput(name, value, checked) {
    return {name: name, value: value, checked: !!checked, disabled: false};
}

// A radio group the way the browser keeps one: checking a member clears the rest.
function fakeRadioGroup(name, values) {
    const group = values.map(function (value, index) {
        const input = {name: name, value: value, disabled: false, _checked: index === 0};
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

function buildFakeForm(storesChecked, gameChecked, search, storeKeys) {
    storesChecked = storesChecked || [true, true];
    if (gameChecked === undefined) gameChecked = true;
    const packages = fakeRadioGroup('package', ['starter', 'all_data']);
    const ctas = [fakeCta('starter', 'Choose Starter'), fakeCta('all_data', 'Choose All Access')];
    const cards = [fakeCard(packages[0]), fakeCard(packages[1])];
    const stores = [fakeInput('stores', 'cardkingdom', storesChecked[0]), fakeInput('stores', 'starcitygames', storesChecked[1])];
    const games = [fakeInput('games', 'magic', gameChecked)];
    const intervals = [fakeInput('interval', 'monthly', true)];
    const all = packages.concat(stores, games, intervals);
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
            return [];
        },
    };

    const elements = {
        'api-config-form': form,
        'api-stores': storesFieldset,
        'api-total-package': {textContent: ''},
        'api-total': {textContent: ''},
        'api-total-period': {textContent: ''},
    };

    const document = {getElementById: function (id) { return elements[id]; }};
    const window = {
        __BAN_API_PLANS: {
            packages: [
                {key: 'starter', name: 'Starter', monthly: 20000, explicit: true, includedStores: 1},
                {key: 'all_data', name: 'All Access', monthly: 80000, explicit: false, includedStores: 0},
            ],
            addons: {extra_store: 15000, extra_game: 15000},
            intervals: [{key: 'monthly', count: 1}],
            includedGames: 1,
            storeKeys: storeKeys,
        },
        location: {search: search || ''},
    };

    // Running the source also fires the initial update() synchronously.
    new Function('window', 'document', source)(window, document);
    return {
        packages: packages,
        stores: stores,
        storesFieldset: storesFieldset,
        submitButton: submitButton,
        ctas: ctas,
        cards: cards,
        totalPackage: elements['api-total-package'],
        triggerChange: function () { changeHandler(); },
    };
}

test('switching off an explicit package disables the stale store checkboxes', () => {
    const {packages, stores, storesFieldset, triggerChange} = buildFakeForm();
    expect(storesFieldset.hidden).toBe(false);
    expect(stores[0].disabled).toBe(false);

    packages[0].checked = false;
    packages[1].checked = true;
    triggerChange();

    expect(storesFieldset.hidden).toBe(true);
    expect(stores[0].disabled).toBe(true);
    expect(stores[1].disabled).toBe(true);
});

test('submit is disabled on an explicit package until enough stores are checked', () => {
    const zeroChecked = buildFakeForm([false, false]);
    expect(zeroChecked.submitButton.disabled).toBe(true);

    const oneChecked = buildFakeForm([true, false]);
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

    ctas[1].click();

    expect(packages[1].checked).toBe(true);
    expect(packages[0].checked).toBe(false);
});

test('the selected CTA reads its data-selected label and the others their data-label', () => {
    const {ctas} = buildFakeForm();
    expect(ctas[0].textContent).toBe('Selected');
    expect(ctas[1].textContent).toBe('Choose All Access');

    ctas[1].click();

    expect(ctas[0].textContent).toBe('Choose Starter');
    expect(ctas[1].textContent).toBe('Selected');
});

test('the total row names the selected package', () => {
    const {ctas, totalPackage} = buildFakeForm();
    expect(totalPackage.textContent).toBe('Starter');

    ctas[1].click();

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
