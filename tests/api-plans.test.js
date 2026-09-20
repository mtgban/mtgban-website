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
