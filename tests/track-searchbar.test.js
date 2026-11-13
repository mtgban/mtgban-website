import { test, expect } from 'bun:test';
import { loadMetrics, el, dispatch } from './metrics-loader.js';

// The search forms count on submit only; what a reader types is never read.
const NO_LOAD = { cfg: { on: true, page: '', build: 'abc' } };

function sentBy(act) {
    const page = loadMetrics(NO_LOAD);
    act(page);
    page.hide();
    return page.sent().map((e) => [e.n, e.v || '', e.c]);
}

test('a click into a tracked search box counts nothing', () => {
    const form = el({ 'data-track': 'ui.searchbar.submit', 'data-track-value': 'nav' }, null, 'form');
    const box = el({}, form, 'input');
    expect(sentBy((p) => dispatch(p, 'click', box))).toEqual([]);
});

test('the submit counts once, as the bar it came from', () => {
    const form = el({ 'data-track': 'ui.searchbar.submit', 'data-track-value': 'results' }, null, 'form');
    const box = el({}, form, 'input');
    expect(sentBy((p) => { dispatch(p, 'click', box); dispatch(p, 'submit', form); }))
        .toEqual([['ui.searchbar.submit', 'results', 1]]);
});

test('a submit button outside its form counts only the submit', () => {
    const form = el({ 'data-track': 'ui.searchbar.submit', 'data-track-value': 'home' }, null, 'form');
    const button = el({ form: 'searchform' }, null, 'button');
    expect(sentBy((p) => { dispatch(p, 'click', button); dispatch(p, 'submit', form); }))
        .toEqual([['ui.searchbar.submit', 'home', 1]]);
});

// A picked name is submitted by clicking a hidden button autocomplete.js appends to the form.
test('a picked name counts one submit, not a click on the form', () => {
    const form = el({ 'data-track': 'ui.searchbar.submit', 'data-track-value': 'nav' }, null, 'form');
    const fake = el({}, form, 'button');
    expect(sentBy((p) => { dispatch(p, 'click', fake); dispatch(p, 'submit', form); }))
        .toEqual([['ui.searchbar.submit', 'nav', 1]]);
});

test('a tracked button beside the form counts as itself', () => {
    const clear = el({ 'data-track': 'ui.scope.clear' }, null, 'button');
    expect(sentBy((p) => dispatch(p, 'click', clear))).toEqual([['ui.scope.clear', '', 1]]);
});
