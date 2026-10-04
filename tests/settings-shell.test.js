import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

// Load the module with an inert window; bind() is DOM glue and is not run here.
function loadShell() {
    const src = readFileSync(join(import.meta.dir, '..', 'js', 'settings-shell.js'), 'utf8');
    const win = {};
    const doc = { addEventListener: () => {}, getElementById: () => null };
    new Function('window', 'document', src)(win, doc);
    return win.SettingsShell;
}
const Shell = loadShell();

const entries = [
    { tab: 'search', title: 'Stores', text: 'stores check stores you want to hide card kingdom tcgplayer' },
    { tab: 'search', title: 'Result Sorting', text: 'result sorting chronological best retail best buylist' },
    { tab: 'upload', title: 'Optimizer Filters', text: 'optimizer filters hide low spread offers' },
    { tab: 'arbit', title: 'Vendors', text: 'vendors checked vendors will be hidden card kingdom' },
];

test('an empty query matches every section', () => {
    expect(Shell.filterEntries(entries, '')).toHaveLength(4);
    expect(Shell.filterEntries(entries, '   ')).toHaveLength(4);
});

test('a query matches title, description and labels, case-insensitively', () => {
    expect(Shell.filterEntries(entries, 'SORT').map(e => e.title)).toEqual(['Result Sorting']);
    expect(Shell.filterEntries(entries, 'hide').map(e => e.title)).toEqual(['Stores', 'Optimizer Filters']);
    expect(Shell.filterEntries(entries, 'card kingdom').map(e => e.tab)).toEqual(['search', 'arbit']);
    expect(Shell.filterEntries(entries, 'zzz')).toEqual([]);
});

test('countByTab counts matches per tab', () => {
    expect(Shell.countByTab(Shell.filterEntries(entries, 'hid'))).toEqual({ search: 1, upload: 1, arbit: 1 });
    expect(Shell.countByTab([])).toEqual({});
});

test('pickTab takes the first hint the body has, else the first tab', () => {
    const tabs = ['search', 'upload', 'offline'];
    expect(Shell.pickTab(tabs, ['offline', 'search'])).toBe('offline');
    expect(Shell.pickTab(tabs, ['news', 'upload'])).toBe('upload');
    expect(Shell.pickTab(tabs, [null, ''])).toBe('search');
    expect(Shell.pickTab([], ['search'])).toBeNull();
});

test('tabFromQuery reads ?settings=<tab>; 1 means the page decides', () => {
    expect(Shell.tabFromQuery('?settings=offline')).toBe('offline');
    expect(Shell.tabFromQuery('?q=x&settings=1')).toBeNull();
    expect(Shell.tabFromQuery('?q=x')).toBeNull();
});

test('markup wraps every hit in <mark> and escapes the rest', () => {
    expect(Shell.markup('Best Retail', 'ret')).toBe('Best <mark>Ret</mark>ail');
    expect(Shell.markup('a <b> a', 'a')).toBe('<mark>a</mark> &lt;b&gt; <mark>a</mark>');
    expect(Shell.markup('plain', '')).toBe('plain');
    expect(Shell.markup('x & y', 'q')).toBe('x &amp; y');
});

test('markup marks only the match in a store label text node', () => {
    // The text node after a grid label's checkbox keeps its leading space
    expect(Shell.markup(' Card Kingdom (Sealed)', 'kingdom')).toBe(' Card <mark>Kingdom</mark> (Sealed)');
    expect(Shell.markup('Hide offers under $ ', 'under')).toBe('Hide offers <mark>under</mark> $ ');
});

test('filterEntries keeps a section matched only inside a word', () => {
    const got = Shell.filterEntries(entries, 'ingdo');
    expect(got.map(e => e.title)).toEqual(['Stores', 'Vendors']);
    expect(got[0].text).toContain('card kingdom');
});
