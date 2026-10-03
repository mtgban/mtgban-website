import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/alerts.js', import.meta.url), 'utf8');

// Loads js/alerts.js the way tests/api-plans.test.js loads its script: a
// stub window/document so the IIFE's top-level code (which only registers
// a DOMContentLoaded listener, never fires it here) runs without a real DOM.
function load() {
    const window = {};
    const document = {
        addEventListener: function () {},
        getElementById: function () { return null; },
    };
    new Function('window', 'document', source)(window, document);
    return window.alertsChannels;
}

test('channelState labels verified, pending and disabled rows', () => {
    const { channelState } = load();
    expect(channelState({ state: 'verified' })).toBe('Verified');
    expect(channelState({ state: 'pending' })).toBe('Confirm pending');
    expect(channelState({ state: 'disabled', reason: 'bounced' })).toBe('Disabled: bounced');
    expect(channelState({ state: 'disabled', reason: 'complained' })).toBe('Disabled: marked as spam');
    expect(channelState({ state: 'disabled', reason: 'unsubscribed' })).toBe('Disabled: unsubscribed');
});

test('allowedChannels trims, lowercases and drops unknown names', () => {
    const { allowedChannels } = load();
    expect(allowedChannels('discord, Email')).toEqual(['discord', 'email']);
    expect(allowedChannels('discord,discord')).toEqual(['discord']);
    expect(allowedChannels('sms,email,,pager')).toEqual(['email']);
    expect(allowedChannels('')).toEqual([]);
    expect(allowedChannels(null)).toEqual([]);
});

test('channelButtons: a user row offers resend or change plus remove', () => {
    const { channelButtons } = load();
    expect(channelButtons({ source: 'user', state: 'pending' })).toEqual(['resend', 'remove']);
    expect(channelButtons({ source: 'user', state: 'verified' })).toEqual(['change', 'remove']);
});

test('channelButtons: a user row disabled as unsubscribed only offers remove', () => {
    const { channelButtons } = load();
    expect(channelButtons({ source: 'user', state: 'disabled', reason: 'unsubscribed' })).toEqual(['remove']);
});

test('channelButtons: a user row disabled by a bounce or complaint still offers resend', () => {
    const { channelButtons } = load();
    expect(channelButtons({ source: 'user', state: 'disabled', reason: 'bounced' })).toEqual(['resend', 'remove']);
    expect(channelButtons({ source: 'user', state: 'disabled', reason: 'complained' })).toEqual(['resend', 'remove']);
});

test('channelButtons: a disabled patreon row offers enable, a verified one offers nothing', () => {
    const { channelButtons } = load();
    expect(channelButtons({ source: 'patreon', state: 'disabled', reason: 'unsubscribed' })).toEqual(['enable']);
    expect(channelButtons({ source: 'patreon', state: 'disabled', reason: 'bounced' })).toEqual(['enable']);
    expect(channelButtons({ source: 'patreon', state: 'verified' })).toEqual([]);
});

test('channelButtons: a patreon row marked as spam is never re-enabled', () => {
    const { channelButtons } = load();
    expect(channelButtons({ source: 'patreon', state: 'disabled', reason: 'complained' })).toEqual([]);
});

const patreonRow = (state, reason) => ({ kind: 'email', source: 'patreon', address: 'ann@patreon.example', state, reason: reason || '' });
const userRow = (state, reason) => ({ kind: 'email', source: 'user', address: 'ann@work.example', state, reason: reason || '' });
const discordRow = { kind: 'discord', source: 'patreon', address: 'd1', state: 'verified' };

// marks is each line's source and whether it receives alert mail.
const marks = (section) => section.lines.map((l) => [l.row.source, l.receives]);

test('emailLines: a verified patreon row with no user row receives mail and offers Add', () => {
    const { emailLines, channelButtons } = load();
    const section = emailLines([discordRow, patreonRow('verified')]);
    expect(marks(section)).toEqual([['patreon', true]]);
    expect(section.add).toBe(true);
    expect(channelButtons(section.lines[0].row)).toEqual([]);
});

test('emailLines: while the user row is pending, the patreon line is the one receiving', () => {
    const { emailLines } = load();
    const section = emailLines([userRow('pending'), patreonRow('verified')]);
    expect(marks(section)).toEqual([['patreon', true], ['user', false]]);
    expect(section.add).toBe(false);
});

test('emailLines: a verified user row wins over the patreon one', () => {
    const { emailLines } = load();
    expect(marks(emailLines([patreonRow('verified'), userRow('verified')]))).toEqual([['patreon', false], ['user', true]]);
});

test('emailLines: disabled rows receive nothing; a disabled user row still holds the Add slot', () => {
    const { emailLines } = load();
    const section = emailLines([patreonRow('disabled', 'unsubscribed'), userRow('disabled', 'bounced')]);
    expect(marks(section)).toEqual([['patreon', false], ['user', false]]);
    expect(section.add).toBe(false);
    expect(marks(emailLines([patreonRow('disabled', 'unsubscribed'), userRow('verified')]))).toEqual([['patreon', false], ['user', true]]);
});

test('emailLines: no email rows means only the Add form', () => {
    const { emailLines } = load();
    expect(emailLines([discordRow])).toEqual({ lines: [], add: true });
    expect(emailLines(null)).toEqual({ lines: [], add: true });
});

test('deliveryOptions: creating defaults into the allowed set', () => {
    const { deliveryOptions } = load();
    expect(deliveryOptions(['discord'], 'email', false)).toEqual({
        options: [{ value: 'discord', label: 'Discord', extra: false }],
        selected: 'discord',
        hidden: true,
    });
    const both = deliveryOptions(['discord', 'email'], 'bogus', false);
    expect(both.selected).toBe('discord');
    expect(both.hidden).toBe(false);
});

test('deliveryOptions: editing never changes the stored delivery away from a lapsed tier', () => {
    const { deliveryOptions } = load();
    const lapsed = deliveryOptions(['discord'], 'email', true);
    expect(lapsed.selected).toBe('email');
    expect(lapsed.hidden).toBe(false);
    expect(lapsed.options).toEqual([
        { value: 'discord', label: 'Discord', extra: false },
        { value: 'email', label: 'Email (not in your tier)', extra: true },
    ]);
});

test('deliveryOptions: editing with the stored channel still allowed adds no extra option', () => {
    const { deliveryOptions } = load();
    const ok = deliveryOptions(['discord', 'email'], 'email', true);
    expect(ok.selected).toBe('email');
    expect(ok.hidden).toBe(false);
    expect(ok.options).toEqual([
        { value: 'discord', label: 'Discord', extra: false },
        { value: 'email', label: 'Email', extra: false },
    ]);
});

test('deliveryOptions: hidden only when exactly one allowed channel matches the selection', () => {
    const { deliveryOptions } = load();
    expect(deliveryOptions(['discord'], 'discord', true).hidden).toBe(true);
    expect(deliveryOptions(['discord'], 'email', true).hidden).toBe(false);
});
