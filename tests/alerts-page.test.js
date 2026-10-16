import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/alerts.js', import.meta.url), 'utf8');

// Loads js/alerts.js as tests/alerts-channels.test.js does: a stub window
// and document, so the IIFE registers its listener and exports its helpers.
function load() {
    const window = {};
    const document = {
        addEventListener: function () {},
        getElementById: function () { return null; },
    };
    new Function('window', 'document', source)(window, document);
    return window.alertsChannels;
}

test('deleteAllPrompt names the count and warns it is final', () => {
    const h = load();
    expect(h.deleteAllPrompt(3)).toBe('Delete all 3 alerts? This cannot be undone.');
    expect(h.deleteAllPrompt(1)).toBe('Delete your only alert? This cannot be undone.');
});

test('existingForCard lists the card\'s alerts in create mode only', () => {
    const h = load();
    const existing = [
        { id: 1, card_id: 'card-1' },
        { id: 2, card_id: 'card-2' },
        { id: 3, card_id: 'card-1' },
    ];
    expect(h.existingForCard(existing, 'card-1', null).map(a => a.id)).toEqual([1, 3]);
    expect(h.existingForCard(existing, 'card-3', null)).toEqual([]);
    // Edit mode shows the form alone; the box above it stays hidden.
    expect(h.existingForCard(existing, 'card-1', '1')).toEqual([]);
    expect(h.existingForCard(null, 'card-1', null)).toEqual([]);
});
