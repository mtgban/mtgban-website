import { test, expect } from 'bun:test';
import { read } from './metrics-helpers.js';

// In the card view the name link is stretched over the image, so the link
// carries the tooltip naming the card: one on the image would never show.
test('an optimizer card is named by its link, not its covered image', () => {
    const html = read('templates/upload.html');
    const links = html.match(/<div class="opt-name-text"><a [^>]*>/g);
    expect(links.length).toBe(2);
    for (const link of links) {
        expect(link).toContain('title="{{$card.Name}} [{{$card.Title}}]"');
    }
    const art = html.match(/<div class="foil-wrap opt-art[^]*?<img [^>]*>/g);
    expect(art.length).toBe(2);
    for (const img of art) {
        expect(img).not.toMatch(/<img [^>]*title=/);
    }
});

// startView runs upload-view.js over one store and answers whether it opened
// on cards.
function startView(saved, phone) {
    const classes = (set = new Set()) => ({
        toggle: (name, on) => { if (on) set.add(name); else set.delete(name); },
        contains: (name) => set.has(name),
    });
    const button = () => ({ classList: classes(), setAttribute() {}, addEventListener() {} });
    const store = { classList: classes(), querySelector: button };
    const panel = {
        querySelectorAll: () => [store],
        querySelector: () => (store.classList.contains('opt-cards') ? null : store),
        addEventListener() {},
    };
    const document = { getElementById: () => panel, querySelector: button };
    const window = { matchMedia: (query) => ({ matches: query === '(max-width: 560px)' && phone }) };
    new Function('document', 'window', 'localStorage', read('js/upload-view.js'))(document, window, { getItem: () => saved });
    return store.classList.contains('opt-cards');
}

test.each([
    [null, true, true],
    [null, false, false],
    ['rows', true, false],
    ['cards', true, true],
    ['cards', false, true],
])('saved %p on a phone %p opens on cards: %p', (saved, phone, want) => {
    expect(startView(saved, phone)).toBe(want);
});
