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
