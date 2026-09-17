import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/card-art-fallback.js', import.meta.url), 'utf8');

function loadFallback() {
    let onError;
    class FakeImage {
        constructor() {
            this.dataset = {};
            this.src = '';
        }

        matches() {
            return true;
        }
    }
    const window = {};
    const document = {
        body: {getAttribute: () => 'pokemon'},
        addEventListener: (type, handler) => {
            if (type === 'error') onError = handler;
        },
    };
    new Function('window', 'document', 'HTMLImageElement', source)(window, document, FakeImage);
    return {FakeImage, onError, setCardArtSource: window.setCardArtSource};
}

test('reused card art can fall back again after its source changes', () => {
    const {FakeImage, onError, setCardArtSource} = loadFallback();
    const image = new FakeImage();

    setCardArtSource(image, 'broken-a.jpg');
    onError({target: image});
    expect(image.src).toBe('/img/backs/pokemon.webp');

    setCardArtSource(image, 'broken-b.jpg');
    expect(image.dataset.cardArtFallback).toBeUndefined();
    onError({target: image});
    expect(image.src).toBe('/img/backs/pokemon.webp');
});
