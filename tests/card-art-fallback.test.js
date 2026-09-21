import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/card-art-fallback.js', import.meta.url), 'utf8');
const uploadTemplate = readFileSync(new URL('../templates/upload.html', import.meta.url), 'utf8');

function loadFallback() {
    let onError;
    class FakeImage {
        constructor() {
            this.dataset = {};
            this.src = '';
        }

        matches(selector) {
            return selector.includes('.card-art');
        }

        closest() {
            return null;
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
    return {FakeImage, onError, setCardArtSource: window.setCardArtSource, cardArtPlaceholder: window.cardArtPlaceholder};
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

test('unrelated images do not receive the card-back fallback', () => {
    const {FakeImage, onError} = loadFallback();
    const image = new FakeImage();
    image.matches = () => false;
    image.src = 'broken.jpg';

    onError({target: image});

    expect(image.src).toBe('broken.jpg');
    expect(image.dataset.cardArtFallback).toBeUndefined();
});

test('hover previews show only for real card art', () => {
    const {FakeImage, setCardArtSource, cardArtPlaceholder} = loadFallback();
    const image = new FakeImage();
    const classes = new Set();
    image.closest = selector => selector === '.hoverWrap' ? {
        classList: {toggle: (name, enabled) => enabled ? classes.add(name) : classes.delete(name)},
    } : null;

    setCardArtSource(image, 'card.jpg');
    expect(classes.has('is-visible')).toBe(true);

    setCardArtSource(image, cardArtPlaceholder);
    expect(classes.has('is-visible')).toBe(false);
});

test('upload printing picker resets reused row art', () => {
    expect(uploadTemplate).toContain('if (img) window.setCardArtSource(img, meta.image);');
});
