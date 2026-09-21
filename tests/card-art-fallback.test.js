import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/card-art-fallback.js', import.meta.url), 'utf8');
const uploadTemplate = readFileSync(new URL('../templates/upload.html', import.meta.url), 'utf8');

function loadFallback(gameAttr) {
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
        body: {getAttribute: () => gameAttr === undefined ? 'pokemon' : gameAttr},
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

// data-game is server-rendered from Config.Game, not user input - but the
// fallback path is still built by string concatenation, so a slug carrying
// meta-characters (a scheme, a traversal sequence, an attribute-breaking
// quote) must never reach img.src. Malformed values fall back to leaving
// the image alone rather than something a browser would resolve as a
// working navigation.
test('a malformed data-game value never reaches img.src', () => {
    const {FakeImage, onError} = loadFallback('javascript:alert(1)');
    const image = new FakeImage();
    image.src = 'broken.jpg';

    onError({target: image});

    expect(image.src).toBe('broken.jpg');
    expect(image.src).not.toContain('javascript:');
});

test('a path-traversal data-game value never reaches img.src', () => {
    const {FakeImage, setCardArtSource} = loadFallback('../../etc/passwd');
    const image = new FakeImage();

    setCardArtSource(image, undefined);

    // No safe target could be determined (no explicit src, no valid game
    // slug), so nothing built from the malformed value ever reaches src -
    // String() covers whether that landed as null or an empty string.
    expect(String(image.src)).not.toContain('..');
});

test('a clean data-game value still builds the normal fallback path', () => {
    const {FakeImage, setCardArtSource} = loadFallback('magic');
    const image = new FakeImage();

    setCardArtSource(image, undefined);

    expect(image.src).toBe('/img/backs/magic.webp');
});
