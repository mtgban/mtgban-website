import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const t = (f) => readFileSync(join(import.meta.dir, '..', 'templates', f), 'utf8');
const GEIST = 'https://fonts.googleapis.com/css2?family=Geist:wght@100..900&display=optional';

test('main.css no longer imports the font', () => {
    const css = readFileSync(join(import.meta.dir, '..', 'css', 'main.css'), 'utf8');
    expect(css).not.toContain('@import');
});

test('every base links Geist once with both preconnects', () => {
    for (const f of ['base.html', 'mobile/base-mobile.html', 'base-landing.html']) {
        const html = t(f);
        expect(html.split(GEIST).length - 1).toBe(1);
        expect(html).toContain('rel="preconnect" href="https://fonts.googleapis.com"');
        expect(html).toContain('rel="preconnect" href="https://fonts.gstatic.com" crossorigin');
    }
});

test('bases that load keyrune preconnect to jsdelivr', () => {
    for (const f of ['base.html', 'base-landing.html']) {
        expect(t(f)).toContain('rel="preconnect" href="https://cdn.jsdelivr.net"');
    }
});

test('the phone search page no longer preloads the chart libraries', () => {
    expect(t('mobile/search.html')).not.toContain('rel="preload"');
});

test('nightmode and guide-data load once', () => {
    expect(t('mobile/home.html')).not.toContain('/js/nightmode.js');
    expect(t('mobile/partials/navbar.html')).toContain('/js/nightmode.js');

    const guide = t('guide.html');
    const dataIdx = guide.indexOf('/js/guide-data.js');
    const jsIdx = guide.indexOf('/js/guide.js');
    expect(dataIdx).toBeGreaterThan(-1);
    expect(jsIdx).toBeGreaterThan(-1);
    expect(dataIdx).toBeLessThan(jsIdx);

    // The bases hand the data to the palette through its loader instead
    expect(t('base.html')).not.toContain('/js/guide-data.js');
    expect(t('base-landing.html')).not.toContain('/js/guide-data.js');
});
