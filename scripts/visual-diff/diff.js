// Visual parity diff: /search vs /offline rendering of one fixture query.
// Manual run; see README.md. Threshold: under 2 percent differing pixels.
const { chromium } = require('playwright');
const fs = require('fs');
const { PNG } = require('pngjs');
// pixelmatch v6 is ESM-only; unwrap the default export under CJS.
const pixelmatchMod = require('pixelmatch');
const pixelmatch = pixelmatchMod.default || pixelmatchMod;

const BASE = process.env.BASE_URL || 'http://localhost:8080';
const FIXTURE = process.env.FIXTURE || 'sol ring s:C21';
const COOKIE = process.env.MTGBAN_COOKIE || '';
const EDITIONS = process.env.EDITIONS || '';
const THRESHOLD_PCT = 2.0;

// shoot clips the first result-header plus its result-body.
async function shoot(page, url, outPath) {
    await page.goto(url, { waitUntil: 'networkidle' });
    await page.waitForSelector('.result-header', { timeout: 20000 });
    const hb = await page.locator('.result-header').first().boundingBox();
    const bb = await page.locator('.result-body').first().boundingBox();
    const clip = {
        x: Math.min(hb.x, bb.x),
        y: hb.y,
        width: Math.max(hb.width, bb.width),
        height: bb.y + bb.height - hb.y,
    };
    await page.screenshot({ path: outPath, clip });
}

function crop(png, width, height) {
    const out = new PNG({ width, height });
    PNG.bitblt(png, out, 0, 0, width, height, 0, 0);
    return out;
}

(async () => {
    const browser = await chromium.launch();
    const context = await browser.newContext({ viewport: { width: 1600, height: 1200 } });
    if (COOKIE) {
        await context.addCookies([{ name: 'MTGBAN', value: COOKIE, url: BASE }]);
    }
    const page = await context.newPage();

    await shoot(page, BASE + '/search?q=' + encodeURIComponent(FIXTURE), 'online.png');

    // Prime offline data in this fresh profile: opt in and wait for sync.
    await page.goto(BASE + '/offline');
    if (EDITIONS) {
        // Restrict the sync to a small set list; empty means all editions.
        await page.evaluate((sel) => localStorage.setItem('offline_editions', sel), EDITIONS);
    }
    await page.evaluate(() => window.OfflineMode.enable());
    await page.waitForFunction(() => {
        const s = window.OfflineMode.status();
        return s.lastSync && !s.syncing;
    }, null, { timeout: 300000 });

    await shoot(page, BASE + '/offline?q=' + encodeURIComponent(FIXTURE), 'offline.png');
    await browser.close();

    const a = PNG.sync.read(fs.readFileSync('online.png'));
    const b = PNG.sync.read(fs.readFileSync('offline.png'));
    const width = Math.min(a.width, b.width);
    const height = Math.min(a.height, b.height);
    const diff = new PNG({ width, height });
    const bad = pixelmatch(crop(a, width, height).data, crop(b, width, height).data,
        diff.data, width, height, { threshold: 0.1 });
    fs.writeFileSync('diff.png', PNG.sync.write(diff));

    const pct = (bad / (width * height)) * 100;
    console.log('size delta:', a.width + 'x' + a.height, 'vs', b.width + 'x' + b.height);
    console.log('diff: ' + bad + ' px, ' + pct.toFixed(3) + '% (threshold ' + THRESHOLD_PCT + '%)');
    process.exit(pct <= THRESHOLD_PCT ? 0 : 1);
})();
