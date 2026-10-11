// Runs Lighthouse for a set of pages and profiles, in the browser at
// CHROME_PATH or else the Chrome that chrome-launcher finds.
// usage: node audit.mjs <label> <base-url> [page ...]
// Writes out/<label>/<page>-<profile>.json and prints a summary table
// plus every failing audit in the four categories.
import lighthouse from 'lighthouse';
import * as chromeLauncher from 'chrome-launcher';
import puppeteer from 'puppeteer-core';
import fs from 'node:fs';
import path from 'node:path';

const [label, base, ...pageArgs] = process.argv.slice(2);
// THEME=light|dark pins the site theme through localStorage; CATS narrows the categories.
const THEME = process.env.THEME || '';
const CATS = process.env.CATS ? process.env.CATS.split(',') : null;
if (!label || !base) {
  console.error('usage: node audit.mjs <label> <base-url> [page ...]');
  process.exit(2);
}
const DEFAULT_PAGES = [
  ['home', '/'],
  ['search', '/search?q=s%3ALEB'],
  ['sealed', '/sealed'],
  ['news', '/newspaper'],
  ['screener', '/screener'],
  ['upload', '/upload'],
  ['sleepers', '/sleepers'],
  ['arbit', '/arbit'],
  ['guide', '/guide'],
];
const pages = pageArgs.length
  ? pageArgs.map(p => [p.replace(/[^a-z0-9]+/gi, '_'), p])
  : DEFAULT_PAGES;
const profiles = ['mobile', 'desktop'];
const cats = CATS || ['performance', 'accessibility', 'best-practices', 'seo'];

const outDir = path.join('out', label);
fs.mkdirSync(outDir, { recursive: true });

const chrome = await chromeLauncher.launch({
  chromePath: process.env.CHROME_PATH,
  chromeFlags: ['--headless=new', '--no-first-run', '--no-default-browser-check'],
});

const rows = [];
const failures = {};
let browser = null;
if (THEME) browser = await puppeteer.connect({ browserURL: `http://127.0.0.1:${chrome.port}` });
try {
  for (const [name, p] of pages) {
    for (const profile of profiles) {
      const url = base.replace(/\/$/, '') + p;
      const flags = {
        port: chrome.port,
        output: 'json',
        logLevel: 'error',
        onlyCategories: cats,
        formFactor: profile,
        screenEmulation: profile === 'desktop'
          ? { mobile: false, width: 1350, height: 940, deviceScaleFactor: 1, disabled: false }
          : { mobile: true, width: 412, height: 823, deviceScaleFactor: 1.75, disabled: false },
        throttlingMethod: 'simulate',
        throttling: profile === 'desktop'
          ? { rttMs: 40, throughputKbps: 10240, cpuSlowdownMultiplier: 1 }
          : { rttMs: 150, throughputKbps: 1638.4, cpuSlowdownMultiplier: 4 },
        emulatedUserAgent: profile === 'desktop'
          ? 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Chrome-Lighthouse'
          : 'Mozilla/5.0 (Linux; Android 11; moto g power (2022)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36 Chrome-Lighthouse',
      };
      let lhr;
      try {
        let page;
        if (browser) {
          page = await browser.newPage();
          await page.evaluateOnNewDocument(t => { try { localStorage.setItem('theme', t); } catch (e) {} }, THEME);
          flags.disableStorageReset = true;
        }
        ({ lhr } = await lighthouse(url, flags, undefined, page));
        if (page) await page.close();
      } catch (err) {
        console.error(`FAIL ${name} ${profile}: ${err.message}`);
        continue;
      }
      fs.writeFileSync(path.join(outDir, `${name}-${profile}.json`), JSON.stringify(lhr));
      const score = c => lhr.categories[c] ? Math.round(lhr.categories[c].score * 100) : '-';
      const a = lhr.audits;
      rows.push({
        page: name, profile,
        perf: score('performance'), a11y: score('accessibility'),
        bp: score('best-practices'), seo: score('seo'),
        fcp: a['first-contentful-paint']?.displayValue ?? '',
        lcp: a['largest-contentful-paint']?.displayValue ?? '',
        tbt: a['total-blocking-time']?.displayValue ?? '',
        cls: a['cumulative-layout-shift']?.displayValue ?? '',
      });
      for (const c of cats) {
        for (const ref of lhr.categories[c].auditRefs) {
          const au = a[ref.id];
          if (!au || au.scoreDisplayMode === 'notApplicable' || au.scoreDisplayMode === 'manual' || au.scoreDisplayMode === 'informative') continue;
          if (au.score !== null && au.score < 1) {
            const key = `${c}: ${ref.id}`;
            failures[key] ??= { title: au.title, where: [] };
            const n = au.details?.items?.length;
            failures[key].where.push(`${name}/${profile}${n ? ` (${n})` : ''}`);
          }
        }
      }
    }
  }
} finally {
  if (!browser) {
    try { browser = await puppeteer.connect({ browserURL: `http://127.0.0.1:${chrome.port}` }); } catch (e) {}
  }
  if (browser) {
    try { await browser.close(); } catch (e) {}
  }
  await chrome.kill();
}

const pad = (s, n) => String(s).padEnd(n);
console.log(`\n== ${label} @ ${base} ==`);
console.log(pad('page', 10) + pad('profile', 8) + pad('perf', 6) + pad('a11y', 6) + pad('bp', 6) + pad('seo', 6) + pad('FCP', 8) + pad('LCP', 8) + pad('TBT', 10) + 'CLS');
for (const r of rows) {
  console.log(pad(r.page, 10) + pad(r.profile, 8) + pad(r.perf, 6) + pad(r.a11y, 6) + pad(r.bp, 6) + pad(r.seo, 6) + pad(r.fcp, 8) + pad(r.lcp, 8) + pad(r.tbt, 10) + r.cls);
}
console.log('\n== failing audits (page/profile, item count) ==');
for (const key of Object.keys(failures).sort()) {
  const f = failures[key];
  console.log(`${key}  ${f.title}\n    ${f.where.join(', ')}`);
}
fs.writeFileSync(path.join(outDir, 'summary.json'), JSON.stringify({ rows, failures }, null, 2));
