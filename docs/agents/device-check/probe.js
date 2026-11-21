// Layout probe: evaluate in a page (an expression, it returns an object).
// Pane: inside pane-sweep.js. Android: android-cdp.py -f probe.js.
//   sw/W      document scrollWidth vs viewport width (sw > W = page overflow)
//   off       visible elements past a viewport edge with no scrolling ancestor
//   clipped   leaf text cut by an overflow:hidden|clip ancestor
//   scrollers boxes with overflow-x auto|scroll that have content to scroll
//   small     visible text inputs under 16px (iOS zooms on focus)
//   view      'mobile' when the mobile navbar is present
(() => {
  // Not innerWidth: Android Chrome grows that to the content of a page
  // that overflows, and sw > W would never be true there.
  const W = document.documentElement.clientWidth;
  const name = e => e.id ? '#' + e.id
    : (typeof e.className === 'string' && e.className.trim()
      ? '.' + e.className.trim().split(/\s+/).slice(0, 2).join('.')
      : e.tagName.toLowerCase());
  // Hidden by itself or by any ancestor: a closed dropdown is opacity 0 on
  // the menu, and a closed <details> still gives its content a layout box.
  const vis = e => {
    if (e.closest('details:not([open]) > :not(summary)')) return false;
    for (let a = e; a && a !== document.documentElement; a = a.parentElement) {
      const cs = getComputedStyle(a);
      if (cs.display === 'none' || cs.visibility === 'hidden' || cs.opacity === '0') return false;
    }
    return true;
  };
  const off = [], clipped = [], scrollers = [];
  for (const el of document.querySelectorAll('body *')) {
    const r = el.getBoundingClientRect();
    if (r.width < 1 || r.height < 1) continue;
    const ox = getComputedStyle(el).overflowX;
    let p = el.parentElement, anc = null;
    while (p && p !== document.body) {
      if (getComputedStyle(p).overflowX !== 'visible') { anc = p; break; }
      p = p.parentElement;
    }
    const outside = r.right > W + 1 || r.left < -1;
    const scrolls = (ox === 'auto' || ox === 'scroll') && el.scrollWidth > el.clientWidth + 1;
    if (!outside && !anc && !scrolls) continue;
    if (!vis(el)) continue;
    if (!anc) {
      if (outside) off.push(name(el) + '@' + Math.round(r.left) + '..' + Math.round(r.right));
    } else {
      const o = getComputedStyle(anc).overflowX, a = anc.getBoundingClientRect();
      if ((o === 'hidden' || o === 'clip') && r.right > a.right + 1 && el.textContent.trim() && !el.children.length)
        clipped.push(name(el) + ' in ' + name(anc) + ' ' + Math.round(r.right - a.right) + 'px "' + el.textContent.trim().slice(0, 25) + '"');
    }
    if (scrolls) scrollers.push(name(el) + ' ' + el.clientWidth + '/' + el.scrollWidth);
  }
  const fields = 'input:not([type=hidden]):not([type=checkbox]):not([type=radio]):not([type=file])' +
    ':not([type=submit]):not([type=button]):not([type=range]):not([type=color]), textarea';
  const small = [...document.querySelectorAll(fields)]
    .filter(e => e.getClientRects().length && vis(e) && parseFloat(getComputedStyle(e).fontSize) < 16)
    .map(e => name(e) + ':' + getComputedStyle(e).fontSize);
  return {
    url: location.pathname + location.search, sw: document.documentElement.scrollWidth, W,
    view: document.querySelector('.m-nav') ? 'mobile' : 'desktop',
    off: off.slice(0, 8), offN: off.length, clipped: clipped.slice(0, 6), clippedN: clipped.length,
    scrollers: scrollers.slice(0, 5), small,
  };
})()
