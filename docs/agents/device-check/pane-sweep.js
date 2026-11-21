// Pane sweep runner. Don't paste this file directly: `pane-bundle.sh` puts
// probe.js in place of the placeholder below and prints one paste for
// javascript_tool, run on any page of the site (the iframe must be
// same-origin).
//
//   __sweep(w, h, paths)   -> probe results for each path at w x h
//   __issues(results)      -> only the entries worth reading
//   __run(plan, paths)     -> starts a long sweep in the background; poll
//                             window.__done and read window.__res
// plan: [['desktop', 1180, 820], ['mobile', 393, 852], ...]; the view is set
// through the MobileView cookie before each size.
window.__probe = __PROBE__;
window.__sweep = async (w, h, paths, settle = 1500) => {
  let f = document.getElementById('__f');
  if (f) f.remove();
  f = document.createElement('iframe');
  f.id = '__f';
  f.style.cssText = `position:absolute;left:0;top:0;width:${w}px;height:${h}px;border:0;z-index:99999;background:#fff`;
  document.body.append(f);
  const out = [];
  for (const u of paths) {
    await new Promise(res => { f.onload = res; f.src = u; });
    await new Promise(r => setTimeout(r, settle));
    try { out.push(f.contentWindow.eval(window.__probe)); } catch (e) { out.push({url: u, err: String(e)}); }
  }
  return out;
};
// Drops the site's known off-canvas parts: the mobile menu and favourites toast.
window.__issues = rs => rs.map(x => {
  const o = {u: x.url};
  if (x.view) o.v = x.view;
  const off = (x.off || []).filter(s => !/^#m-menu@|^#m-fav-toast@/.test(s));
  const clipped = (x.clipped || []).filter(s => !s.includes('landing-popular'));
  if (x.sw > x.W) o.pageOverflow = x.sw - x.W;
  if (off.length) o.off = off.slice(0, 3);
  if (clipped.length) o.clipped = clipped.slice(0, 3);
  if (x.scrollers && x.scrollers.length) o.sc = x.scrollers.slice(0, 3);
  if (x.small && x.small.length) o.small = x.small.slice(0, 3);
  if (x.err) o.err = x.err;
  return o;
}).filter(o => o.err || Object.keys(o).length > 2);
window.__run = (plan, paths) => {
  window.__res = {};
  window.__done = false;
  (async () => {
    for (const [view, w, h] of plan) {
      document.cookie = 'MobileView=' + (view === 'mobile') + '; path=/; max-age=31536000';
      window.__res[view + ' ' + w + 'x' + h] = window.__issues(await window.__sweep(w, h, paths));
    }
    document.cookie = 'MobileView=; path=/; max-age=0';
    document.getElementById('__f')?.remove();
    window.__done = true;
  })();
  return 'started';
};
'ready';
