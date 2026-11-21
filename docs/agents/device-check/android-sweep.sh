#!/bin/bash
# Load each path in Android Chrome's page tab and print what probe.js finds.
#   android-sweep.sh https://mtgban.com / '/search?q=Sol+Ring' ...
# Needs `adb forward tcp:9222 localabstract:chrome_devtools_remote` (done by
# android-boot.sh) and ONE tab open in Chrome: a background tab is frozen
# and won't navigate, and android-cdp.py drives the first page tab.
here=$(cd "$(dirname "$0")" && pwd)
cdp() { python3 -I "$here/android-cdp.py" "$@"; }
origin=$1; shift
out=$(mktemp)
for u in "$@"; do
  # JSON-encoded, so a path with an apostrophe (Urza's Saga) stays one string.
  url=$(python3 -I -c 'import json, sys; print(json.dumps(sys.argv[1]))' "$origin$u")
  cdp "location.href = $url; 1" >/dev/null 2>&1
  sleep "${SETTLE:-5}"
  cdp -f "$here/probe.js" >"$out" 2>&1
  U="$u" OUT="$out" python3 -I -c '
import json, os
from urllib.parse import unquote_plus
raw = open(os.environ["OUT"]).read()
try:
    r = json.loads(raw)
except Exception:
    r = None
if not isinstance(r, dict) or "url" not in r:
    print(os.environ["U"], "ERR", raw.strip()[:200]); raise SystemExit
o = {k: r[k] for k in ("url", "view", "sw", "W")}
# Landed somewhere else: a redirect, or a navigation that failed and left
# the previous page. Show both rather than pass it off as the path asked for.
if unquote_plus(r["url"]) != unquote_plus(os.environ["U"]):
    o["asked"] = os.environ["U"]
off = [x for x in r["off"] if not x.startswith(("#m-menu@", "#m-fav-toast@"))]
cl = [x for x in r["clipped"] if "landing-popular" not in x]
for key, val in (("off", off), ("clipped", cl), ("sc", r["scrollers"]), ("small", r["small"])):
    if val: o[key] = val[:3]
print(json.dumps(o))'
done
rm -f "$out"
