#!/bin/bash
# Sweep pages at many sizes in a desktop Chrome over DevTools: the pane
# bundle, without the pane's 45 s limit or a hidden pane's throttled timers.
#   "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new \
#     --remote-debugging-port=9333 --user-data-dir=<scratch dir> about:blank &
#   (sign it in by sending the tab to the admin link: pane.md in this guide,
#   "Headless Chrome", has the steps)
#   chrome-sweep.sh https://mtgban.com 'desktop:1180x820 mobile:393x852' / /user ...
# Prints one JSON line per size, with only the entries worth reading. Inputs
# under 16px are dropped: desktop Chrome has no touch at any width, so the
# pointer: coarse rules that fix them never apply. Check those on a device.
here=$(cd "$(dirname "$0")" && pwd)
export CDP_PORT=${CDP_PORT:-9333}
cdp() { python3 -I "$here/android-cdp.py" "$@"; }
origin=$1; sizes=$2; shift 2
paths=$(python3 -I -c 'import json, sys; print(json.dumps(sys.argv[1:]))' "$@")
job=$(mktemp)
home=$(python3 -I -c 'import json, sys; print(json.dumps(sys.argv[1]))' "$origin/")
cdp "location.href = $home; 1" >/dev/null 2>&1
sleep 3
for size in $sizes; do
  view=${size%%:*}; wh=${size#*:}; w=${wh%x*}; h=${wh#*x}
  { "$here/pane-bundle.sh"
    echo "(async () => {"
    echo "  document.cookie = 'MobileView=$([ "$view" = mobile ] && echo true || echo false); path=/; max-age=31536000';"
    echo "  const r = __issues(await __sweep($w, $h, $paths));"
    echo "  document.getElementById('__f').remove();"
    echo "  return {size: '$size', issues: r};"
    echo "})()"
  } > "$job"
  cdp -f "$job" | python3 -I -c '
import json, sys
r = json.load(sys.stdin)
for x in r["issues"]:
    x.pop("small", None)
r["issues"] = [x for x in r["issues"] if len(x) > 2]
print(json.dumps(r))'
done
cdp "document.cookie = 'MobileView=false; path=/; max-age=31536000'; 1" >/dev/null
rm -f "$job"
