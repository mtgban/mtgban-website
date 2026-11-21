#!/bin/bash
# Lay screenshots side by side with captions and render one PNG with
# headless Chrome (no PIL or ImageMagick on this Mac; sips only crops from
# the centre). Send the PNG to the user, not the HTML.
#   sheet.sh out.png 'Caption one' a.png 'Caption two' b.png ...
# Env: TILE_W (CSS px per tile, default 300), TILE_H (crop height, default
# 650; 0 = whole image).
set -e
out=$1; shift
w=${TILE_W:-300}; h=${TILE_H:-650}
dir=$(mktemp -d)
html=$dir/sheet.html
n=0
{
  echo "<!doctype html><meta charset=utf-8><style>"
  echo "body{margin:0;padding:16px;background:#e9ebef;font:600 14px -apple-system,Helvetica,sans-serif;display:flex;gap:16px;align-items:flex-start}"
  echo "figure{margin:0;width:${w}px}figcaption{margin:0 0 8px;color:#1b2430}"
  [ "$h" != 0 ] && echo ".t{height:${h}px;overflow:hidden;border-radius:10px;box-shadow:0 1px 4px #0003}" \
                || echo ".t{border-radius:10px;overflow:hidden;box-shadow:0 1px 4px #0003}"
  echo "img{width:100%;display:block}</style>"
  while [ $# -ge 2 ]; do
    cp "$2" "$dir/$n.png"
    printf '<figure><figcaption>%s</figcaption><div class=t><img src="%s.png"></div></figure>\n' "$1" "$n"
    n=$((n + 1)); shift 2
  done
} > "$html"
width=$(( n * (w + 16) + 16 ))
height=$([ "$h" != 0 ] && echo $(( h + 70 )) || echo 2400)
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new --disable-gpu \
  --hide-scrollbars --force-device-scale-factor=2 --window-size="$width,$height" \
  --screenshot="$out" "file://$html" >/dev/null 2>&1
rm -r "$dir"
echo "$out"
