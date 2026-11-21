#!/bin/bash
# Boot the mtgban_pixel8 emulator (if it isn't running), wait for Android,
# make Chrome skip its first-run terms screen, and forward Chrome's DevTools
# socket to localhost:9222 for android-cdp.py. Safe to run again.
#   android-boot.sh [avd-name]
set -e
export ANDROID_SDK_ROOT=${ANDROID_SDK_ROOT:-/opt/homebrew/share/android-commandlinetools}
export JAVA_HOME=${JAVA_HOME:-/opt/homebrew/opt/openjdk@17}
avd=${1:-mtgban_pixel8}
adb=$ANDROID_SDK_ROOT/platform-tools/adb
if ! "$adb" devices | grep -q '^emulator-'; then
  nohup "$ANDROID_SDK_ROOT/emulator/emulator" -avd "$avd" -no-snapshot-save -no-boot-anim \
    -netdelay none -netspeed full >"${TMPDIR:-/tmp}/emulator-$avd.log" 2>&1 &
fi
"$adb" wait-for-device
for _ in $(seq 1 120); do
  [ "$("$adb" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] && break
  sleep 2
done
[ "$("$adb" shell getprop sys.boot_completed | tr -d '\r')" = 1 ] || { echo "Android did not boot" >&2; exit 1; }
# Chrome reads this file only while it is the debug app; this skips the
# first-run screen without accepting Chrome's terms on the user's behalf.
"$adb" shell 'echo "_ --disable-fre --no-default-browser-check --no-first-run --disable-signin-promo" > /data/local/tmp/chrome-command-line'
"$adb" shell am set-debug-app --persistent com.android.chrome >/dev/null
"$adb" forward tcp:9222 localabstract:chrome_devtools_remote >/dev/null
# The DevTools socket exists only while Chrome is in front: open it.
"$adb" shell am start -a android.intent.action.VIEW -d "${START_URL:-https://mtgban.com/}" com.android.chrome >/dev/null
for _ in $(seq 1 30); do curl -sf localhost:9222/json/version >/dev/null && break; sleep 1; done
curl -sf localhost:9222/json/version >/dev/null || { echo "Chrome's DevTools did not come up on localhost:9222" >&2; exit 1; }
# Keep only the newest tab: android-cdp.py drives the first page tab, and a
# background tab is frozen and won't navigate. Tab ids count up.
for id in $(curl -s localhost:9222/json | python3 -I -c '
import json, sys
ids = sorted((t["id"] for t in json.load(sys.stdin) if t["type"] == "page"), key=lambda i: int(i) if i.isdigit() else 0)
print(" ".join(ids[:-1]))'); do
  curl -s "localhost:9222/json/close/$id" >/dev/null
done
echo "booted: $("$adb" shell wm size | tr -d '\r' | awk '{print $NF}') @ $("$adb" shell wm density | tr -d '\r' | awk '{print $NF}') dpi;" \
  "Chrome $(curl -s localhost:9222/json/version | python3 -c 'import json,sys; print(json.load(sys.stdin)["Browser"])'), DevTools on localhost:9222;" \
  "$(curl -s localhost:9222/json | python3 -c 'import json,sys; print(sum(t["type"] == "page" for t in json.load(sys.stdin)))') tab(s) open"
