# Chrome on the Android emulator

## One-time setup (ask the maintainer first)

It downloads about 2.3 GB and needs Google's SDK licence accepted. Both need
the maintainer's yes. Check what's already there:
`ls /opt/homebrew/share/android-commandlinetools ~/.android/avd`.

```bash
brew install openjdk@17          # not the temurin cask: a .pkg that needs the admin password
brew install --cask android-commandlinetools
export JAVA_HOME=/opt/homebrew/opt/openjdk@17
export ANDROID_SDK_ROOT=/opt/homebrew/share/android-commandlinetools
yes | sdkmanager --licenses      # the licence acceptance: only with the maintainer's yes
sdkmanager --install platform-tools emulator "system-images;android-35;google_apis_playstore;arm64-v8a"
echo no | avdmanager create avd -n mtgban_pixel8 -k "system-images;android-35;google_apis_playstore;arm64-v8a" -d pixel_8
```

- `avdmanager` prints `Could not load devices from .../devices.xml`. The
  AVD is still created: check `~/.android/avd/mtgban_pixel8.avd/config.ini`
  for `hw.device.name=pixel_8`.
- **Size:** Pixel 8 is 1080x2400 at 420 dpi, which is 412x784 CSS px at
  dpr 2.625.
- **Chrome version:** the Play image ships Chrome 124 and doesn't update
  without a Google account. It is new enough for `:has`, `color-mix` and
  `overflow: clip`. Say which version you measured on.
- **Shells:** a shell without `/opt/homebrew/bin` on its PATH (the desktop
  app's `!` input) needs full paths: `/opt/homebrew/bin/sdkmanager`.

## Each session

```bash
docs/agents/device-check/android-boot.sh
```

The script:

- boots the AVD if it isn't running, in its own window (closing the window
  shuts it down);
- waits for Android to finish booting;
- makes Chrome skip its first-run terms screen without accepting the terms:
  it writes `--disable-fre` to `/data/local/tmp/chrome-command-line`, which
  Chrome reads while it is the debug app (`am set-debug-app --persistent`);
- opens Chrome on `START_URL` (default `https://mtgban.com/`) and closes
  every tab except that one;
- forwards Chrome's DevTools socket to `localhost:9222`.

The first launch still shows a notifications prompt: decline it ("No
thanks").

Sign in from a file so the link stays out of the transcript:

```bash
adb shell "am start -a android.intent.action.VIEW -d '$(cat $SCRATCH/adminlink)' com.android.chrome"
```

That opens a new tab. Run `android-boot.sh` again to get back to one.

## Measuring inside Chrome

```bash
S=docs/agents/device-check
python3 -I $S/android-cdp.py '({W: innerWidth, sw: document.documentElement.scrollWidth})'
python3 -I $S/android-cdp.py -f $S/probe.js
$S/android-sweep.sh https://mtgban.com / '/search?q=Sol+Ring' /user
```

- **How it works:** `android-cdp.py` is a stdlib websocket client (there's
  no websocket package on this Mac). It evaluates in the first page tab,
  awaits promises and prints the value as JSON. For an async check, wrap it
  in `(async () => { ... })()`.
- **The view:** Android Chrome gets the mobile view. For the desktop view,
  set the cookie through CDP (`document.cookie = 'MobileView=false; path=/;
  max-age=31536000'`) before sweeping, and set it back after.
- **Faking a tier:** set `data-tier` on `.m-nav` / `.navbar-v2` and call
  `BANTheme.set('light')`. Unlike Safari, you can then screenshot the
  result.
- **Undeployed fixes:** inject them the same way as in the pane
  ([`pane.md`](pane.md)).

## When the scripts fail

- **`RemoteDisconnected` or empty JSON from `/json`:** Chrome isn't in
  front, so its DevTools socket is gone. Run `android-boot.sh`.
- **The sweep shows the same URL for every path:** the script is driving a
  frozen background tab. Run `android-boot.sh` to get back to one tab.
- **Reading a page mid-navigation** prints an `ERR` line with "Execution
  context was destroyed". Raise `SETTLE` (seconds, default 5) for
  `android-sweep.sh`.
- **A row with `asked`** landed on a different URL from the path asked for:
  a redirect, or a navigation that failed and left the previous page.
  Check it before trusting its numbers.
- **Calling the scripts from zsh:** zsh doesn't word-split `$VAR`, so don't
  store `python3 -I …` in a variable. Call the scripts directly or through
  a function.

## Screens and taps

- **Screenshot:** `adb exec-out screencap -p > x.png`, then
  `sips -Z 900 x.png --out xs.png` to read it.
- **Taps** are in device pixels: `adb shell input tap X Y`. That's a pixel
  of the scaled screenshot times (1080 / its width).
- **CSS to device pixels:** device y = (CSS y × dpr) + the height of the
  status bar and toolbar. Reading the target off a screenshot is easier
  than computing it.
- **Keys:** `adb shell input keyevent KEYCODE_BACK` closes the keyboard.
- **Exact colours:** `png-pixel.py x.png 20,200 900,330`, a stdlib
  PNG decoder. Sample the toolbar around y 200 and the page's bar around
  y 330 at full resolution.

## What Android Chrome does differently

- **A page wider than the viewport widens the layout viewport.** On iPhone
  the page pans; here `innerWidth` grows (523 on a 412 phone) and the page
  is laid out at that width. Right-edge and fixed controls (the navbar's
  menu and view switch) end up off-screen until the reader pans. A page
  overflow is more serious on Android than on iOS.
- **The toolbar takes theme-color**, matched to the pixel. The system status
  bar above it doesn't (black on this image).
- **No zoom on focus.** The keyboard shrinks the visual viewport
  (`visualViewport.height`, 424 of 784 on Pixel 8) and leaves the layout
  viewport alone. Check the focused field stays visible.
- **Android UA plus `pointer: coarse`**, so the server serves the mobile
  view and touch rules apply.
